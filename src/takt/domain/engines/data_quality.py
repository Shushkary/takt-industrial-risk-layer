from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from takt.domain.entities.event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class DataQualitySnapshot:
    """DQ 0..1 и флаг частичной наблюдаемости."""

    dq_score: float
    partial_observability: bool
    reasons: tuple[str, ...]


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def evaluate_sequence_gaps(
    events: Sequence[NormalizedEvent],
    *,
    max_gap_seconds: float,
) -> DataQualitySnapshot:
    """
    Inv_DQ_02 (telemetry gap): большие разрывы между событиями одного источника.
    """
    if len(events) < 2:
        return DataQualitySnapshot(1.0, False, ())
    reasons: list[str] = []
    gap_penalty = 0.0
    prev = events[0]
    for cur in events[1:]:
        delta = (cur.observed_at - prev.observed_at).total_seconds()
        if delta > max_gap_seconds:
            gap_penalty += min(0.2, (delta - max_gap_seconds) / max_gap_seconds * 0.05)
            reasons.append("telemetry_gap")
        prev = cur
    score = max(0.0, 1.0 - gap_penalty)
    partial = score < 0.5
    return DataQualitySnapshot(score, partial, tuple(reasons))


def evaluate_stale_telemetry(
    events: Sequence[NormalizedEvent],
    *,
    stale_window_seconds: float = 90.0,
) -> DataQualitySnapshot:
    """
    Inv_DQ_01 (stale data упрощ.): одинаковые ключевые поля payload при долгом интервале.
    """
    if len(events) < 2:
        return DataQualitySnapshot(1.0, False, ())
    reasons: list[str] = []
    stale_penalty = 0.0
    prev = events[0]

    def _sig(e: NormalizedEvent) -> tuple:
        pl = e.payload
        return (
            pl.get("telemetry_value"),
            pl.get("value"),
            e.operation,
            e.payload_size,
        )

    for cur in events[1:]:
        delta = (cur.observed_at - prev.observed_at).total_seconds()
        if delta >= stale_window_seconds and _sig(cur) == _sig(prev):
            stale_penalty += 0.15
            reasons.append("stale_data")
        prev = cur
    score = _clamp(1.0 - stale_penalty)
    return DataQualitySnapshot(score, score < 0.5, tuple(reasons))


def evaluate_source_reputation(
    *,
    source_key: str,
    trust_by_source: Mapping[str, float],
) -> DataQualitySnapshot:
    """
    Inv_DQ_03: дрейф репутации источника; trust 0..1 снаружи (хранилище наблюдений).
    """
    trust = float(trust_by_source.get(source_key, 1.0))
    trust = _clamp(trust)
    if trust >= 0.85:
        return DataQualitySnapshot(trust, False, ())
    return DataQualitySnapshot(trust, trust < 0.5, ("source_reputation_drift",))


def compose_dq(
    *snapshots: DataQualitySnapshot,
) -> DataQualitySnapshot:
    """Агрегирование нескольких DQ-проверок (консервативное — минимум)."""
    if not snapshots:
        return DataQualitySnapshot(1.0, False, ())
    score = min(s.dq_score for s in snapshots)
    reasons = tuple(dict.fromkeys(r for s in snapshots for r in s.reasons))
    partial = any(s.partial_observability for s in snapshots) or score < 0.5
    return DataQualitySnapshot(score, partial, reasons)


def evaluate_full_pipeline(
    events: Sequence[NormalizedEvent],
    *,
    max_gap_seconds: float,
    stale_window_seconds: float,
    source_key: str,
    trust_by_source: Mapping[str, float],
) -> DataQualitySnapshot:
    """Inv_DQ_01 + Inv_DQ_02 + Inv_DQ_03 (агрегировано)."""
    return compose_dq(
        evaluate_sequence_gaps(events, max_gap_seconds=max_gap_seconds),
        evaluate_stale_telemetry(events, stale_window_seconds=stale_window_seconds),
        evaluate_source_reputation(source_key=source_key, trust_by_source=trust_by_source),
    )
