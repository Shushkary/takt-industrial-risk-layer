"""Слияние дублирующих открытых кейсов (миграция v0.7.x, один актив + операция + временной бакет)."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from datetime import datetime, timezone

from takt.domain.engines.alert_fatigue import case_bucket_burst_fingerprint
from takt.domain.engines.risk_engine import worst_risk_class
from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def migration_group_key(case: Case, bucket_sec: int) -> tuple[str, str, int]:
    aid = (case.primary_asset_id or "").strip().lower() or "_"
    op = (case.trigger_operation or "").strip().upper() or "_"
    bucket = int(_utc(case.created_at).timestamp() // bucket_sec)
    return aid, op, bucket


def merge_open_cases_group_v070(group: Sequence[Case], *, bucket_sec: int) -> tuple[Case, list[str]]:
    """
    Объединяет **открытые** кейсы одной группы (уже отфильтрованы по ключу миграции).
    Возвращает выживший кейс и список **case_id** для удаления из БД.
    """
    if len(group) < 2:
        raise ValueError("merge_open_cases_group_v070 expects at least 2 cases")
    ordered = sorted(group, key=lambda c: (_utc(c.created_at), c.case_id))
    survivor = deepcopy(ordered[0])
    dead_ids = [c.case_id for c in ordered[1:]]
    others = ordered[1:]

    all_cases = ordered
    survivor.risk_score = max(c.risk_score for c in all_cases)
    rcls = survivor.risk_class
    for c in others:
        rcls = worst_risk_class(rcls, c.risk_class)
    survivor.risk_class = rcls

    seen_ids: list[str] = []
    for c in all_cases:
        for eid in c.normalized_event_ids:
            if eid not in seen_ids:
                seen_ids.append(eid)
    survivor.normalized_event_ids = seen_ids

    survivor.invariant_hits = sorted(frozenset().union(*(frozenset(c.invariant_hits) for c in all_cases)))

    hit_keys: set[tuple[str, str]] = set()
    merged_records: list[InvariantHitRecord] = []
    for c in all_cases:
        for r in c.invariant_hit_records:
            k = (r.invariant_id, r.event_ref)
            if k in hit_keys:
                continue
            hit_keys.add(k)
            merged_records.append(r)
    survivor.invariant_hit_records = merged_records
    survivor.manual_permits = [p for c in all_cases for p in c.manual_permits]

    by_src: dict[str, Observation] = {}
    for c in all_cases:
        for o in c.observations:
            if o.source not in by_src:
                by_src[o.source] = Observation(source=o.source, ingest_trust=o.ingest_trust, event_ids=[])
            cur = by_src[o.source]
            cur.ingest_trust = max(cur.ingest_trust, o.ingest_trust)
            for eid in o.event_ids:
                if eid not in cur.event_ids:
                    cur.event_ids.append(eid)
    survivor.observations = list(by_src.values())

    best_dq = ordered[0]
    for c in others:
        if c.risk_score > best_dq.risk_score or (
            c.risk_score == best_dq.risk_score and _utc(c.created_at) > _utc(best_dq.created_at)
        ):
            best_dq = c
    survivor.dq_score = best_dq.dq_score
    survivor.dq_partial = best_dq.dq_partial
    survivor.dq_reasons = list(best_dq.dq_reasons)

    latest = max(all_cases, key=lambda c: (_utc(c.created_at), c.case_id))
    survivor.last_event_source = latest.last_event_source
    survivor.xai_summary = max(all_cases, key=lambda c: c.risk_score).xai_summary

    n = len(seen_ids)
    base_title = survivor.title
    if "] " in base_title:
        base_title = base_title.split("] ", 1)[-1]
    survivor.title = f"[x{n}] {base_title}"

    ts_note = _utc(survivor.created_at)
    survivor.append_audit(f"migration v0.7.0 merged cases: {', '.join(dead_ids)}", ts_note)
    for c in others:
        survivor.audit_log.extend(c.audit_log)

    bs = bucket_sec if bucket_sec >= 1 else 300
    survivor.burst_fingerprint = case_bucket_burst_fingerprint(
        primary_asset_id=survivor.primary_asset_id,
        trigger_operation=survivor.trigger_operation,
        created_at=survivor.created_at,
        bucket_sec=bs,
    )
    return survivor, dead_ids
