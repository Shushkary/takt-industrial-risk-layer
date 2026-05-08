from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.engines.data_quality import (
    compose_dq,
    evaluate_full_pipeline,
    evaluate_sequence_gaps,
    evaluate_source_reputation,
    evaluate_stale_telemetry,
)


def _ev(
    eid: str,
    t: datetime,
    *,
    operation: str = "POLL",
    payload_size: int = 4,
    payload: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=eid,
        observed_at=t,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation=operation,
        payload_size=payload_size,
        payload=payload or {"asset_id": "a1"},
    )


def test_sequence_gaps_insufficient_events():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    s = evaluate_sequence_gaps([_ev("1", t0)], max_gap_seconds=60.0)
    assert s.dq_score == 1.0
    assert s.partial_observability is False
    assert s.reasons == ()


def test_sequence_gaps_no_penalty_under_threshold():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    seq = [_ev("1", t0), _ev("2", t0 + timedelta(seconds=30))]
    s = evaluate_sequence_gaps(seq, max_gap_seconds=60.0)
    assert s.dq_score == 1.0
    assert s.reasons == ()


def test_sequence_gaps_detects_gap():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    seq = [_ev("1", t0), _ev("2", t0 + timedelta(seconds=200))]
    s = evaluate_sequence_gaps(seq, max_gap_seconds=60.0)
    assert "telemetry_gap" in s.reasons
    assert s.dq_score < 1.0


def test_sequence_gaps_accumulates_multiple_gap_reasons():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    seq = [
        _ev("1", t0),
        _ev("2", t0 + timedelta(seconds=200)),
        _ev("3", t0 + timedelta(seconds=450)),
    ]
    s = evaluate_sequence_gaps(seq, max_gap_seconds=60.0)
    assert s.reasons.count("telemetry_gap") == 2
    assert s.dq_score < 1.0


def test_stale_telemetry_requires_same_signature():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    a = _ev("1", t0, payload={"telemetry_value": 7, "asset_id": "a1"})
    b = _ev(
        "2",
        t0 + timedelta(seconds=120),
        payload={"telemetry_value": 8, "asset_id": "a1"},
    )
    s = evaluate_stale_telemetry([a, b], stale_window_seconds=90.0)
    assert s.reasons == ()


def test_stale_telemetry_same_sig_over_window():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    p = {"telemetry_value": 7, "asset_id": "a1"}
    a = _ev("1", t0, payload=p)
    b = _ev("2", t0 + timedelta(seconds=120), payload=p)
    s = evaluate_stale_telemetry([a, b], stale_window_seconds=90.0)
    assert "stale_data" in s.reasons
    assert s.dq_score < 1.0


def test_stale_telemetry_accumulates_multiple_stale_edges():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    p = {"telemetry_value": 7, "asset_id": "a1"}
    a = _ev("1", t0, payload=p)
    b = _ev("2", t0 + timedelta(seconds=100), payload=p)
    c = _ev("3", t0 + timedelta(seconds=220), payload=p)
    s = evaluate_stale_telemetry([a, b, c], stale_window_seconds=90.0)
    assert s.reasons.count("stale_data") == 2
    assert s.dq_score == pytest.approx(0.7)


def test_stale_telemetry_uses_value_field_in_signature():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    p = {"value": 42, "asset_id": "z"}
    a = _ev("1", t0, operation="POLL", payload_size=2, payload=p)
    b = _ev(
        "2",
        t0 + timedelta(seconds=120),
        operation="POLL",
        payload_size=2,
        payload=p,
    )
    s = evaluate_stale_telemetry([a, b], stale_window_seconds=90.0)
    assert "stale_data" in s.reasons


def test_source_reputation_missing_key_full_trust():
    s = evaluate_source_reputation(source_key="plc_polling", trust_by_source={})
    assert s.dq_score == 1.0
    assert s.reasons == ()


def test_source_reputation_no_drift_at_threshold():
    s = evaluate_source_reputation(
        source_key="s",
        trust_by_source={"s": 0.9},
    )
    assert s.dq_score == pytest.approx(0.9)
    assert s.reasons == ()


def test_source_reputation_drift_below_threshold():
    s = evaluate_source_reputation(
        source_key="s",
        trust_by_source={"s": 0.7},
    )
    assert s.dq_score == pytest.approx(0.7)
    assert "source_reputation_drift" in s.reasons


def test_source_reputation_boundary_085_no_drift_flag_reason():
    s = evaluate_source_reputation(
        source_key="s",
        trust_by_source={"s": 0.85},
    )
    assert s.dq_score == pytest.approx(0.85)
    assert s.partial_observability is False
    assert s.reasons == ()


def test_source_reputation_clamps_trust_above_one():
    s = evaluate_source_reputation(
        source_key="s",
        trust_by_source={"s": 2.0},
    )
    assert s.dq_score == pytest.approx(1.0)
    assert s.reasons == ()


def test_source_reputation_clamps_negative_trust():
    s = evaluate_source_reputation(
        source_key="s",
        trust_by_source={"s": -0.5},
    )
    assert s.dq_score == pytest.approx(0.0)
    assert s.partial_observability is True
    assert "source_reputation_drift" in s.reasons


def test_compose_dq_partial_when_any_snapshot_partial():
    weak = evaluate_source_reputation(source_key="a", trust_by_source={"a": 0.4})
    strong = evaluate_source_reputation(source_key="b", trust_by_source={"b": 1.0})
    out = compose_dq(weak, strong)
    assert out.dq_score == pytest.approx(0.4)
    assert out.partial_observability is True


def test_compose_dq_empty():
    s = compose_dq()
    assert s.dq_score == 1.0
    assert s.reasons == ()


def test_compose_dq_min_score_and_dedupes_reasons():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    a = evaluate_sequence_gaps(
        [_ev("1", t0), _ev("2", t0 + timedelta(seconds=200))],
        max_gap_seconds=60.0,
    )
    b = evaluate_source_reputation(source_key="x", trust_by_source={"x": 0.4})
    out = compose_dq(a, b)
    assert out.dq_score == min(a.dq_score, b.dq_score)
    assert "telemetry_gap" in out.reasons
    assert "source_reputation_drift" in out.reasons


def test_full_pipeline_aggregates_sub_snapshots():
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    p = {"telemetry_value": 1, "asset_id": "x"}
    events = [
        _ev("1", t0, payload=p),
        _ev("2", t0 + timedelta(seconds=500), payload=p),
        _ev("3", t0 + timedelta(seconds=620), payload=p),
    ]
    s = evaluate_full_pipeline(
        events,
        max_gap_seconds=60.0,
        stale_window_seconds=90.0,
        source_key="plc_polling",
        trust_by_source={},
    )
    assert "telemetry_gap" in s.reasons
    assert "stale_data" in s.reasons
