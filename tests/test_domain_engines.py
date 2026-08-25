from __future__ import annotations

from datetime import UTC, datetime

from takt.domain.engines.alert_fatigue import burst_fingerprint, burst_fingerprint_bucketed, compute_burst_fingerprint
from takt.domain.engines.causal_mesh import GraphEdge, detect_jump_server_bypass
from takt.domain.engines.chaos_predictor import FEIGENBAUM_DELTA, predict_polling_chaos
from takt.domain.entities.event import EventSource, NormalizedEvent


def _norm_ev(*, source: EventSource, op: str, payload: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e1",
        observed_at=datetime.now(UTC),
        source=source,
        protocol="M",
        operation=op,
        payload_size=1,
        payload=payload,
    )


def test_feigenbaum_constant():
    assert abs(FEIGENBAUM_DELTA - 4.669201609) < 1e-6


def test_chaos_predictor_detects_ratio_trend():
    # разности растут ~ в районе Feigenbaum между шагами (синтетика)
    intervals = [1000.0, 1000.0, 4670.0, 21800.0]
    pred = predict_polling_chaos(intervals)
    assert pred is not None
    assert pred.jitter_trend_increasing


def test_chaos_predictor_too_few_samples():
    assert predict_polling_chaos([1.0, 2.0, 3.0]) is None


def test_chaos_predictor_non_positive_filtered_out():
    assert predict_polling_chaos([1000.0, 1100.0, 0.0, 2426.0]) is None


def test_chaos_predictor_returns_none_when_last_gap_zero():
    assert predict_polling_chaos([1000.0, 1000.0, 1000.0, 1000.0]) is None


def test_chaos_predictor_jitter_increasing_without_feigenbaum():
    pred = predict_polling_chaos([1000.0, 1000.0, 2000.0, 4000.0])
    assert pred is not None
    assert pred.jitter_trend_increasing is True
    assert pred.suggests_period_doubling_cluster is False


def test_jump_server_bypass():
    edges = [GraphEdge("laptop", "plc-01", "tcp")]
    assert detect_jump_server_bypass(edges, "jump-01", frozenset({"plc-01"})) is True
    ok_edges = [GraphEdge("jump-01", "plc-01", "ssh")]
    assert detect_jump_server_bypass(ok_edges, "jump-01", frozenset({"plc-01"})) is False


def test_jump_server_bypass_empty_edges():
    assert detect_jump_server_bypass([], "jump-01", frozenset({"plc-01"})) is False


def test_jump_server_bypass_non_plc_destination():
    assert (
        detect_jump_server_bypass(
            [GraphEdge("laptop", "router-1", "tcp")],
            "jump-01",
            frozenset({"plc-01"}),
        )
        is False
    )


def test_burst_fingerprint_uses_asset_id():
    ev = _norm_ev(
        source=EventSource.PLC_POLLING,
        op="READ",
        payload={"asset_id": "plc-a"},
    )
    assert burst_fingerprint(ev) == "plc_polling|plc-a|READ"


def test_burst_fingerprint_falls_back_to_plc_id():
    ev = _norm_ev(
        source=EventSource.PLC_POLLING,
        op="WRITE",
        payload={"plc_id": "plc-b"},
    )
    assert burst_fingerprint(ev) == "plc_polling|plc-b|WRITE"


def test_burst_fingerprint_missing_asset_placeholder():
    ev = _norm_ev(
        source=EventSource.NETWORK,
        op="PING",
        payload={},
    )
    assert burst_fingerprint(ev) == "network_events|_|PING"


def test_burst_fingerprint_bucketed_same_operation_asset_differs_from_legacy():
    ev = _norm_ev(
        source=EventSource.PLC_POLLING,
        op="READ",
        payload={"asset_id": "plc-a"},
    )
    legacy = burst_fingerprint(ev)
    bucketed = burst_fingerprint_bucketed(ev, bucket_sec=300)
    assert legacy.startswith("plc_polling|")
    assert bucketed.startswith("plc-a|READ|")
    assert compute_burst_fingerprint(ev, mode="legacy", bucket_sec=300) == legacy
    assert compute_burst_fingerprint(ev, mode="bucketed", bucket_sec=300) == bucketed


def test_worst_risk_class():
    from takt.domain.engines.risk_engine import worst_risk_class

    assert worst_risk_class("LOW", "HIGH") == "HIGH"
    assert worst_risk_class("CRITICAL", "MEDIUM") == "CRITICAL"
    assert worst_risk_class("low", "high") == "high"
    assert worst_risk_class("UNKNOWN", "HIGH") == "HIGH"
    assert worst_risk_class("HIGH", "unknown_case") == "HIGH"
    assert worst_risk_class("MEDIUM", "MEDIUM") == "MEDIUM"
