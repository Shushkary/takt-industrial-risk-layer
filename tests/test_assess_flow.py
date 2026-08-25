from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from takt.application.use_cases.assess_risk import (
    AssessRiskUseCase,
    demo_ticket_for_asset,
)
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.engines.chaos_predictor import ChaosPrediction
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import InvariantContext
from takt.infrastructure.stores.memory import InMemoryExpectedBehavior


def test_assess_end_to_end():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 22, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_LOGIN",
        payload_size=80,
        payload={"asset_id": "plc-99", "username": "root"},
    )
    prev = NormalizedEvent(
        event_id="e0",
        observed_at=t0 - timedelta(seconds=300),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="PING",
        payload_size=10,
        payload={},
    )
    tickets: list[ServiceTicket] = []
    edges = [GraphEdge("ws-1", "plc-99", "ssh")]
    intervals = [1000.0, 1000.0, 4670.0, 21800.0]
    res = uc.execute(
        ev,
        recent_events=[prev],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert res.data_quality.dq_score >= 0.0
    assert res.risk_score >= 0.0
    assert res.suggested_case.case_id
    assert "jump_server_bypass" in res.invariant_hits


def test_assess_polling_jitter_with_jump_bypass_without_feigenbaum_chaos():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "plc-99"},
    )
    edges = [GraphEdge("jump-01", "plc-99", "ssh")]
    intervals = [1000.0, 1020.0, 1060.0, 1120.0]
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert "polling_jitter" in res.invariant_hits
    assert InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value not in res.invariant_hits


def test_assess_out_of_shift_admin():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 23, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_SESSION_OPEN",
        payload_size=10,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
    )
    assert InvariantId.OUT_OF_SHIFT_ACCESS.value in res.invariant_hits


def test_assess_context_dissonance_without_ticket():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 14, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_LOGIN",
        payload_size=10,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
    )
    assert InvariantId.CONTEXT_DISSONANCE.value in res.invariant_hits


def test_assess_no_context_dissonance_when_ticket_covers():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 14, 0, tzinfo=UTC)
    win_start = t0 - timedelta(hours=1)
    win_end = t0 + timedelta(hours=2)
    tickets = [demo_ticket_for_asset("plc-99", start=win_start, end=win_end)]
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_LOGIN",
        payload_size=10,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=tickets,
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
    )
    assert InvariantId.CONTEXT_DISSONANCE.value not in res.invariant_hits


def test_assess_telemetry_gap_reason_maps_to_invariant():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 15, 0, tzinfo=UTC)
    prev = NormalizedEvent(
        event_id="e0",
        observed_at=t0 - timedelta(seconds=500),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=4,
        payload={"asset_id": "plc-99"},
    )
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=4,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=[prev],
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
    )
    assert InvariantId.TELEMETRY_GAP.value in res.invariant_hits


def test_assess_stale_data_reason_maps_to_invariant():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 15, 0, tzinfo=UTC)
    prev = NormalizedEvent(
        event_id="e0",
        observed_at=t0 - timedelta(seconds=120),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=4,
        payload={"asset_id": "plc-99", "telemetry_value": 42},
    )
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=4,
        payload={"asset_id": "plc-99", "telemetry_value": 42},
    )
    res = uc.execute(
        ev,
        recent_events=[prev],
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
    )
    assert InvariantId.STALE_DATA.value in res.invariant_hits


def test_assess_source_reputation_drift():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 15, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=4,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1060.0, 1120.0],
        clock=t0,
        trust_by_source={EventSource.PLC_POLLING.value: 0.5},
    )
    assert InvariantId.SOURCE_REPUTATION_DRIFT.value in res.invariant_hits


def test_assess_polling_period_doubling_suspect():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "plc-99"},
    )
    intervals = [1000.0, 1100.0, 1334.0, 2426.0]
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value in res.invariant_hits


def test_assess_suppresses_period_doubling_when_marked_experimental_in_catalog(monkeypatch: pytest.MonkeyPatch):
    """Спринт 3: experimental-инварианты по умолчанию не попадают в hits и не тянут rhythm 0.75."""
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    pred = ChaosPrediction(bifurcation_ratio=4.67, suggests_period_doubling_cluster=True, jitter_trend_increasing=False)
    monkeypatch.setattr(
        "takt.application.use_cases.assess_risk.predict_polling_chaos",
        lambda *_: pred,
    )
    monkeypatch.setattr(
        "takt.domain.invariants.rule_predicates.predict_polling_chaos",
        lambda *_: pred,
    )
    uc = AssessRiskUseCase(
        weights,
        plc_hosts=frozenset({"plc-99"}),
        experimental_invariant_ids=frozenset({InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value}),
    )
    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1.0, 2.0, 3.0, 4.0],
        clock=t0,
    )
    assert InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value not in res.invariant_hits


def test_assess_includes_period_doubling_when_include_experimental_in_profile(monkeypatch: pytest.MonkeyPatch):
    pred = ChaosPrediction(bifurcation_ratio=4.67, suggests_period_doubling_cluster=True, jitter_trend_increasing=False)
    monkeypatch.setattr(
        "takt.application.use_cases.assess_risk.predict_polling_chaos",
        lambda *_: pred,
    )
    monkeypatch.setattr(
        "takt.domain.invariants.rule_predicates.predict_polling_chaos",
        lambda *_: pred,
    )
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(
        weights,
        plc_hosts=frozenset({"plc-99"}),
        experimental_invariant_ids=frozenset({InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value}),
        invariant_profile=InvariantContext(include_experimental_invariants=True),
    )
    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "plc-99"},
    )
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=[1.0, 2.0, 3.0, 4.0],
        clock=t0,
    )
    assert InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value in res.invariant_hits


def test_assess_polling_jitter_without_period_doubling_cluster():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    uc = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "plc-99"},
    )
    intervals = [1000.0, 1000.0, 2000.0, 4000.0]
    res = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-99", "ssh")],
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert InvariantId.POLLING_JITTER.value in res.invariant_hits
    assert InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value not in res.invariant_hits


def test_demo_ticket_for_asset_builds_window_for_asset():
    start = datetime(2026, 6, 10, 8, 0, tzinfo=UTC)
    end = datetime(2026, 6, 10, 18, 0, tzinfo=UTC)
    t = demo_ticket_for_asset("PLC-DEMO", start=start, end=end)
    assert t.ticket_id == "SD-1"
    assert t.maintenance_window.asset_ids == frozenset({"PLC-DEMO"})
    assert t.maintenance_window.starts_at == start
    assert t.maintenance_window.ends_at == end


def test_assess_expected_behavior_dampens_risk():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    t0 = datetime(2026, 4, 30, 23, 0, tzinfo=UTC)
    edges = [GraphEdge("jump-01", "plc-99", "ssh")]
    intervals = [1000.0, 1020.0, 1060.0, 1120.0]
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_LOGIN",
        payload_size=10,
        payload={"asset_id": "plc-99"},
    )
    uc_plain = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    res_high = uc_plain.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    eb = InMemoryExpectedBehavior()
    eb.mark_expected("plc-99", "ADMIN_LOGIN")
    uc_damped = AssessRiskUseCase(
        weights, plc_hosts=frozenset({"plc-99"}), expected_behavior=eb
    )
    res_low = uc_damped.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert res_low.risk_score < res_high.risk_score
    assert InvariantId.OUT_OF_SHIFT_ACCESS.value in res_low.invariant_hits


def test_assess_expected_behavior_skips_dampening_without_asset():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    t0 = datetime(2026, 4, 30, 23, 0, tzinfo=UTC)
    edges = [GraphEdge("jump-01", "plc-99", "ssh")]
    intervals = [1000.0, 1020.0, 1060.0, 1120.0]
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="ADMIN_LOGIN",
        payload_size=10,
        payload={},
    )
    uc_plain = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-99"}))
    res_plain = uc_plain.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    eb = InMemoryExpectedBehavior()
    eb.mark_expected("plc-99", "ADMIN_LOGIN")
    uc_damped = AssessRiskUseCase(
        weights, plc_hosts=frozenset({"plc-99"}), expected_behavior=eb
    )
    res_damped = uc_damped.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert res_plain.risk_score == pytest.approx(res_damped.risk_score)
    assert res_plain.invariant_hits == res_damped.invariant_hits
    assert InvariantId.OUT_OF_SHIFT_ACCESS.value in res_plain.invariant_hits


def test_assess_invariant_ctx_execute_overrides_constructor_profile():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    ctor_ctx = InvariantContext(allowed_function_codes=frozenset({"0", "1"}))
    uc = AssessRiskUseCase(
        weights, plc_hosts=frozenset({"plc-99"}), invariant_profile=ctor_ctx
    )
    t0 = datetime(2026, 4, 30, 14, 0, tzinfo=UTC)
    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "plc-99", "function_code": "3"},
    )
    edges = [GraphEdge("jump-01", "plc-99", "ssh")]
    intervals = [1000.0, 1020.0, 1060.0, 1120.0]
    res_ctor = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value in res_ctor.invariant_hits

    override = InvariantContext(allowed_function_codes=frozenset({"3", "4"}))
    res_ok = uc.execute(
        ev,
        recent_events=(),
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
        invariant_ctx=override,
    )
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value not in res_ok.invariant_hits
