from __future__ import annotations

from datetime import datetime, timezone

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.invariants.catalog import InvariantId
from takt.infrastructure.stores.memory import InMemoryCaseStore


def test_alert_fatigue_merges_open_case():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)

    def ev(eid: str, op: str = "POLL"):
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation=op,
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]

    o1 = proc.execute(
        ev("a"),
        recent_events=[],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert not o1.merged_into_existing

    o2 = proc.execute(
        ev("b"),
        recent_events=[ev("a")],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert o2.merged_into_existing
    assert len(repo.list_all()) == 1
    assert len(o2.case.normalized_event_ids) == 2
    assert o2.case.xai_summary == o2.assessment.suggested_case.xai_summary
    assert o2.case.trigger_operation == o2.assessment.suggested_case.trigger_operation
    assert o2.case.last_event_source == "plc_polling"
    assert o2.case.dq_score == o2.assessment.data_quality.dq_score
    assert o2.case.dq_partial == o2.assessment.data_quality.partial_observability
    assert o2.case.dq_reasons == list(o2.assessment.data_quality.reasons)


def test_alert_fatigue_merge_title_shows_third_event_count():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)

    def ev(eid: str, op: str = "POLL"):
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation=op,
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]

    proc.execute(
        ev("e1"), recent_events=[], tickets=tickets, graph_edges=edges, polling_intervals_us=intervals, clock=t0
    )
    proc.execute(
        ev("e2"), recent_events=[ev("e1")], tickets=tickets, graph_edges=edges, polling_intervals_us=intervals, clock=t0
    )
    out3 = proc.execute(
        ev("e3"),
        recent_events=[ev("e1"), ev("e2")],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert out3.merged_into_existing
    assert "[x3]" in out3.case.title
    assert len(repo.list_all()) == 1


def test_alert_fatigue_merges_invariant_hits_union():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 11, 0, tzinfo=timezone.utc)

    def ev(eid: str, **payload):
        base = {"asset_id": "plc-x"}
        base.update(payload)
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="POLL",
            payload_size=10,
            payload=base,
        )

    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]
    e1 = ev("a", trust_index_drop=True)
    e2 = ev("b", new_node_airgap=True)
    proc.execute(e1, recent_events=[], tickets=tickets, graph_edges=edges, polling_intervals_us=intervals, clock=t0)
    out = proc.execute(e2, recent_events=[e1], tickets=tickets, graph_edges=edges, polling_intervals_us=intervals, clock=t0)
    assert out.merged_into_existing
    h = frozenset(out.case.invariant_hits)
    assert "trust_index_drop" in h
    assert "new_node_airgap" in h
    assert len(out.case.invariant_hit_records) >= 2


def test_alert_fatigue_merge_takes_max_risk_score():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)

    def ev(eid: str):
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="POLL",
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    flat_intervals = [1000.0, 1000.0, 1000.0, 1000.0]
    chaos_intervals = [1000.0, 1000.0, 4670.0, 21_800.0]

    o1 = proc.execute(
        ev("a"),
        recent_events=[],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=flat_intervals,
        clock=t0,
    )
    s1 = o1.case.risk_score
    o2 = proc.execute(
        ev("b"),
        recent_events=[ev("a")],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=chaos_intervals,
        clock=t0,
    )
    assert o2.merged_into_existing
    assert o2.case.risk_score >= max(s1, o2.assessment.risk_score)


def test_alert_fatigue_merges_different_sources_same_bucket():
    """Режим bucketed: один актив + операция в одном UTC-бакете — один кейс, несколько наблюдений."""
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
        "alert_fatigue": {"mode": "bucketed", "bucket_sec": 300},
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc)
    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]

    def ev_plc(eid: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="READ",
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    def ev_auth(eid: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.AUTH_LOGS,
            protocol="TCP",
            operation="READ",
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    o1 = proc.execute(
        ev_plc("p1"),
        recent_events=[],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert not o1.merged_into_existing
    o2 = proc.execute(
        ev_auth("a1"),
        recent_events=[ev_plc("p1")],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert o2.merged_into_existing
    assert len(repo.list_all()) == 1
    assert o2.case.last_event_source == "auth_logs"
    srcs = {o.source for o in o2.case.observations}
    assert srcs == {"plc_polling", "auth_logs"}


def test_alert_fatigue_bucketed_does_not_merge_different_time_buckets():
    """Спринт 2: события с тем же source|asset|op в соседних 300s-бакетах (интервал 11 мин) — два кейса."""
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
        "alert_fatigue": {"mode": "bucketed", "bucket_sec": 300},
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 1, 14, 0, tzinfo=timezone.utc)
    t_late = datetime(2026, 5, 1, 14, 11, tzinfo=timezone.utc)
    edges: list[GraphEdge] = []
    tickets: list[ServiceTicket] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]

    def ev_at(eid: str, ts: datetime) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=ts,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="READ",
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    proc.execute(ev_at("e1", t0), recent_events=[], tickets=tickets, graph_edges=edges, polling_intervals_us=intervals, clock=t0)
    out = proc.execute(
        ev_at("e2", t_late),
        recent_events=[ev_at("e1", t0)],
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t_late,
    )
    assert not out.merged_into_existing
    assert len(repo.list_all()) == 2


def test_process_event_applies_enrichment_before_assess():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    enrichment = {"enabled": True, "air_gap_segments": ["AIR_GAP_L2"]}
    proc = ProcessEventUseCase(assess, repo, enrichment=enrichment)
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    ev = NormalizedEvent(
        event_id="e-enr",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="TCP",
        operation="HELLO",
        payload_size=1,
        payload={"asset_id": "plc-x", "segment": "air_gap_l2", "is_new_peer": "true"},
    )
    out = proc.execute(
        ev,
        recent_events=[],
        tickets=[],
        graph_edges=[GraphEdge("jump-01", "plc-x", "ssh")],
        polling_intervals_us=[1000.0, 1020.0, 1050.0, 1100.0],
        clock=t0,
    )
    assert InvariantId.NEW_NODE_AIRGAP.value in out.assessment.invariant_hits


def test_process_merge_backfills_empty_primary_asset_id():
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(weights, plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    t0 = datetime(2026, 5, 12, 11, 0, tzinfo=timezone.utc)
    edges: list[GraphEdge] = []
    intervals = [1000.0, 1000.0, 1000.0, 1000.0]

    def ev(eid: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="POLL",
            payload_size=10,
            payload={"asset_id": "plc-x"},
        )

    o1 = proc.execute(
        ev("e1"),
        recent_events=[],
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert not o1.merged_into_existing
    assert o1.case.primary_asset_id == "plc-x"
    stored = repo.get(o1.case.case_id)
    assert stored is not None
    stored.primary_asset_id = ""
    repo.save(stored)

    o2 = proc.execute(
        ev("e2"),
        recent_events=[ev("e1")],
        tickets=[],
        graph_edges=edges,
        polling_intervals_us=intervals,
        clock=t0,
    )
    assert o2.merged_into_existing
    assert o2.case.primary_asset_id == "plc-x"
