from __future__ import annotations

from datetime import UTC, datetime

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.infrastructure.stores.memory import InMemoryCaseStore


def _weights() -> dict[str, float | int]:
    return {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }


def test_run_backtest_same_bucket_event_order_yields_identical_final_case_state():
    """Спринт 2: перестановка порядка событий в одном бакете → тот же итоговый кейс."""
    from itertools import permutations

    t0 = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
    t1 = datetime(2026, 4, 30, 12, 0, 5, tzinfo=UTC)

    def mk_e(eid: str, ts) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=ts,
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="POLL",
            payload_size=64,
            payload={"asset_id": "plc-01"},
        )

    base = [mk_e("e0", t0), mk_e("e1", t1)]
    snapshots: list[tuple[float, tuple[str, ...], tuple[str, ...]]] = []
    for perm in permutations(base):
        repo = InMemoryCaseStore()
        assess = AssessRiskUseCase(_weights(), plc_hosts=frozenset({"plc-01"}))
        proc = ProcessEventUseCase(assess, repo)
        bt = RunBacktestUseCase(proc)
        bt.execute(
            list(perm),
            graph_edges=[],
            polling_intervals_us=[1000.0, 1000.0, 1000.0, 1000.0],
            trust_by_source=None,
        )
        c = repo.list_all()[0]
        snapshots.append(
            (
                round(c.risk_score, 9),
                tuple(sorted(c.invariant_hits)),
                tuple(sorted(c.normalized_event_ids)),
            )
        )
    assert len(set(snapshots)) == 1


def test_run_backtest_empty_events():
    assess = AssessRiskUseCase(_weights(), plc_hosts=frozenset())
    proc = ProcessEventUseCase(assess, InMemoryCaseStore())
    bt = RunBacktestUseCase(proc)
    r = bt.execute([])
    assert r.events_processed == 0
    assert r.cases_created == 0
    assert r.merges == 0
    assert r.risk_class_histogram == {}


def test_run_backtest_merge_counts_and_histogram():
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(_weights(), plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    bt = RunBacktestUseCase(proc)
    t0 = datetime(2026, 5, 1, 10, 0, tzinfo=UTC)

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

    events = [ev("e1"), ev("e2"), ev("e3")]
    r = bt.execute(
        events,
        graph_edges=[],
        polling_intervals_us=[1000.0, 1000.0, 1000.0, 1000.0],
        trust_by_source=None,
    )
    assert r.events_processed == 3
    assert r.cases_created == 1
    assert r.merges == 2
    assert len(repo.list_all()) == 1
    assert sum(r.risk_class_histogram.values()) == 3


def test_run_backtest_passes_trust_and_custom_edges():
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(_weights(), plc_hosts=frozenset({"plc-x"}))
    proc = ProcessEventUseCase(assess, repo)
    bt = RunBacktestUseCase(proc)
    t0 = datetime(2026, 5, 2, 11, 0, tzinfo=UTC)

    ev = NormalizedEvent(
        event_id="e1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="POLL",
        payload_size=10,
        payload={"asset_id": "plc-x"},
    )
    r = bt.execute(
        [ev],
        graph_edges=[GraphEdge("eng-workstation", "plc-x", "ssh")],
        polling_intervals_us=[1000.0, 1010.0, 1020.0, 1030.0],
        trust_by_source={"plc_polling": 0.8},
    )
    assert r.events_processed == 1
    assert r.cases_created == 1
    assert r.merges == 0
    assert sum(r.risk_class_histogram.values()) == 1
