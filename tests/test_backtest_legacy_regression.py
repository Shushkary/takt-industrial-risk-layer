"""Регрессия: backtest `plc_polling_demo.csv` в режиме **alert_fatigue: legacy** совпадает с золотым JSON."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.entities.event import EventSource
from takt.domain.ports.system_ports import IdProviderPort
from takt.infrastructure.importers.csv_events import load_normalized_from_csv
from takt.infrastructure.stores.memory import InMemoryCaseStore


class _FixedCaseIds(IdProviderPort):
    __slots__ = ()

    def new_case_id_short(self) -> str:
        return "aaaaaaaa"


def _legacy_weights() -> dict:
    return {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
        "alert_fatigue": {"mode": "legacy", "bucket_sec": 300},
    }


def test_backtest_plc_polling_demo_legacy_byte_identical() -> None:
    root = Path(__file__).resolve().parent
    golden_path = root / "fixtures" / "backtest_plc_polling_demo_legacy_golden.json"
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    csv_path = root.parent / "config" / "demo" / "plc_polling_demo.csv"
    events = load_normalized_from_csv(csv_path, source=EventSource.PLC_POLLING)
    events = [replace(ev, event_id=f"e{i}") for i, ev in enumerate(events)]

    repo = InMemoryCaseStore()
    proc = ProcessEventUseCase(
        AssessRiskUseCase(_legacy_weights(), plc_hosts=frozenset({"plc-01"}), ids=_FixedCaseIds()),
        repo,
    )
    rep = RunBacktestUseCase(proc).execute(
        events,
        graph_edges=[],
        polling_intervals_us=[1000.0, 1000.0, 1000.0, 1000.0],
        trust_by_source=None,
    )

    assert rep.events_processed == golden["report"]["events_processed"]
    assert rep.cases_created == golden["report"]["cases_created"]
    assert rep.merges == golden["report"]["merges"]
    assert dict(sorted(rep.risk_class_histogram.items())) == golden["report"]["risk_class_histogram"]

    cases = sorted(repo.list_all(), key=lambda c: c.case_id)
    assert len(cases) == golden["final_case_count"]

    snap = []
    for c in cases:
        snap.append(
            {
                "case_id": c.case_id,
                "risk_score": round(c.risk_score, 12),
                "risk_class": c.risk_class,
                "invariant_hits": sorted(c.invariant_hits),
                "burst_fingerprint": c.burst_fingerprint,
                "normalized_event_ids": list(c.normalized_event_ids),
                "invariant_hit_records_count": len(c.invariant_hit_records),
            }
        )
    assert snap == golden["cases_snapshot"]

    # Строгое побайтовое совпадение сериализации снимка (чек-лист Спринта 2)
    assert json.dumps(snap, ensure_ascii=False, sort_keys=True) == json.dumps(
        golden["cases_snapshot"], ensure_ascii=False, sort_keys=True
    )
