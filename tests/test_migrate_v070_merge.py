"""Миграция v0.7.0: свёртка открытых дубликатов в SQLite."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation
from takt.domain.engines.alert_fatigue import case_bucket_burst_fingerprint
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore


def _case(
    case_id: str,
    *,
    fp: str,
    eids: list[str],
    observations: list[Observation],
    risk: float = 0.2,
    inv: list[str] | None = None,
) -> Case:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    hits = inv or []
    recs = [
        InvariantHitRecord(
            invariant_id=h,
            event_ref=eids[0] if eids else "x",
            ts=t0,
            score_contribution=risk,
            dq_score=1.0,
            dq_partial=False,
            dq_reasons=[],
        )
        for h in hits
    ]
    return Case(
        case_id=case_id,
        status=CaseStatus.NEW,
        title=f"Risk LOW: POLL",
        risk_class="LOW",
        risk_score=risk,
        created_at=t0,
        normalized_event_ids=list(eids),
        burst_fingerprint=fp,
        primary_asset_id="plc-01",
        trigger_operation="POLL",
        invariant_hits=list(hits),
        invariant_hit_records=recs,
        observations=list(observations),
        last_event_source=observations[0].source if observations else "plc_polling",
    )


def test_merge_duplicate_open_cases_v070_idempotent(tmp_path) -> None:
    db = tmp_path / "m.db"
    store = SqliteCaseStore(db)
    try:
        c1 = _case(
            "alpha",
            fp="plc_polling|plc-01|POLL",
            eids=["e1"],
            observations=[Observation(source="plc_polling", ingest_trust=1.0, event_ids=["e1"])],
            inv=["polling_jitter"],
        )
        c2 = _case(
            "beta",
            fp="auth_logs|plc-01|POLL",
            eids=["e2"],
            observations=[Observation(source="auth_logs", ingest_trust=0.9, event_ids=["e2"])],
            risk=0.15,
            inv=[],
        )
        store.save(c1)
        store.save(c2)
        assert len(store.list_all()) == 2

        merged_groups = store.merge_duplicate_open_cases_v070(bucket_sec=300)
        assert merged_groups == 1
        rows = store.list_all()
        assert len(rows) == 1
        one = rows[0]
        assert set(one.normalized_event_ids) == {"e1", "e2"}
        assert "polling_jitter" in one.invariant_hits
        assert len(one.observations) == 2
        srcs = {o.source for o in one.observations}
        assert srcs == {"plc_polling", "auth_logs"}
        t_anchor = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
        assert one.burst_fingerprint == case_bucket_burst_fingerprint(
            primary_asset_id="plc-01",
            trigger_operation="POLL",
            created_at=t_anchor,
            bucket_sec=300,
        )

        again = store.merge_duplicate_open_cases_v070(bucket_sec=300)
        assert again == 0
        assert len(store.list_all()) == 1
    finally:
        store.close()


def test_migrate_script_runs_on_sample_db(tmp_path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    db = tmp_path / "via_script.db"
    store = SqliteCaseStore(db)
    try:
        store.save(
            _case(
                "a",
                fp="s1|plc-01|POLL",
                eids=["x"],
                observations=[Observation("plc_polling", 1.0, ["x"])],
            )
        )
        store.save(
            _case(
                "b",
                fp="s2|plc-01|POLL",
                eids=["y"],
                observations=[Observation("network_events", 1.0, ["y"])],
            )
        )
    finally:
        store.close()

    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "migrate_0_7_0.py"), str(db), "--bucket-sec", "300"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "merged_open_case_groups=1" in r.stdout

    store2 = SqliteCaseStore(db)
    try:
        assert len(store2.list_all()) == 1
    finally:
        store2.close()
