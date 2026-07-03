from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import sqlite3

from takt.domain.entities.case import (
    Case,
    CaseDecisionRecord,
    CaseStatus,
    FormalVerdictRecord,
    InvariantHitRecord,
    ManualPermit,
    Observation,
    RemediationAttempt,
)
from takt.infrastructure.stores.sqlite_store import (
    CURRENT_DB_SCHEMA_VERSION,
    SqliteCaseStore,
    _checkpoint_wal_best_effort,
)


def test_sqlite_case_store_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "cases.db"
    store = SqliteCaseStore(db)
    t0 = datetime(2026, 5, 2, 9, 0, tzinfo=timezone.utc)
    c = Case(
        case_id="abc12345",
        status=CaseStatus.NEW,
        title="Risk HIGH: READ",
        risk_class="HIGH",
        risk_score=0.71,
        created_at=t0,
        normalized_event_ids=["e1", "e2"],
        xai_summary="what | why",
        audit_log=["2026-05-02T09:00:00+00:00 | created"],
        burst_fingerprint="plc_polling|plc-1|READ",
        primary_asset_id="plc-1",
        trigger_operation="READ",
        invariant_hits=["polling_period_doubling_suspect"],
        observations=[
            Observation(source="plc_polling", ingest_trust=1.0, event_ids=["e1"]),
        ],
        invariant_hit_records=[
            InvariantHitRecord(
                invariant_id="polling_period_doubling_suspect",
                event_ref="e1",
                ts=t0,
                score_contribution=0.5,
                dq_score=0.9,
                dq_partial=False,
                dq_reasons=[],
            )
        ],
        dq_score=0.9,
        dq_partial=False,
        dq_reasons=[],
        last_event_source="plc_polling",
    )
    store.save(c)
    loaded = store.get("abc12345")
    assert loaded is not None
    assert loaded.case_id == c.case_id
    assert loaded.status == c.status
    assert loaded.normalized_event_ids == ["e1", "e2"]
    assert loaded.invariant_hits == ["polling_period_doubling_suspect"]
    assert loaded.last_event_source == "plc_polling"
    assert len(loaded.observations) == 1
    assert loaded.observations[0].event_ids == ["e1"]
    assert len(loaded.invariant_hit_records) == 1
    assert loaded.invariant_hit_records[0].event_ref == "e1"
    assert len(store.list_all()) == 1

    c.status = CaseStatus.TRIAGE
    c.normalized_event_ids.append("e3")
    store.save(c)
    loaded2 = store.get("abc12345")
    assert loaded2 is not None
    assert loaded2.status == CaseStatus.TRIAGE
    assert loaded2.normalized_event_ids == ["e1", "e2", "e3"]
    store.close()
    store.close()


def test_sqlite_find_open_by_fingerprint_status(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SqliteCaseStore(db)
    t0 = datetime(2026, 5, 2, 10, 0, tzinfo=timezone.utc)
    fp = "plc_polling|x|POLL"

    open_case = Case(
        case_id="open1",
        status=CaseStatus.TRIAGE,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        normalized_event_ids=["a"],
        burst_fingerprint=fp,
        primary_asset_id="x",
        trigger_operation="POLL",
    )
    closed = Case(
        case_id="closed1",
        status=CaseStatus.FALSE_POSITIVE,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=t0,
        normalized_event_ids=["b"],
        burst_fingerprint=fp,
        primary_asset_id="x",
        trigger_operation="POLL",
    )
    store.save(open_case)
    store.save(closed)
    found = store.find_open_by_fingerprint(fp)
    assert found is not None
    assert found.case_id == "open1"
    store.close()


def test_sqlite_case_store_reports_db_schema_version(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "v.db")
    try:
        assert store.db_schema_version() == CURRENT_DB_SCHEMA_VERSION
    finally:
        store.close()


def test_sqlite_case_store_close_idempotent(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "close.db")
    store.close()
    store.close()
    assert (tmp_path / "close.db").is_file()


def test_sqlite_get_missing_returns_none(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "empty.db")
    try:
        assert store.get("no-such-case") is None
    finally:
        store.close()


def test_sqlite_save_after_close_raises(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteCaseStore(tmp_path / "closed-save.db")
    t0 = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)
    c = Case(
        case_id="x",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=t0,
    )
    store.save(c)
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.save(c)


def test_sqlite_get_and_list_after_close_raises(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteCaseStore(tmp_path / "closed-read.db")
    t0 = datetime(2026, 7, 2, 9, 0, tzinfo=timezone.utc)
    store.save(
        Case(
            case_id="y",
            status=CaseStatus.NEW,
            title="t",
            risk_class="LOW",
            risk_score=0.1,
            created_at=t0,
        )
    )
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.get("y")
    with pytest.raises(sqlite3.ProgrammingError):
        store.list_all()


def test_sqlite_find_open_after_close_raises(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteCaseStore(tmp_path / "closed-find.db")
    t0 = datetime(2026, 7, 3, 9, 0, tzinfo=timezone.utc)
    store.save(
        Case(
            case_id="z",
            status=CaseStatus.NEW,
            title="t",
            risk_class="LOW",
            risk_score=0.1,
            created_at=t0,
            burst_fingerprint="f",
        )
    )
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.find_open_by_fingerprint("f")


def test_sqlite_db_schema_version_after_close_raises(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteCaseStore(tmp_path / "closed-schema.db")
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.db_schema_version()


def test_sqlite_list_all_orders_by_created_at_desc(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "order.db")
    t_old = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
    t_new = datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc)
    store.save(
        Case(
            case_id="older",
            status=CaseStatus.NEW,
            title="a",
            risk_class="LOW",
            risk_score=0.1,
            created_at=t_old,
        )
    )
    store.save(
        Case(
            case_id="newer",
            status=CaseStatus.NEW,
            title="b",
            risk_class="LOW",
            risk_score=0.2,
            created_at=t_new,
        )
    )
    rows = store.list_all()
    assert [c.case_id for c in rows] == ["newer", "older"]
    store.close()


def test_sqlite_loads_created_at_with_z_suffix(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "ztime.db")
    t0 = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
    try:
        store.save(
            Case(
                case_id="z1",
                status=CaseStatus.NEW,
                title="t",
                risk_class="LOW",
                risk_score=0.1,
                created_at=t0,
            )
        )
        store._conn.execute(
            "UPDATE cases SET created_at = ? WHERE case_id = ?",
            ("2026-09-01T08:00:00Z", "z1"),
        )
        loaded = store.get("z1")
        assert loaded is not None
        assert loaded.created_at.tzinfo is not None
        assert loaded.created_at.isoformat(timespec="seconds") == "2026-09-01T08:00:00+00:00"
    finally:
        store.close()


def test_sqlite_db_schema_version_defaults_when_metadata_row_missing(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "meta.db")
    try:
        store._conn.execute("DELETE FROM app_metadata WHERE key = 'schema_version'")
        assert store.db_schema_version() == CURRENT_DB_SCHEMA_VERSION
    finally:
        store.close()


def test_sqlite_naive_created_at_roundtrip(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "naive.db")
    t_naive = datetime(2026, 8, 1, 12, 30, 5)
    c = Case(
        case_id="naive1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=t_naive,
    )
    try:
        store.save(c)
        loaded = store.get("naive1")
        assert loaded is not None
        assert loaded.created_at.isoformat(timespec="seconds") == t_naive.isoformat(timespec="seconds")
    finally:
        store.close()


def test_checkpoint_wal_best_effort_swallows_sqlite_errors() -> None:
    conn = MagicMock()
    conn.execute.side_effect = sqlite3.Error("wal fail")
    _checkpoint_wal_best_effort(conn)
    assert conn.execute.call_count == 2


def test_sqlite_audit_ledger_verification_ok_and_detects_tamper(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "ledger.db")
    try:
        t0 = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
        c = Case(
            case_id="ledger-1",
            status=CaseStatus.NEW,
            title="t",
            risk_class="LOW",
            risk_score=0.1,
            created_at=t0,
        )
        c.append_audit("created", t0)
        store.save(c)
        ok = store.verify_audit_ledger("ledger-1")
        assert ok["ok"] is True
        assert ok["checked_entries"] == 1
        with pytest.raises(sqlite3.DatabaseError):
            store._conn.execute(
                "UPDATE case_audit_ledger SET audit_line = ? WHERE case_id = ?",
                ("2026-09-02T09:00:00+00:00 | tampered", "ledger-1"),
            )
    finally:
        store.close()


def test_sqlite_operation_ledger_verification_ok_and_detects_tamper(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "op-ledger.db")
    try:
        store.record_operation_event(
            operation_type="decision",
            entity_id="case-1",
            actor="operator-1",
            payload_json=json.dumps({"case_id": "case-1", "next_status": "TRIAGE"}, sort_keys=True),
            created_at="2026-09-02T09:00:00+00:00",
        )
        ok = store.verify_operation_ledger("decision:case-1")
        assert ok["ok"] is True
        assert ok["checked_entries"] == 1
        with pytest.raises(sqlite3.DatabaseError):
            store._conn.execute(
                "UPDATE operation_audit_ledger SET payload_json = ? WHERE stream_key = ?",
                ('{"case_id":"case-1","next_status":"CLOSED"}', "decision:case-1"),
            )
    finally:
        store.close()


def test_sqlite_roundtrip_persists_manual_decision_remediation_and_pdf_fields(tmp_path: Path) -> None:
    db = tmp_path / "cases-full-roundtrip.db"
    store = SqliteCaseStore(db)
    try:
        t0 = datetime(2026, 9, 3, 9, 0, tzinfo=timezone.utc)
        case = Case(
            case_id="case-full-1",
            status=CaseStatus.TRIAGE,
            title="Risk HIGH: WRITE_COIL",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=t0,
            operator_id="operator-1",
            manual_permits=[
                ManualPermit(
                    permit_id="permit-1",
                    case_id="case-full-1",
                    work_order_number="WO-1",
                    actor="operator-1",
                    created_at=t0,
                    asset_id="plc-01",
                    operation="WRITE_COIL",
                    verdict="legitimate",
                    confidence=0.85,
                    rationale="planned work",
                    counterfactual="would be illegitimate otherwise",
                    note="ok",
                )
            ],
            formal_verdict_records=[
                FormalVerdictRecord(
                    ts=t0,
                    actor="operator-1",
                    prev="неопределённое",
                    next="легитимное",
                    score=0.85,
                    source="manual_permit",
                    permit_id="permit-1",
                    reason="planned work",
                )
            ],
            decision_records=[
                CaseDecisionRecord(
                    ts=t0,
                    actor="operator-1",
                    prev_status="NEW",
                    next_status="TRIAGE",
                    reason="manual review",
                    request_id="req-1",
                )
            ],
            remediation_attempts=[
                RemediationAttempt(
                    attempt_id="att-1",
                    case_id="case-full-1",
                    kind="generate_forensic_bundle",
                    status="completed",
                    actor="operator-1",
                    created_at=t0,
                    action="bundle generated",
                    result="ok",
                    readiness_before=False,
                    readiness_after=True,
                    note="done",
                    request_id="req-2",
                )
            ],
            pdf_last_sha256="a" * 64,
            pdf_last_generated_at="2026-09-03T09:00:00+00:00",
        )
        store.save(case)
        loaded = store.get("case-full-1")
        assert loaded is not None
        assert loaded.operator_id == "operator-1"
        assert loaded.manual_permits and loaded.manual_permits[0].work_order_number == "WO-1"
        assert loaded.formal_verdict_records and loaded.formal_verdict_records[0].next == "легитимное"
        assert loaded.formal_verdict_records[0].score == 0.85
        assert loaded.decision_records and loaded.decision_records[0].reason == "manual review"
        assert loaded.remediation_attempts and loaded.remediation_attempts[0].readiness_after is True
        assert loaded.pdf_last_sha256 == "a" * 64
        assert loaded.pdf_last_generated_at == "2026-09-03T09:00:00+00:00"
    finally:
        store.close()
