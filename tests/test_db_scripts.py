from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
from pathlib import Path

import pytest


def _load_function(script_name: str, function_name: str):
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(f"test_{script_name}", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


backup = _load_function("db_backup.py", "backup")
run = _load_function("db_migrate.py", "run")
verify = _load_function("verify_audit_ledger.py", "verify")
verify_operations = _load_function("verify_operation_ledger.py", "verify")


def test_db_migrate_adds_pdf_columns(tmp_path) -> None:
    db = tmp_path / "cases.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE cases (
              case_id TEXT PRIMARY KEY NOT NULL,
              status TEXT NOT NULL,
              title TEXT NOT NULL,
              risk_class TEXT NOT NULL,
              risk_score REAL NOT NULL,
              created_at TEXT NOT NULL,
              normalized_event_ids TEXT NOT NULL,
              xai_summary TEXT NOT NULL,
              audit_log TEXT NOT NULL,
              burst_fingerprint TEXT NOT NULL,
              primary_asset_id TEXT NOT NULL,
              trigger_operation TEXT NOT NULL,
              invariant_hits TEXT NOT NULL,
              observations TEXT NOT NULL DEFAULT '[]',
              invariant_hit_records TEXT NOT NULL DEFAULT '[]',
              manual_permits TEXT NOT NULL DEFAULT '[]',
              decision_records TEXT NOT NULL DEFAULT '[]',
              remediation_attempts TEXT NOT NULL DEFAULT '[]',
              dq_score REAL NOT NULL,
              dq_partial INTEGER NOT NULL,
              dq_reasons TEXT NOT NULL,
              last_event_source TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_version', '2')")
        conn.commit()
    finally:
        conn.close()

    assert run(db) == 0

    conn2 = sqlite3.connect(str(db))
    try:
        cols = {str(row[1]) for row in conn2.execute("PRAGMA table_info(cases)").fetchall()}
        assert "pdf_last_sha256" in cols
        assert "pdf_last_generated_at" in cols
    finally:
        conn2.close()


def test_db_backup_copies_db(tmp_path) -> None:
    src = tmp_path / "src.db"
    dst = tmp_path / "dst.db"
    conn = sqlite3.connect(str(src))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)")
        conn.execute("INSERT INTO t (v) VALUES ('ok')")
        conn.commit()
    finally:
        conn.close()

    assert backup(src, dst) == 0

    conn2 = sqlite3.connect(str(dst))
    try:
        row = conn2.execute("SELECT v FROM t LIMIT 1").fetchone()
        assert row is not None
        assert row[0] == "ok"
    finally:
        conn2.close()


def test_db_migrate_creates_audit_ledger_table(tmp_path) -> None:
    db = tmp_path / "cases_v4.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE cases (
              case_id TEXT PRIMARY KEY NOT NULL,
              status TEXT NOT NULL,
              title TEXT NOT NULL,
              risk_class TEXT NOT NULL,
              risk_score REAL NOT NULL,
              created_at TEXT NOT NULL,
              normalized_event_ids TEXT NOT NULL,
              xai_summary TEXT NOT NULL,
              audit_log TEXT NOT NULL,
              burst_fingerprint TEXT NOT NULL,
              primary_asset_id TEXT NOT NULL,
              trigger_operation TEXT NOT NULL,
              invariant_hits TEXT NOT NULL,
              observations TEXT NOT NULL DEFAULT '[]',
              invariant_hit_records TEXT NOT NULL DEFAULT '[]',
              dq_score REAL NOT NULL,
              dq_partial INTEGER NOT NULL,
              dq_reasons TEXT NOT NULL,
              last_event_source TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_version', '3')")
        conn.commit()
    finally:
        conn.close()

    assert run(db) == 0
    conn2 = sqlite3.connect(str(db))
    try:
        cols = {str(row[1]) for row in conn2.execute("PRAGMA table_info(case_audit_ledger)").fetchall()}
        assert "case_id" in cols
        assert "chain_sha256" in cols
    finally:
        conn2.close()


def test_verify_audit_ledger_script_function(tmp_path) -> None:
    db = tmp_path / "verify.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE case_audit_ledger (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              audit_line TEXT NOT NULL,
              line_sha256 TEXT NOT NULL,
              prev_chain_sha256 TEXT NOT NULL,
              chain_sha256 TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        line = "2026-05-01T00:00:00+00:00 | created"
        line_sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
        chain_sha = hashlib.sha256(f":c-1:{line_sha}:{len(line)}".encode()).hexdigest()
        conn.execute(
            """
            INSERT INTO case_audit_ledger (
              case_id, audit_line, line_sha256, prev_chain_sha256, chain_sha256, created_at
            ) VALUES (?,?,?,?,?,?)
            """,
            ("c-1", line, line_sha, "", chain_sha, "2026-05-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()
    ok = verify(db, "c-1")
    assert ok["ok"] is True


def test_db_migrate_creates_operation_ledger_table(tmp_path) -> None:
    db = tmp_path / "cases_v5.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE cases (
              case_id TEXT PRIMARY KEY NOT NULL,
              status TEXT NOT NULL,
              title TEXT NOT NULL,
              risk_class TEXT NOT NULL,
              risk_score REAL NOT NULL,
              created_at TEXT NOT NULL,
              normalized_event_ids TEXT NOT NULL,
              xai_summary TEXT NOT NULL,
              audit_log TEXT NOT NULL,
              burst_fingerprint TEXT NOT NULL,
              primary_asset_id TEXT NOT NULL,
              trigger_operation TEXT NOT NULL,
              invariant_hits TEXT NOT NULL,
              observations TEXT NOT NULL DEFAULT '[]',
              invariant_hit_records TEXT NOT NULL DEFAULT '[]',
              dq_score REAL NOT NULL,
              dq_partial INTEGER NOT NULL,
              dq_reasons TEXT NOT NULL,
              last_event_source TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_version', '4')")
        conn.commit()
    finally:
        conn.close()
    assert run(db) == 0
    conn2 = sqlite3.connect(str(db))
    try:
        cols = {str(row[1]) for row in conn2.execute("PRAGMA table_info(operation_audit_ledger)").fetchall()}
        assert "stream_key" in cols
        assert "chain_sha256" in cols
    finally:
        conn2.close()


def test_verify_operation_ledger_script_function(tmp_path) -> None:
    db = tmp_path / "verify-op.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE operation_audit_ledger (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              stream_key TEXT NOT NULL,
              operation_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              actor TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              prev_chain_sha256 TEXT NOT NULL,
              chain_sha256 TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        payload = '{"case_id":"c-1","next_status":"TRIAGE"}'
        payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        chain_sha = hashlib.sha256(f":decision:c-1:{payload_sha}:{len(payload)}".encode()).hexdigest()
        conn.execute(
            """
            INSERT INTO operation_audit_ledger (
              stream_key, operation_type, entity_id, actor, payload_json,
              payload_sha256, prev_chain_sha256, chain_sha256, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                "decision:c-1",
                "decision",
                "c-1",
                "operator-1",
                payload,
                payload_sha,
                "",
                chain_sha,
                "2026-05-01T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    ok = verify_operations(db, "decision:c-1")
    assert ok["ok"] is True


def test_db_migrate_v6_adds_raw_evidence_and_append_only_triggers(tmp_path) -> None:
    db = tmp_path / "cases_v6.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE cases (
              case_id TEXT PRIMARY KEY NOT NULL,
              status TEXT NOT NULL,
              title TEXT NOT NULL,
              risk_class TEXT NOT NULL,
              risk_score REAL NOT NULL,
              created_at TEXT NOT NULL,
              normalized_event_ids TEXT NOT NULL,
              xai_summary TEXT NOT NULL,
              audit_log TEXT NOT NULL,
              burst_fingerprint TEXT NOT NULL,
              primary_asset_id TEXT NOT NULL,
              trigger_operation TEXT NOT NULL,
              invariant_hits TEXT NOT NULL,
              observations TEXT NOT NULL DEFAULT '[]',
              invariant_hit_records TEXT NOT NULL DEFAULT '[]',
              manual_permits TEXT NOT NULL DEFAULT '[]',
              decision_records TEXT NOT NULL DEFAULT '[]',
              remediation_attempts TEXT NOT NULL DEFAULT '[]',
              dq_score REAL NOT NULL,
              dq_partial INTEGER NOT NULL,
              dq_reasons TEXT NOT NULL,
              last_event_source TEXT NOT NULL,
              pdf_last_sha256 TEXT NOT NULL DEFAULT '',
              pdf_last_generated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE case_audit_ledger (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              audit_line TEXT NOT NULL,
              line_sha256 TEXT NOT NULL,
              prev_chain_sha256 TEXT NOT NULL,
              chain_sha256 TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE operation_audit_ledger (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              stream_key TEXT NOT NULL,
              operation_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              actor TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              prev_chain_sha256 TEXT NOT NULL,
              chain_sha256 TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_version', '5')")
        conn.execute(
            """
            INSERT INTO case_audit_ledger (
              case_id, audit_line, line_sha256, prev_chain_sha256, chain_sha256, created_at
            ) VALUES ('c-1','line','x','','y','2026-05-01T00:00:00+00:00')
            """
        )
        conn.execute(
            """
            INSERT INTO operation_audit_ledger (
              stream_key, operation_type, entity_id, actor, payload_json, payload_sha256, prev_chain_sha256, chain_sha256, created_at
            ) VALUES ('decision:c-1','decision','c-1','op','{}','x','','y','2026-05-01T00:00:00+00:00')
            """
        )
        conn.commit()
    finally:
        conn.close()
    assert run(db) == 0
    conn2 = sqlite3.connect(str(db))
    try:
        cols = {str(row[1]) for row in conn2.execute("PRAGMA table_info(cases)").fetchall()}
        assert "raw_evidence_refs" in cols
        with pytest.raises(sqlite3.DatabaseError):
            conn2.execute("UPDATE case_audit_ledger SET audit_line='tamper' WHERE case_id='c-1'")
        with pytest.raises(sqlite3.DatabaseError):
            conn2.execute("UPDATE operation_audit_ledger SET payload_json='tamper' WHERE stream_key='decision:c-1'")
    finally:
        conn2.close()


def test_db_migrate_v8_adds_recent_events_table(tmp_path) -> None:
    db = tmp_path / "migrate-v8.sqlite"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_version', '7')")
        conn.commit()
    finally:
        conn.close()

    rc = run(db)
    assert rc == 0

    conn2 = sqlite3.connect(str(db))
    try:
        cols = {str(row[1]) for row in conn2.execute("PRAGMA table_info(recent_events)").fetchall()}
        assert {"event_id", "observed_at", "payload_json", "inserted_at"}.issubset(cols)
        version = conn2.execute("SELECT value FROM app_metadata WHERE key='schema_version'").fetchone()[0]
        assert version == "8"
    finally:
        conn2.close()
