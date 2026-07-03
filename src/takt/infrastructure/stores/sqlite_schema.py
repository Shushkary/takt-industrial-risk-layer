from __future__ import annotations

import sqlite3

from takt.infrastructure.stores.sqlite_connection import table_columns


def ensure_case_schema(conn: sqlite3.Connection, schema_version: int) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
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
          operator_id TEXT NOT NULL DEFAULT '',
          invariant_hits TEXT NOT NULL,
          observations TEXT NOT NULL DEFAULT '[]',
          invariant_hit_records TEXT NOT NULL DEFAULT '[]',
          manual_permits TEXT NOT NULL DEFAULT '[]',
          formal_verdict_records TEXT NOT NULL DEFAULT '[]',
          decision_records TEXT NOT NULL DEFAULT '[]',
          remediation_attempts TEXT NOT NULL DEFAULT '[]',
          dq_score REAL NOT NULL,
          dq_partial INTEGER NOT NULL,
          dq_reasons TEXT NOT NULL,
          last_event_source TEXT NOT NULL,
          raw_evidence_refs TEXT NOT NULL DEFAULT '[]',
          pdf_last_sha256 TEXT NOT NULL DEFAULT '',
          pdf_last_generated_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_cases_fp_status
          ON cases (burst_fingerprint, status);
        CREATE TABLE IF NOT EXISTS idempotency_keys (
          idem_key TEXT PRIMARY KEY NOT NULL,
          body_hash TEXT NOT NULL,
          response_json TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys (expires_at);
        CREATE TABLE IF NOT EXISTS recent_events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL,
          observed_at TEXT NOT NULL,
          source TEXT NOT NULL,
          protocol TEXT NOT NULL,
          operation TEXT NOT NULL,
          payload_size INTEGER NOT NULL,
          payload_json TEXT NOT NULL,
          operator_id TEXT NOT NULL DEFAULT '',
          inserted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recent_events_seq
          ON recent_events (seq DESC);
        CREATE TABLE IF NOT EXISTS app_metadata (
          key TEXT PRIMARY KEY NOT NULL,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_audit_ledger (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id TEXT NOT NULL,
          audit_line TEXT NOT NULL,
          line_sha256 TEXT NOT NULL,
          prev_chain_sha256 TEXT NOT NULL,
          chain_sha256 TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_case_audit_ledger_case_seq
          ON case_audit_ledger (case_id, seq);
        CREATE TRIGGER IF NOT EXISTS trg_case_audit_ledger_no_update
          BEFORE UPDATE ON case_audit_ledger
        BEGIN
          SELECT RAISE(ABORT, 'case_audit_ledger is append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS trg_case_audit_ledger_no_delete
          BEFORE DELETE ON case_audit_ledger
        BEGIN
          SELECT RAISE(ABORT, 'case_audit_ledger is append-only');
        END;
        CREATE TABLE IF NOT EXISTS operation_audit_ledger (
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
        );
        CREATE INDEX IF NOT EXISTS idx_operation_audit_stream_seq
          ON operation_audit_ledger (stream_key, seq);
        CREATE TRIGGER IF NOT EXISTS trg_operation_audit_ledger_no_update
          BEFORE UPDATE ON operation_audit_ledger
        BEGIN
          SELECT RAISE(ABORT, 'operation_audit_ledger is append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS trg_operation_audit_ledger_no_delete
          BEFORE DELETE ON operation_audit_ledger
        BEGIN
          SELECT RAISE(ABORT, 'operation_audit_ledger is append-only');
        END;
        """
    )
    cols = table_columns(conn, "cases")
    _add_missing_case_columns(conn, cols)
    _set_schema_version(conn, schema_version)


def ensure_expected_behavior_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS expected_behavior (
          asset_id_norm TEXT NOT NULL,
          operation_upper TEXT NOT NULL,
          PRIMARY KEY (asset_id_norm, operation_upper)
        );
        """
    )


def ensure_recent_events_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recent_events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL,
          observed_at TEXT NOT NULL,
          source TEXT NOT NULL,
          protocol TEXT NOT NULL,
          operation TEXT NOT NULL,
          payload_size INTEGER NOT NULL,
          payload_json TEXT NOT NULL,
          operator_id TEXT NOT NULL DEFAULT '',
          inserted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recent_events_seq
          ON recent_events (seq DESC);
        """
    )


def ensure_audit_engagement_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_engagements (
          engagement_id TEXT PRIMARY KEY NOT NULL,
          created_at TEXT NOT NULL,
          status TEXT NOT NULL,
          customer TEXT NOT NULL,
          scope TEXT NOT NULL,
          case_ids TEXT NOT NULL DEFAULT '[]',
          nda_signed INTEGER NOT NULL DEFAULT 0,
          evidence_intake_checklist TEXT NOT NULL DEFAULT '[]',
          stages TEXT NOT NULL DEFAULT '[]',
          findings TEXT NOT NULL DEFAULT '[]',
          final_report_json TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_engagements_created_at
          ON audit_engagements (created_at DESC);
        """
    )


def _add_missing_case_columns(conn: sqlite3.Connection, cols: set[str]) -> None:
    migrations = {
        "observations": "ALTER TABLE cases ADD COLUMN observations TEXT NOT NULL DEFAULT '[]'",
        "invariant_hit_records": "ALTER TABLE cases ADD COLUMN invariant_hit_records TEXT NOT NULL DEFAULT '[]'",
        "manual_permits": "ALTER TABLE cases ADD COLUMN manual_permits TEXT NOT NULL DEFAULT '[]'",
        "formal_verdict_records": "ALTER TABLE cases ADD COLUMN formal_verdict_records TEXT NOT NULL DEFAULT '[]'",
        "operator_id": "ALTER TABLE cases ADD COLUMN operator_id TEXT NOT NULL DEFAULT ''",
        "decision_records": "ALTER TABLE cases ADD COLUMN decision_records TEXT NOT NULL DEFAULT '[]'",
        "remediation_attempts": "ALTER TABLE cases ADD COLUMN remediation_attempts TEXT NOT NULL DEFAULT '[]'",
        "pdf_last_sha256": "ALTER TABLE cases ADD COLUMN pdf_last_sha256 TEXT NOT NULL DEFAULT ''",
        "pdf_last_generated_at": "ALTER TABLE cases ADD COLUMN pdf_last_generated_at TEXT NOT NULL DEFAULT ''",
        "raw_evidence_refs": "ALTER TABLE cases ADD COLUMN raw_evidence_refs TEXT NOT NULL DEFAULT '[]'",
    }
    for column, sql in migrations.items():
        if column not in cols:
            conn.execute(sql)


def _set_schema_version(conn: sqlite3.Connection, schema_version: int) -> None:
    cur = conn.execute(
        "SELECT value FROM app_metadata WHERE key = 'schema_version' LIMIT 1",
    )
    row = cur.fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO app_metadata (key, value)
            VALUES ('schema_version', ?)
            """,
            (str(schema_version),),
        )
        return
    try:
        version = int(str(row[0]))
    except ValueError:
        version = 1
    if version < schema_version:
        conn.execute(
            """
            UPDATE app_metadata SET value = ?
            WHERE key = 'schema_version'
            """,
            (str(schema_version),),
        )
        return
    if version > schema_version:
        raise RuntimeError(f"SQLite schema_version {version} is newer than supported {schema_version}")
