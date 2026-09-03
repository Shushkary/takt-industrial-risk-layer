#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

LATEST_SCHEMA_VERSION = 9


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _schema_version(conn: sqlite3.Connection) -> int:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_metadata (
          key TEXT PRIMARY KEY NOT NULL,
          value TEXT NOT NULL
        )
        """
    )
    row = conn.execute("SELECT value FROM app_metadata WHERE key='schema_version' LIMIT 1").fetchone()
    if row is None:
        return 1
    try:
        return int(str(row[0]))
    except ValueError:
        return 1


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        """
        INSERT INTO app_metadata (key, value) VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
        (str(version),),
    )


def _apply_to_v3(conn: sqlite3.Connection) -> None:
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "manual_permits" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN manual_permits TEXT NOT NULL DEFAULT '[]'")
    if "decision_records" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN decision_records TEXT NOT NULL DEFAULT '[]'")
    if "remediation_attempts" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN remediation_attempts TEXT NOT NULL DEFAULT '[]'")
    if "pdf_last_sha256" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN pdf_last_sha256 TEXT NOT NULL DEFAULT ''")
    if "pdf_last_generated_at" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN pdf_last_generated_at TEXT NOT NULL DEFAULT ''")


def _apply_to_v4(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_audit_ledger (
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
        CREATE INDEX IF NOT EXISTS idx_case_audit_ledger_case_seq
          ON case_audit_ledger (case_id, seq)
        """
    )


def _apply_to_v5(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
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
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_operation_audit_stream_seq
          ON operation_audit_ledger (stream_key, seq)
        """
    )


def _apply_to_v6(conn: sqlite3.Connection) -> None:
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "raw_evidence_refs" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN raw_evidence_refs TEXT NOT NULL DEFAULT '[]'")
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "case_audit_ledger" in tables:
        conn.executescript(
            """
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
            """
        )
    if "operation_audit_ledger" in tables:
        conn.executescript(
            """
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


def _apply_to_v7(conn: sqlite3.Connection) -> None:
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if cols and "formal_verdict_records" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN formal_verdict_records TEXT NOT NULL DEFAULT '[]'")


def _apply_to_v8(conn: sqlite3.Connection) -> None:
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


def _apply_to_v9(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS assembly_queue (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          pending INTEGER NOT NULL DEFAULT 0,
          lease_owner TEXT NOT NULL DEFAULT '',
          lease_until TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO assembly_queue (id, pending, lease_owner, lease_until)
          VALUES (1, 0, '', '');
        """
    )


def run(db_path: Path) -> int:
    conn = _connect(db_path)
    try:
        current = _schema_version(conn)
        if current > LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {current} is newer than supported {LATEST_SCHEMA_VERSION}"
            )
        if current < 3:
            _apply_to_v3(conn)
            current = 3
        if current < 4:
            _apply_to_v4(conn)
            current = 4
        if current < 5:
            _apply_to_v5(conn)
            current = 5
        if current < 6:
            _apply_to_v6(conn)
            current = 6
        if current < 7:
            _apply_to_v7(conn)
            current = 7
        if current < 8:
            _apply_to_v8(conn)
            current = 8
        if current < 9:
            _apply_to_v9(conn)
            current = 9
        _set_schema_version(conn, current)
        conn.commit()
        print(f"schema_version={current}")
        return 0
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply SQLite schema migrations for TAKT.")
    parser.add_argument("--db", required=True, help="Path to SQLite database.")
    args = parser.parse_args()
    return run(Path(args.db).expanduser().resolve())


if __name__ == "__main__":
    raise SystemExit(main())
