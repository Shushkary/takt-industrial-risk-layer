from __future__ import annotations

import json
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
          correlation_fingerprints TEXT NOT NULL DEFAULT '[]',
          correlation_evidence TEXT NOT NULL DEFAULT '[]',
          related_cases TEXT NOT NULL DEFAULT '[]',
          artifacts TEXT NOT NULL DEFAULT '[]',
          findings TEXT NOT NULL DEFAULT '[]',
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
        CREATE TABLE IF NOT EXISTS case_correlation_keys (
          fingerprint TEXT NOT NULL,
          case_id TEXT NOT NULL,
          PRIMARY KEY (fingerprint, case_id)
        );
        CREATE INDEX IF NOT EXISTS idx_case_correlation_keys_fp
          ON case_correlation_keys (fingerprint);
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
    ensure_assembly_queue_schema(conn)
    cols = table_columns(conn, "cases")
    _add_missing_case_columns(conn, cols)
    _set_schema_version(conn, schema_version)


def ensure_assembly_queue_schema(conn: sqlite3.Connection) -> None:
    """Очередь сигналов сборки: одна строка со счётчиком и арендой воркера.

    `CHECK (id = 1)` — не украшение: строка здесь ровно одна, и без ограничения ошибка
    вставки развела бы приём и воркер по разным счётчикам, а выглядело бы это как «воркер
    молчит».
    """
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
        -- Отпечатки настройки сборки лежат в общих метаданных. Очередь открывают и на базе,
        -- где схема кейсов ещё не создавалась (воркер, поднятый раньше API), поэтому таблица
        -- заводится здесь же.
        CREATE TABLE IF NOT EXISTS app_metadata (
          key TEXT PRIMARY KEY NOT NULL,
          value TEXT NOT NULL
        );
        """
    )


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
        CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY NOT NULL,
          observed_at TEXT NOT NULL,
          source TEXT NOT NULL,
          protocol TEXT NOT NULL,
          operation TEXT NOT NULL,
          payload_size INTEGER NOT NULL,
          payload_json TEXT NOT NULL,
          operator_id TEXT NOT NULL DEFAULT '',
          host_id TEXT,
          user_id TEXT,
          process_id TEXT,
          parent_process_id TEXT,
          src_address TEXT,
          dst_address TEXT,
          artifacts_json TEXT NOT NULL DEFAULT '[]',
          ingest_trust REAL NOT NULL DEFAULT 1.0,
          inserted_at TEXT NOT NULL,
          process_key TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_source_time ON events (source, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_host_time ON events (host_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_user_time ON events (user_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_process_time ON events (process_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_process_key_time ON events (process_key, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_src_address ON events (src_address);
        CREATE INDEX IF NOT EXISTS idx_events_dst_address ON events (dst_address);
        CREATE TABLE IF NOT EXISTS entity_registry (
          entity_type TEXT NOT NULL,
          entity_id TEXT NOT NULL,
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          sources_json TEXT NOT NULL DEFAULT '[]',
          event_count INTEGER NOT NULL DEFAULT 0,
          attributes_json TEXT NOT NULL DEFAULT '{}',
          PRIMARY KEY (entity_type, entity_id)
        );
        CREATE TABLE IF NOT EXISTS entity_activity (
          entity_type TEXT NOT NULL,
          entity_id TEXT NOT NULL,
          bucket_hour TEXT NOT NULL,
          event_count INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (entity_type, entity_id, bucket_hour)
        );
        CREATE INDEX IF NOT EXISTS idx_entity_activity_lookup
          ON entity_activity (entity_type, entity_id, bucket_hour DESC);
        """
    )
    _migrate_process_identity(conn)


# Версия схемы хранилища событий. Поднимается, когда прежние записи нужно пересобрать:
# `CREATE TABLE IF NOT EXISTS` существующую базу не трогает, и без явного шага миграции
# старые строки остались бы жить по прежнему ключу.
_RECENT_EVENTS_SCHEMA_VERSION = 1


def _migrate_process_identity(conn: sqlite3.Connection) -> None:
    """Ключ процесса: заполнение колонки и пересборка реестра по прежним событиям.

    До этой правки процесс заводился по значению из источника, и один PID на двух узлах давал
    одну карточку. Ключ считается заново из уже принятых событий — сами события не меняются,
    пересобираются только производные строки реестра и почасовой активности.
    """
    from takt.domain.services.process_identity import process_entity_key, process_identity_kind

    cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    if "process_key" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN process_key TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_process_key_time ON events (process_key, observed_at DESC)"
        )
    version = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
    if version >= _RECENT_EVENTS_SCHEMA_VERSION:
        return

    rows = conn.execute(
        "SELECT event_id, host_id, process_id, source, observed_at, parent_process_id"
        " FROM events WHERE process_id IS NOT NULL AND process_id != ''"
    ).fetchall()
    conn.execute("DELETE FROM entity_registry WHERE entity_type = 'process'")
    conn.execute("DELETE FROM entity_activity WHERE entity_type = 'process'")
    registry: dict[str, dict] = {}
    activity: dict[tuple[str, str], int] = {}
    for event_id, host_id, process_id, source, observed_at, parent_process_id in rows:
        key = process_entity_key(process_id, host_id)
        if not key:
            continue
        conn.execute("UPDATE events SET process_key = ? WHERE event_id = ?", (key, event_id))
        entry = registry.setdefault(
            key,
            {
                "first_seen": observed_at,
                "last_seen": observed_at,
                "sources": set(),
                "count": 0,
                "attributes": {
                    "display_id": process_id,
                    "host_id": host_id,
                    "identity": process_identity_kind(process_id, host_id),
                },
            },
        )
        entry["first_seen"] = min(entry["first_seen"], observed_at)
        entry["last_seen"] = max(entry["last_seen"], observed_at)
        entry["sources"].add(source)
        entry["count"] += 1
        if parent_process_id:
            entry["attributes"]["parent_process_id"] = parent_process_id
        bucket = f"{str(observed_at)[:13]}:00:00Z".replace(" ", "T")
        activity[(key, bucket)] = activity.get((key, bucket), 0) + 1
    for key, entry in registry.items():
        conn.execute(
            """
            INSERT INTO entity_registry (
              entity_type, entity_id, first_seen, last_seen, sources_json, event_count, attributes_json
            ) VALUES ('process', ?, ?, ?, ?, ?, ?)
            """,
            (
                key, entry["first_seen"], entry["last_seen"],
                json.dumps(sorted(entry["sources"])), entry["count"],
                json.dumps(entry["attributes"], ensure_ascii=False),
            ),
        )
    for (key, bucket), count in activity.items():
        conn.execute(
            "INSERT INTO entity_activity (entity_type, entity_id, bucket_hour, event_count)"
            " VALUES ('process', ?, ?, ?)",
            (key, bucket, count),
        )
    conn.execute(f"PRAGMA user_version = {_RECENT_EVENTS_SCHEMA_VERSION}")


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
        "correlation_fingerprints": "ALTER TABLE cases ADD COLUMN correlation_fingerprints TEXT NOT NULL DEFAULT '[]'",
        "correlation_evidence": "ALTER TABLE cases ADD COLUMN correlation_evidence TEXT NOT NULL DEFAULT '[]'",
        "related_cases": "ALTER TABLE cases ADD COLUMN related_cases TEXT NOT NULL DEFAULT '[]'",
        "artifacts": "ALTER TABLE cases ADD COLUMN artifacts TEXT NOT NULL DEFAULT '[]'",
        "findings": "ALTER TABLE cases ADD COLUMN findings TEXT NOT NULL DEFAULT '[]'",
        "risk_vectors": "ALTER TABLE cases ADD COLUMN risk_vectors TEXT NOT NULL DEFAULT '{}'",
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
