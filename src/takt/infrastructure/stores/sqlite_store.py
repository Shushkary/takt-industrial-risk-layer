from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from takt.domain.entities.case import (
    Case,
    CaseStatus,
)
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.infrastructure.stores.sqlite_audit_engagement_store import SqliteAuditEngagementStore
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
    configure_sqlite_connection as _configure_sqlite_connection,
    dt_to_sql as _dt_to_sql,
    sqlite_busy_timeout_ms_from_env,
)
from takt.infrastructure.stores.sqlite_audit_ledger import (
    append_case_audit_ledger_line,
    record_operation_event as _record_operation_event,
    verify_case_audit_ledger,
    verify_operation_ledger as _verify_operation_ledger,
)
from takt.infrastructure.stores.sqlite_case_mapper import (
    _row_to_case,
    _serialize_decision_records,
    _serialize_formal_verdict_records,
    _serialize_hit_records,
    _serialize_manual_permits,
    _serialize_observations,
    _serialize_raw_evidence_refs,
    _serialize_remediation_attempts,
)
from takt.infrastructure.stores.sqlite_expected_behavior import SqliteExpectedBehavior
from takt.infrastructure.stores.sqlite_schema import ensure_case_schema

# Р’РµСЂСЃРёСЏ СЃС…РµРјС‹ Р‘Р” РєРµР№СЃРѕРІ (РјРµС‚Р°РґР°РЅРЅС‹Рµ `app_metadata`); РїСЂРё РјРёРіСЂР°С†РёСЏС… СѓРІРµР»РёС‡РёРІР°С‚СЊ.
CURRENT_DB_SCHEMA_VERSION = 8


class SqliteCaseStore(CaseRepositoryPort):
    """РџРµСЂСЃРёСЃС‚РµРЅС‚РЅРѕРµ С…СЂР°РЅРёР»РёС‰Рµ РєРµР№СЃРѕРІ (РѕРґРёРЅ С„Р°Р№Р» SQLite РЅР° РїСЂРѕС†РµСЃСЃ API)."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._closed = False
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        _configure_sqlite_connection(self._conn)
        self._ensure_schema()

    @property
    def database_path(self) -> Path:
        """РџСѓС‚СЊ Рє С„Р°Р№Р»Сѓ Р‘Р” РєРµР№СЃРѕРІ (РґР»СЏ **security_log** Рё СЂРµР·РµСЂРІРЅРѕРіРѕ РєРѕРїРёСЂРѕРІР°РЅРёСЏ)."""
        return self._path

    def _ensure_schema(self) -> None:
        with self._lock:
            ensure_case_schema(self._conn, CURRENT_DB_SCHEMA_VERSION)

    def _append_audit_ledger_line(self, case_id: str, audit_line: str, created_at: str) -> None:
        append_case_audit_ledger_line(
            self._conn,
            case_id=case_id,
            audit_line=audit_line,
            created_at=created_at,
        )

    def db_schema_version(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM app_metadata WHERE key = 'schema_version' LIMIT 1",
            )
            row = cur.fetchone()
            if row is None:
                return CURRENT_DB_SCHEMA_VERSION
            return int(str(row[0]))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    @contextmanager
    def transaction(self):
        """РЇРІРЅР°СЏ С‚СЂР°РЅР·Р°РєС†РёСЏ: COMMIT РїСЂРё СѓСЃРїРµС…Рµ, ROLLBACK РїСЂРё РёСЃРєР»СЋС‡РµРЅРёРё (РґР»СЏ РїР°РєРµС‚РЅРѕРіРѕ РёРјРїРѕСЂС‚Р°)."""
        with self._lock:
            if self._closed:
                raise RuntimeError("SqliteCaseStore connection is closed")
            self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            with self._lock:
                self._conn.rollback()
            raise
        else:
            with self._lock:
                self._conn.commit()

    def save(self, case: Case) -> None:
        with self._lock:
            existing = self.get(case.case_id)
            self._conn.execute(
                """
                INSERT INTO cases (
                  case_id, status, title, risk_class, risk_score, created_at,
                  normalized_event_ids, xai_summary, audit_log, burst_fingerprint,
                  primary_asset_id, trigger_operation, operator_id, invariant_hits,
                  observations, invariant_hit_records, manual_permits, formal_verdict_records, decision_records, remediation_attempts,
                  dq_score, dq_partial, dq_reasons, last_event_source, raw_evidence_refs, pdf_last_sha256, pdf_last_generated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(case_id) DO UPDATE SET
                  status = excluded.status,
                  title = excluded.title,
                  risk_class = excluded.risk_class,
                  risk_score = excluded.risk_score,
                  created_at = excluded.created_at,
                  normalized_event_ids = excluded.normalized_event_ids,
                  xai_summary = excluded.xai_summary,
                  audit_log = excluded.audit_log,
                  burst_fingerprint = excluded.burst_fingerprint,
                  primary_asset_id = excluded.primary_asset_id,
                  trigger_operation = excluded.trigger_operation,
                  operator_id = excluded.operator_id,
                  invariant_hits = excluded.invariant_hits,
                  observations = excluded.observations,
                  invariant_hit_records = excluded.invariant_hit_records,
                  manual_permits = excluded.manual_permits,
                  formal_verdict_records = excluded.formal_verdict_records,
                  decision_records = excluded.decision_records,
                  remediation_attempts = excluded.remediation_attempts,
                  dq_score = excluded.dq_score,
                  dq_partial = excluded.dq_partial,
                  dq_reasons = excluded.dq_reasons,
                  last_event_source = excluded.last_event_source,
                  raw_evidence_refs = excluded.raw_evidence_refs,
                  pdf_last_sha256 = excluded.pdf_last_sha256,
                  pdf_last_generated_at = excluded.pdf_last_generated_at
                """,
                (
                    case.case_id,
                    case.status.value,
                    case.title,
                    case.risk_class,
                    case.risk_score,
                    _dt_to_sql(case.created_at),
                    json.dumps(case.normalized_event_ids, ensure_ascii=False),
                    case.xai_summary,
                    json.dumps(case.audit_log, ensure_ascii=False),
                    case.burst_fingerprint,
                    case.primary_asset_id,
                    case.trigger_operation,
                    case.operator_id,
                    json.dumps(case.invariant_hits, ensure_ascii=False),
                    _serialize_observations(case.observations),
                    _serialize_hit_records(case.invariant_hit_records),
                    _serialize_manual_permits(case.manual_permits),
                    _serialize_formal_verdict_records(case.formal_verdict_records),
                    _serialize_decision_records(case.decision_records),
                    _serialize_remediation_attempts(case.remediation_attempts),
                    case.dq_score,
                    1 if case.dq_partial else 0,
                    json.dumps(case.dq_reasons, ensure_ascii=False),
                    case.last_event_source,
                    _serialize_raw_evidence_refs(case.raw_evidence_refs),
                    case.pdf_last_sha256,
                    case.pdf_last_generated_at,
                ),
            )
            old_audit = existing.audit_log if existing is not None else []
            if len(case.audit_log) > len(old_audit):
                for line in case.audit_log[len(old_audit) :]:
                    created_at = line.split(" | ", 1)[0] if " | " in line else _dt_to_sql(datetime.now(timezone.utc))
                    self._append_audit_ledger_line(case.case_id, line, created_at)

    def delete_cases_by_id(self, case_ids: Sequence[str]) -> int:
        """РЈРґР°Р»РµРЅРёРµ РєР°СЂС‚РѕС‡РµРє РїРѕ **case_id** (СЃРєСЂРёРїС‚С‹ РјРёРіСЂР°С†РёРё; РІРЅРµ РїРѕСЂС‚Р° СЂРµРїРѕР·РёС‚РѕСЂРёСЏ)."""
        if not case_ids:
            return 0
        with self._lock:
            n = 0
            for cid in case_ids:
                cur = self._conn.execute("DELETE FROM cases WHERE case_id = ?", (cid,))
                n += cur.rowcount or 0
            return n

    def merge_duplicate_open_cases_v070(self, bucket_sec: int = 300) -> int:
        """
        РРґРµРјРїРѕС‚РµРЅС‚РЅРѕ СЃРІРѕСЂР°С‡РёРІР°РµС‚ РѕС‚РєСЂС‹С‚С‹Рµ РєРµР№СЃС‹ СЃ РѕРґРЅРѕР№ РїР°СЂРѕР№ (Р°РєС‚РёРІ, РѕРїРµСЂР°С†РёСЏ) РІ РѕРґРЅРѕРј UTC-Р±Р°РєРµС‚Рµ
        (РЅР°РїСЂРёРјРµСЂ, СЂР°Р·СЉРµС…Р°РІС€РёРµСЃСЏ РїРѕ **legacy** `source|asset|op`). РџРѕРІС‚РѕСЂРЅС‹Р№ Р·Р°РїСѓСЃРє вЂ” no-op.
        """
        bs = bucket_sec if bucket_sec >= 1 else 300
        from takt.domain.services.case_merge import merge_open_cases_group_v070, migration_group_key

        cases = self.list_all()
        open_ = [c for c in cases if c.status in (CaseStatus.NEW, CaseStatus.TRIAGE)]
        groups: dict[tuple[str, str, int], list[Case]] = {}
        for c in open_:
            groups.setdefault(migration_group_key(c, bs), []).append(c)
        merged_groups = 0
        with self.transaction():
            for g in groups.values():
                if len(g) < 2:
                    continue
                surv, dead = merge_open_cases_group_v070(g, bucket_sec=bs)
                self.save(surv)
                self.delete_cases_by_id(dead)
                merged_groups += 1
        return merged_groups

    def get(self, case_id: str) -> Case | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            )
            row = cur.fetchone()
            return None if row is None else _row_to_case(row)

    def list_all(self) -> list[Case]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
            return [_row_to_case(r) for r in cur.fetchall()]

    def idempotency_delete_expired(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock:
            self._conn.execute("DELETE FROM idempotency_keys WHERE expires_at < ?", (now,))

    def idempotency_get(self, key: str) -> tuple[str, str] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT body_hash, response_json, expires_at FROM idempotency_keys WHERE idem_key = ?",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            if str(row[2]) < now:
                self._conn.execute("DELETE FROM idempotency_keys WHERE idem_key = ?", (key,))
                return None
            return str(row[0]), str(row[1])

    def idempotency_put(self, key: str, body_hash: str, response_json: str, expires_at_iso: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO idempotency_keys (idem_key, body_hash, response_json, expires_at)
                VALUES (?,?,?,?)
                ON CONFLICT(idem_key) DO UPDATE SET
                  body_hash = excluded.body_hash,
                  response_json = excluded.response_json,
                  expires_at = excluded.expires_at
                """,
                (key, body_hash, response_json, expires_at_iso),
            )

    def find_open_by_fingerprint(self, fingerprint: str) -> Case | None:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM cases
                WHERE burst_fingerprint = ?
                  AND status IN (?, ?)
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (fingerprint, CaseStatus.NEW.value, CaseStatus.TRIAGE.value),
            )
            row = cur.fetchone()
            return None if row is None else _row_to_case(row)

    def verify_audit_ledger(self, case_id: str) -> dict[str, object]:
        with self._lock:
            return verify_case_audit_ledger(self._conn, case_id)

    def record_operation_event(
        self,
        *,
        operation_type: str,
        entity_id: str,
        actor: str,
        payload_json: str,
        created_at: str,
    ) -> None:
        with self._lock:
            _record_operation_event(
                self._conn,
                operation_type=operation_type,
                entity_id=entity_id,
                actor=actor,
                payload_json=payload_json,
                created_at=created_at,
            )

    def verify_operation_ledger(self, stream_key: str = '') -> dict[str, object]:
        with self._lock:
            return _verify_operation_ledger(self._conn, stream_key)


