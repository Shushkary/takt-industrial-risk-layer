from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path

from takt.domain.entities.case import (
    Case,
    CaseStatus,
)
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.infrastructure.stores.sqlite_audit_engagement_store import SqliteAuditEngagementStore  # noqa: F401
from takt.infrastructure.stores.sqlite_audit_ledger import (
    append_case_audit_ledger_line,
    verify_case_audit_ledger,
)
from takt.infrastructure.stores.sqlite_audit_ledger import (
    record_operation_event as _record_operation_event,
)
from takt.infrastructure.stores.sqlite_audit_ledger import (
    verify_operation_ledger as _verify_operation_ledger,
)
from takt.infrastructure.stores.sqlite_case_mapper import (
    CASE_UPSERT_SQL,
    _row_to_case,
    case_upsert_params,
)
from takt.infrastructure.stores.sqlite_connection import _now_utc as _now_utc
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
)
from takt.infrastructure.stores.sqlite_connection import (
    configure_sqlite_connection as _configure_sqlite_connection,
)
from takt.infrastructure.stores.sqlite_connection import dt_to_sql as _dt_to_sql
from takt.infrastructure.stores.sqlite_connection import sqlite_busy_timeout_ms_from_env  # noqa: F401
from takt.infrastructure.stores.sqlite_correlation_keys import reindex_correlation_keys as _reindex_correlation_keys
from takt.infrastructure.stores.sqlite_expected_behavior import SqliteExpectedBehavior  # noqa: F401
from takt.infrastructure.stores.sqlite_idempotency import (
    idempotency_delete_expired as _idempotency_delete_expired,
)
from takt.infrastructure.stores.sqlite_idempotency import (
    idempotency_get as _idempotency_get,
)
from takt.infrastructure.stores.sqlite_idempotency import (
    idempotency_put as _idempotency_put,
)
from takt.infrastructure.stores.sqlite_schema import ensure_case_schema

# Версия схемы БД кейсов (метаданные `app_metadata`); при миграциях увеличивать.
CURRENT_DB_SCHEMA_VERSION = 9


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
            self._conn.execute(CASE_UPSERT_SQL, case_upsert_params(case))
            _reindex_correlation_keys(self._conn, case, existing)
            old_audit = existing.audit_log if existing is not None else []
            if len(case.audit_log) > len(old_audit):
                for line in case.audit_log[len(old_audit) :]:
                    created_at = line.split(" | ", 1)[0] if " | " in line else _dt_to_sql(_now_utc())
                    self._append_audit_ledger_line(case.case_id, line, created_at)

    def save_all(self, cases: Sequence[Case]) -> None:
        """Пакетная запись в одной транзакции: либо записаны все дела, либо ни одного.

        Нужна ручной корректировке состава: она меняет два дела сразу, и сбой между записями
        оставлял бы источник закрытым, а цель — без его событий.
        """
        with self.transaction():
            for case in cases:
                self.save(case)

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
        with self._lock:
            _idempotency_delete_expired(self._conn)

    def idempotency_get(self, key: str) -> tuple[str, str] | None:
        with self._lock:
            return _idempotency_get(self._conn, key)

    def idempotency_put(self, key: str, body_hash: str, response_json: str, expires_at_iso: str) -> None:
        with self._lock:
            _idempotency_put(self._conn, key, body_hash, response_json, expires_at_iso)

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

    def find_open_by_fingerprints(self, fingerprints: list[str]) -> tuple[Case, str] | None:
        with self._lock:
            for fingerprint in fingerprints:
                row = self._conn.execute(
                    """
                    SELECT c.* FROM case_correlation_keys k
                    JOIN cases c ON c.case_id = k.case_id
                    WHERE k.fingerprint = ? AND c.status IN (?, ?)
                    ORDER BY c.created_at DESC LIMIT 1
                    """,
                    (fingerprint, CaseStatus.NEW.value, CaseStatus.TRIAGE.value),
                ).fetchone()
                if row is not None:
                    return _row_to_case(row), fingerprint
        return None

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


