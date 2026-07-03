from __future__ import annotations

import json
import sqlite3
import threading
from copy import deepcopy
from pathlib import Path

from takt.domain.entities.audit_engagement import AuditEngagement
from takt.domain.ports.audit_engagement_repository import AuditEngagementRepositoryPort
from takt.infrastructure.stores.sqlite_audit_engagement_mapper import (
    _row_to_audit_engagement,
    _serialize_audit_final_report,
    _serialize_audit_stages,
)
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
    configure_sqlite_connection as _configure_sqlite_connection,
    dt_to_sql as _dt_to_sql,
)
from takt.infrastructure.stores.sqlite_schema import ensure_audit_engagement_schema


class SqliteAuditEngagementStore(AuditEngagementRepositoryPort):
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

    def _ensure_schema(self) -> None:
        ensure_audit_engagement_schema(self._conn)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    def save(self, engagement: AuditEngagement) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_engagements (
                  engagement_id, created_at, status, customer, scope,
                  case_ids, nda_signed, evidence_intake_checklist, stages, findings, final_report_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(engagement_id) DO UPDATE SET
                  created_at = excluded.created_at,
                  status = excluded.status,
                  customer = excluded.customer,
                  scope = excluded.scope,
                  case_ids = excluded.case_ids,
                  nda_signed = excluded.nda_signed,
                  evidence_intake_checklist = excluded.evidence_intake_checklist,
                  stages = excluded.stages,
                  findings = excluded.findings,
                  final_report_json = excluded.final_report_json
                """,
                (
                    engagement.engagement_id,
                    _dt_to_sql(engagement.created_at),
                    engagement.status,
                    engagement.customer,
                    engagement.scope,
                    json.dumps(engagement.case_ids, ensure_ascii=False),
                    1 if engagement.nda_signed else 0,
                    json.dumps(engagement.evidence_intake_checklist, ensure_ascii=False),
                    _serialize_audit_stages(engagement.stages),
                    json.dumps(engagement.findings, ensure_ascii=False),
                    _serialize_audit_final_report(engagement.final_report),
                ),
            )

    def get(self, engagement_id: str) -> AuditEngagement | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            return None if row is None else deepcopy(_row_to_audit_engagement(row))

    def list_all(self) -> list[AuditEngagement]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_engagements ORDER BY created_at DESC",
            ).fetchall()
            return [deepcopy(_row_to_audit_engagement(row)) for row in rows]
