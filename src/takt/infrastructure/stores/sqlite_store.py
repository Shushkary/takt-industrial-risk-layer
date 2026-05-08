from __future__ import annotations

import json
import os
import sqlite3
import threading
import hashlib
from copy import deepcopy
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from takt.domain.entities.audit_engagement import AuditEngagement, AuditFinalReport, AuditStage
from takt.domain.entities.case import (
    Case,
    CaseDecisionRecord,
    CaseStatus,
    InvariantHitRecord,
    ManualPermit,
    Observation,
    RawEvidenceRef,
    RemediationAttempt,
)
from takt.domain.ports.audit_engagement_repository import AuditEngagementRepositoryPort
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort

# Версия схемы БД кейсов (метаданные `app_metadata`); при миграциях увеличивать.
CURRENT_DB_SCHEMA_VERSION = 6


def sqlite_busy_timeout_ms_from_env() -> int:
    """**TAKT_SQLITE_BUSY_TIMEOUT_MS**: **PRAGMA busy_timeout** в мс для соединений SQLite (по умолчанию **5000**; вне **100**–**300000** или невалидное значение — **5000**)."""
    raw = os.environ.get("TAKT_SQLITE_BUSY_TIMEOUT_MS", "").strip()
    if not raw:
        return 5000
    try:
        v = int(raw, 10)
    except ValueError:
        return 5000
    if v < 100 or v > 300_000:
        return 5000
    return v


def _configure_sqlite_connection(conn: sqlite3.Connection) -> None:
    ms = sqlite_busy_timeout_ms_from_env()
    conn.execute("PRAGMA busy_timeout=%d" % int(ms))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")


def _checkpoint_wal_best_effort(conn: sqlite3.Connection) -> None:
    """Перед **`close()`**: сброс WAL на диск (лучше при **SIGTERM** / остановке контейнера)."""
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass


def _dt_to_sql(dt: datetime) -> str:
    if dt.tzinfo is None:
        return dt.isoformat(timespec="seconds")
    return dt.astimezone().isoformat(timespec="seconds")


def _dt_from_sql(raw: str) -> datetime:
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.execute("PRAGMA table_info(%s)" % table)
    return {str(row[1]) for row in cur.fetchall()}


def _serialize_observations(obs: list[Observation]) -> str:
    payload = [{"source": o.source, "ingest_trust": o.ingest_trust, "event_ids": list(o.event_ids)} for o in obs]
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_observations(raw: str) -> list[Observation]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[Observation] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append(
            Observation(
                source=str(item.get("source", "")),
                ingest_trust=float(item.get("ingest_trust", 1.0)),
                event_ids=list(item.get("event_ids") or []),
            )
        )
    return out


def _serialize_hit_records(records: list[InvariantHitRecord]) -> str:
    payload = []
    for r in records:
        payload.append(
            {
                "invariant_id": r.invariant_id,
                "event_ref": r.event_ref,
                "ts": _dt_to_sql(r.ts),
                "score_contribution": r.score_contribution,
                "dq_score": r.dq_score,
                "dq_partial": r.dq_partial,
                "dq_reasons": list(r.dq_reasons),
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_hit_records(raw: str) -> list[InvariantHitRecord]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[InvariantHitRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("ts", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            InvariantHitRecord(
                invariant_id=str(item.get("invariant_id", "")),
                event_ref=str(item.get("event_ref", "")),
                ts=ts_parsed,
                score_contribution=float(item.get("score_contribution", 0.0)),
                dq_score=float(item.get("dq_score", 1.0)),
                dq_partial=bool(item.get("dq_partial", False)),
                dq_reasons=list(item.get("dq_reasons") or []),
            )
        )
    return out


def _serialize_manual_permits(records: list[ManualPermit]) -> str:
    payload = []
    for p in records:
        payload.append(
            {
                "permit_id": p.permit_id,
                "case_id": p.case_id,
                "work_order_number": p.work_order_number,
                "actor": p.actor,
                "created_at": _dt_to_sql(p.created_at),
                "asset_id": p.asset_id,
                "operation": p.operation,
                "verdict": p.verdict,
                "confidence": p.confidence,
                "rationale": p.rationale,
                "counterfactual": p.counterfactual,
                "note": p.note,
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_manual_permits(raw: str) -> list[ManualPermit]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[ManualPermit] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("created_at", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            ManualPermit(
                permit_id=str(item.get("permit_id", "")),
                case_id=str(item.get("case_id", "")),
                work_order_number=str(item.get("work_order_number", "")),
                actor=str(item.get("actor", "")),
                created_at=ts_parsed,
                asset_id=str(item.get("asset_id", "")),
                operation=str(item.get("operation", "")),
                verdict=str(item.get("verdict", "")),
                confidence=float(item.get("confidence", 0.5)),
                rationale=str(item.get("rationale", "")),
                counterfactual=str(item.get("counterfactual", "")),
                note=str(item.get("note", "")),
            )
        )
    return out


def _serialize_decision_records(records: list[CaseDecisionRecord]) -> str:
    payload = []
    for r in records:
        payload.append(
            {
                "ts": _dt_to_sql(r.ts),
                "actor": r.actor,
                "prev_status": r.prev_status,
                "next_status": r.next_status,
                "reason": r.reason,
                "request_id": r.request_id,
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_decision_records(raw: str) -> list[CaseDecisionRecord]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[CaseDecisionRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("ts", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            CaseDecisionRecord(
                ts=ts_parsed,
                actor=str(item.get("actor", "")),
                prev_status=str(item.get("prev_status", "")),
                next_status=str(item.get("next_status", "")),
                reason=str(item.get("reason", "")),
                request_id=str(item.get("request_id", "")),
            )
        )
    return out


def _serialize_remediation_attempts(records: list[RemediationAttempt]) -> str:
    payload = []
    for a in records:
        payload.append(
            {
                "attempt_id": a.attempt_id,
                "case_id": a.case_id,
                "kind": a.kind,
                "status": a.status,
                "actor": a.actor,
                "created_at": _dt_to_sql(a.created_at),
                "action": a.action,
                "result": a.result,
                "readiness_before": a.readiness_before,
                "readiness_after": a.readiness_after,
                "note": a.note,
                "request_id": a.request_id,
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_remediation_attempts(raw: str) -> list[RemediationAttempt]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[RemediationAttempt] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("created_at", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            RemediationAttempt(
                attempt_id=str(item.get("attempt_id", "")),
                case_id=str(item.get("case_id", "")),
                kind=str(item.get("kind", "")),
                status=str(item.get("status", "")),
                actor=str(item.get("actor", "")),
                created_at=ts_parsed,
                action=str(item.get("action", "")),
                result=str(item.get("result", "")),
                readiness_before=item.get("readiness_before"),
                readiness_after=item.get("readiness_after"),
                note=str(item.get("note", "")),
                request_id=str(item.get("request_id", "")),
            )
        )
    return out


def _serialize_raw_evidence_refs(records: list[RawEvidenceRef]) -> str:
    payload = []
    for r in records:
        payload.append(
            {
                "evidence_id": r.evidence_id,
                "source": r.source,
                "media_type": r.media_type,
                "captured_at": _dt_to_sql(r.captured_at),
                "payload_b64": r.payload_b64,
                "sha256": r.sha256,
                "size_bytes": r.size_bytes,
                "event_id": r.event_id,
                "note": r.note,
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_raw_evidence_refs(raw: str) -> list[RawEvidenceRef]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[RawEvidenceRef] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("captured_at", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            RawEvidenceRef(
                evidence_id=str(item.get("evidence_id", "")),
                source=str(item.get("source", "")),
                media_type=str(item.get("media_type", "application/octet-stream")),
                captured_at=ts_parsed,
                payload_b64=str(item.get("payload_b64", "")),
                sha256=str(item.get("sha256", "")),
                size_bytes=int(item.get("size_bytes", 0)),
                event_id=str(item.get("event_id", "")),
                note=str(item.get("note", "")),
            )
        )
    return out


def _row_to_case(row: sqlite3.Row) -> Case:
    observations_raw = str(row["observations"] if "observations" in row.keys() else "[]")
    hits_raw = str(row["invariant_hit_records"] if "invariant_hit_records" in row.keys() else "[]")
    permits_raw = str(row["manual_permits"] if "manual_permits" in row.keys() else "[]")
    decisions_raw = str(row["decision_records"] if "decision_records" in row.keys() else "[]")
    remediation_raw = str(row["remediation_attempts"] if "remediation_attempts" in row.keys() else "[]")
    raw_evidence_refs = str(row["raw_evidence_refs"] if "raw_evidence_refs" in row.keys() else "[]")
    return Case(
        case_id=str(row["case_id"]),
        status=CaseStatus(str(row["status"])),
        title=str(row["title"]),
        risk_class=str(row["risk_class"]),
        risk_score=float(row["risk_score"]),
        created_at=_dt_from_sql(str(row["created_at"])),
        normalized_event_ids=list(json.loads(row["normalized_event_ids"] or "[]")),
        xai_summary=str(row["xai_summary"] or ""),
        audit_log=list(json.loads(row["audit_log"] or "[]")),
        burst_fingerprint=str(row["burst_fingerprint"] or ""),
        primary_asset_id=str(row["primary_asset_id"] or ""),
        trigger_operation=str(row["trigger_operation"] or ""),
        invariant_hits=list(json.loads(row["invariant_hits"] or "[]")),
        invariant_hit_records=_deserialize_hit_records(hits_raw),
        observations=_deserialize_observations(observations_raw),
        manual_permits=_deserialize_manual_permits(permits_raw),
        decision_records=_deserialize_decision_records(decisions_raw),
        remediation_attempts=_deserialize_remediation_attempts(remediation_raw),
        raw_evidence_refs=_deserialize_raw_evidence_refs(raw_evidence_refs),
        dq_score=float(row["dq_score"]),
        dq_partial=bool(row["dq_partial"]),
        dq_reasons=list(json.loads(row["dq_reasons"] or "[]")),
        last_event_source=str(row["last_event_source"] or ""),
        pdf_last_sha256=str(row["pdf_last_sha256"] if "pdf_last_sha256" in row.keys() else ""),
        pdf_last_generated_at=str(row["pdf_last_generated_at"] if "pdf_last_generated_at" in row.keys() else ""),
    )


class SqliteCaseStore(CaseRepositoryPort):
    """Персистентное хранилище кейсов (один файл SQLite на процесс API)."""

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
        """Путь к файлу БД кейсов (для **security_log** и резервного копирования)."""
        return self._path

    def _ensure_schema(self) -> None:
        self._conn.executescript(
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
        cols = _table_columns(self._conn, "cases")
        if "observations" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN observations TEXT NOT NULL DEFAULT '[]'")
        if "invariant_hit_records" not in cols:
            self._conn.execute(
                "ALTER TABLE cases ADD COLUMN invariant_hit_records TEXT NOT NULL DEFAULT '[]'"
            )
        if "manual_permits" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN manual_permits TEXT NOT NULL DEFAULT '[]'")
        if "decision_records" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN decision_records TEXT NOT NULL DEFAULT '[]'")
        if "remediation_attempts" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN remediation_attempts TEXT NOT NULL DEFAULT '[]'")
        if "pdf_last_sha256" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN pdf_last_sha256 TEXT NOT NULL DEFAULT ''")
        if "pdf_last_generated_at" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN pdf_last_generated_at TEXT NOT NULL DEFAULT ''")
        if "raw_evidence_refs" not in cols:
            self._conn.execute("ALTER TABLE cases ADD COLUMN raw_evidence_refs TEXT NOT NULL DEFAULT '[]'")
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM app_metadata WHERE key = 'schema_version' LIMIT 1",
            )
            row = cur.fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO app_metadata (key, value)
                    VALUES ('schema_version', ?)
                    """,
                    (str(CURRENT_DB_SCHEMA_VERSION),),
                )
            else:
                try:
                    ver = int(str(row[0]))
                except ValueError:
                    ver = 1
                if ver < CURRENT_DB_SCHEMA_VERSION:
                    self._conn.execute(
                        """
                        UPDATE app_metadata SET value = ?
                        WHERE key = 'schema_version'
                        """,
                        (str(CURRENT_DB_SCHEMA_VERSION),),
                    )

    def _append_audit_ledger_line(self, case_id: str, audit_line: str, created_at: str) -> None:
        row = self._conn.execute(
            "SELECT chain_sha256 FROM case_audit_ledger WHERE case_id = ? ORDER BY seq DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        prev_chain = str(row[0]) if row is not None else ""
        line_sha = hashlib.sha256(audit_line.encode("utf-8")).hexdigest()
        chain_sha = hashlib.sha256(
            f"{prev_chain}:{case_id}:{line_sha}:{len(audit_line)}".encode("utf-8")
        ).hexdigest()
        self._conn.execute(
            """
            INSERT INTO case_audit_ledger (
              case_id, audit_line, line_sha256, prev_chain_sha256, chain_sha256, created_at
            ) VALUES (?,?,?,?,?,?)
            """,
            (case_id, audit_line, line_sha, prev_chain, chain_sha, created_at),
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
        """Явная транзакция: COMMIT при успехе, ROLLBACK при исключении (для пакетного импорта)."""
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
                  primary_asset_id, trigger_operation, invariant_hits,
                  observations, invariant_hit_records, manual_permits, decision_records, remediation_attempts,
                  dq_score, dq_partial, dq_reasons, last_event_source, raw_evidence_refs, pdf_last_sha256, pdf_last_generated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                  invariant_hits = excluded.invariant_hits,
                  observations = excluded.observations,
                  invariant_hit_records = excluded.invariant_hit_records,
                  manual_permits = excluded.manual_permits,
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
                    json.dumps(case.invariant_hits, ensure_ascii=False),
                    _serialize_observations(case.observations),
                    _serialize_hit_records(case.invariant_hit_records),
                    _serialize_manual_permits(case.manual_permits),
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
        """Удаление карточек по **case_id** (скрипты миграции; вне порта репозитория)."""
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
        Идемпотентно сворачивает открытые кейсы с одной парой (актив, операция) в одном UTC-бакете
        (например, разъехавшиеся по **legacy** `source|asset|op`). Повторный запуск — no-op.
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
            rows = self._conn.execute(
                """
                SELECT seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256
                FROM case_audit_ledger
                WHERE case_id = ?
                ORDER BY seq ASC
                """,
                (case_id,),
            ).fetchall()
        prev_chain = ""
        checked = 0
        for row in rows:
            _seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256 = row
            audit_line = str(audit_line)
            expected_line = hashlib.sha256(audit_line.encode("utf-8")).hexdigest()
            if expected_line != str(line_sha256):
                return {"ok": False, "checked_entries": checked, "issue": "line_sha_mismatch"}
            if str(prev_chain_sha256) != prev_chain:
                return {"ok": False, "checked_entries": checked, "issue": "prev_chain_mismatch"}
            expected_chain = hashlib.sha256(
                f"{prev_chain}:{case_id}:{expected_line}:{len(audit_line)}".encode("utf-8")
            ).hexdigest()
            if expected_chain != str(chain_sha256):
                return {"ok": False, "checked_entries": checked, "issue": "chain_mismatch"}
            prev_chain = expected_chain
            checked += 1
        return {"ok": True, "checked_entries": checked, "issue": ""}

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
            op = operation_type.strip()
            eid = entity_id.strip()
            if not op or not eid:
                raise ValueError("operation_type and entity_id are required")
            stream_key = f"{op}:{eid}"
            row = self._conn.execute(
                "SELECT chain_sha256 FROM operation_audit_ledger WHERE stream_key = ? ORDER BY seq DESC LIMIT 1",
                (stream_key,),
            ).fetchone()
            prev_chain = str(row[0]) if row is not None else ""
            payload_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            chain_sha = hashlib.sha256(
                f"{prev_chain}:{stream_key}:{payload_sha}:{len(payload_json)}".encode("utf-8")
            ).hexdigest()
            self._conn.execute(
                """
                INSERT INTO operation_audit_ledger (
                  stream_key, operation_type, entity_id, actor, payload_json,
                  payload_sha256, prev_chain_sha256, chain_sha256, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (stream_key, op, eid, actor.strip(), payload_json, payload_sha, prev_chain, chain_sha, created_at),
            )

    def verify_operation_ledger(self, stream_key: str = "") -> dict[str, object]:
        where = ""
        params: tuple[str, ...] = ()
        if stream_key.strip():
            where = "WHERE stream_key = ?"
            params = (stream_key.strip(),)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT stream_key, payload_json, payload_sha256, prev_chain_sha256, chain_sha256
                FROM operation_audit_ledger
                {where}
                ORDER BY stream_key ASC, seq ASC
                """,
                params,
            ).fetchall()
        checked = 0
        active_stream = ""
        prev_chain = ""
        for row in rows:
            row_stream, payload_json, payload_sha256, prev_chain_sha256, chain_sha256 = row
            row_stream = str(row_stream)
            payload_json = str(payload_json)
            if row_stream != active_stream:
                active_stream = row_stream
                prev_chain = ""
            expected_payload = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if expected_payload != str(payload_sha256):
                return {"ok": False, "checked_entries": checked, "issue": "payload_sha_mismatch"}
            if str(prev_chain_sha256) != prev_chain:
                return {"ok": False, "checked_entries": checked, "issue": "prev_chain_mismatch"}
            expected_chain = hashlib.sha256(
                f"{prev_chain}:{row_stream}:{expected_payload}:{len(payload_json)}".encode("utf-8")
            ).hexdigest()
            if expected_chain != str(chain_sha256):
                return {"ok": False, "checked_entries": checked, "issue": "chain_mismatch"}
            prev_chain = expected_chain
            checked += 1
        return {"ok": True, "checked_entries": checked, "issue": ""}


class SqliteExpectedBehavior(ExpectedBehaviorPort):
    """Пары (актив, операция) для снижения user-риска после EXPECTED_BEHAVIOR; тот же файл, что и кейсы."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._closed = False
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        _configure_sqlite_connection(self._conn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS expected_behavior (
              asset_id_norm TEXT NOT NULL,
              operation_upper TEXT NOT NULL,
              PRIMARY KEY (asset_id_norm, operation_upper)
            );
            """
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    def mark_expected(self, asset_id: str, operation: str) -> None:
        aid = (asset_id or "").lower().strip()
        op = (operation or "").upper().strip()
        if not aid or not op:
            return
        with self._lock:
            if self._closed:
                raise RuntimeError("SqliteExpectedBehavior connection is closed")
            self._conn.execute(
                """
                INSERT OR REPLACE INTO expected_behavior (asset_id_norm, operation_upper)
                VALUES (?, ?)
                """,
                (aid, op),
            )

    def is_expected(self, asset_id: str, operation: str) -> bool:
        aid = (asset_id or "").lower().strip()
        op = (operation or "").upper().strip()
        if not aid or not op:
            return False
        with self._lock:
            if self._closed:
                raise RuntimeError("SqliteExpectedBehavior connection is closed")
            cur = self._conn.execute(
                """
                SELECT 1 FROM expected_behavior
                WHERE asset_id_norm = ? AND operation_upper = ?
                LIMIT 1
                """,
                (aid, op),
            )
            return cur.fetchone() is not None


def _serialize_audit_stages(stages: list[AuditStage]) -> str:
    return json.dumps(
        [
            {
                "code": s.code,
                "title": s.title,
                "day_range": s.day_range,
                "status": s.status,
                "started_at": _dt_to_sql(s.started_at) if s.started_at is not None else "",
                "completed_at": _dt_to_sql(s.completed_at) if s.completed_at is not None else "",
                "note": s.note,
            }
            for s in stages
        ],
        ensure_ascii=False,
    )


def _deserialize_audit_stages(raw: str) -> list[AuditStage]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[AuditStage] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        started_raw = str(item.get("started_at", ""))
        completed_raw = str(item.get("completed_at", ""))
        out.append(
            AuditStage(
                code=str(item.get("code", "")),
                title=str(item.get("title", "")),
                day_range=str(item.get("day_range", "")),
                status=str(item.get("status", "pending")),
                started_at=_dt_from_sql(started_raw) if started_raw else None,
                completed_at=_dt_from_sql(completed_raw) if completed_raw else None,
                note=str(item.get("note", "")),
            )
        )
    return out


def _serialize_audit_final_report(report: AuditFinalReport | None) -> str:
    if report is None:
        return ""
    return json.dumps(
        {
            "title": report.title,
            "uri": report.uri,
            "summary": report.summary,
            "generated_at": _dt_to_sql(report.generated_at),
        },
        ensure_ascii=False,
    )


def _deserialize_audit_final_report(raw: str) -> AuditFinalReport | None:
    if not raw:
        return None
    item = json.loads(raw)
    if not isinstance(item, dict):
        return None
    return AuditFinalReport(
        title=str(item.get("title", "")),
        uri=str(item.get("uri", "")),
        summary=str(item.get("summary", "")),
        generated_at=_dt_from_sql(str(item.get("generated_at", ""))),
    )


def _row_to_audit_engagement(row: sqlite3.Row) -> AuditEngagement:
    return AuditEngagement(
        engagement_id=str(row["engagement_id"]),
        created_at=_dt_from_sql(str(row["created_at"])),
        status=str(row["status"]),
        customer=str(row["customer"]),
        scope=str(row["scope"]),
        case_ids=list(json.loads(str(row["case_ids"] or "[]"))),
        nda_signed=bool(row["nda_signed"]),
        evidence_intake_checklist=list(json.loads(str(row["evidence_intake_checklist"] or "[]"))),
        stages=_deserialize_audit_stages(str(row["stages"] or "[]")),
        findings=list(json.loads(str(row["findings"] or "[]"))),
        final_report=_deserialize_audit_final_report(str(row["final_report_json"] or "")),
    )


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
        self._conn.executescript(
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
