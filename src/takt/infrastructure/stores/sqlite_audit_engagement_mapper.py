from __future__ import annotations

import json
import sqlite3

from takt.domain.entities.audit_engagement import AuditEngagement, AuditFinalReport, AuditStage
from takt.infrastructure.stores.sqlite_connection import dt_from_sql as _dt_from_sql
from takt.infrastructure.stores.sqlite_connection import dt_to_sql as _dt_to_sql


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


