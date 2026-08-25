from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from takt.domain.entities.case import (
    Case,
    CaseArtifact,
    CaseDecisionRecord,
    CaseStatus,
    CorrelationEvidence,
    Finding,
    FormalVerdictRecord,
    InvariantHitRecord,
    ManualPermit,
    Observation,
    RawEvidenceRef,
    RemediationAttempt,
)
from takt.infrastructure.stores.sqlite_connection import dt_from_sql as _dt_from_sql
from takt.infrastructure.stores.sqlite_connection import dt_to_sql as _dt_to_sql


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
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
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
                "action_class": p.action_class,
                "verdict": p.verdict,
                "confidence": p.confidence,
                "rationale": p.rationale,
                "counterfactual": p.counterfactual,
                "counterfactual_struct": p.counterfactual_struct,
                "executor": p.executor,
                "approver": p.approver,
                "valid_from": p.valid_from,
                "valid_to": p.valid_to,
                "document_status": p.document_status,
                "restrictions": p.restrictions,
                "organizational_context_sha256": p.organizational_context_sha256,
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
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
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
                action_class=str(item.get("action_class", "")),
                verdict=str(item.get("verdict", "")),
                confidence=float(item.get("confidence", 0.5)),
                rationale=str(item.get("rationale", "")),
                counterfactual=str(item.get("counterfactual", "")),
                counterfactual_struct=item.get("counterfactual_struct") or {},
                executor=str(item.get("executor", "")),
                approver=str(item.get("approver", "")),
                valid_from=str(item.get("valid_from", "")),
                valid_to=str(item.get("valid_to", "")),
                document_status=str(item.get("document_status", "")),
                restrictions=str(item.get("restrictions", "")),
                organizational_context_sha256=str(item.get("organizational_context_sha256", "")),
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
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
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


def _serialize_formal_verdict_records(records: list[FormalVerdictRecord]) -> str:
    payload = []
    for r in records:
        payload.append(
            {
                "ts": _dt_to_sql(r.ts),
                "actor": r.actor,
                "prev": r.prev,
                "next": r.next,
                "score": r.score,
                "source": r.source,
                "permit_id": r.permit_id,
                "reason": r.reason,
            }
        )
    return json.dumps(payload, ensure_ascii=False)


def _deserialize_formal_verdict_records(raw: str) -> list[FormalVerdictRecord]:
    if not raw or raw == "[]":
        return []
    data = json.loads(raw)
    out: list[FormalVerdictRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ts_raw = str(item.get("ts", ""))
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
        if ts_raw:
            ts_parsed = _dt_from_sql(ts_raw)
        out.append(
            FormalVerdictRecord(
                ts=ts_parsed,
                actor=str(item.get("actor", "")),
                prev=str(item.get("prev", "")),
                next=str(item.get("next", "")),
                score=float(item.get("score", 0.0)),
                source=str(item.get("source", "")),
                permit_id=str(item.get("permit_id", "")),
                reason=str(item.get("reason", "")),
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
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
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
        ts_parsed = datetime(1970, 1, 1, tzinfo=UTC)
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


def _column(row: sqlite3.Row, name: str, default: str) -> str:
    """Значение колонки, если она есть в выборке; иначе `default`.

    Колонки добавлялись к схеме по ходу развития, и дела, записанные раньше, их не содержат —
    отсутствие колонки не ошибка, а более старая запись.

    Проверка идёт через `keys()` намеренно. `sqlite3.Row` — не словарь: оператор `in` у него
    ищет среди **значений**, а не среди имён колонок, поэтому подсказка ruff `name in row`
    (SIM118) поменяла бы смысл проверки. Она стала бы ложной для каждой колонки, и загрузка
    дела молча теряла бы наблюдения, срабатывания инвариантов, разрешения и решения.
    """
    return row[name] if name in row.keys() else default  # noqa: SIM118


def _row_to_case(row: sqlite3.Row) -> Case:
    observations_raw = str(_column(row, "observations", "[]"))
    hits_raw = str(_column(row, "invariant_hit_records", "[]"))
    permits_raw = str(_column(row, "manual_permits", "[]"))
    verdict_records_raw = str(_column(row, "formal_verdict_records", "[]"))
    decisions_raw = str(_column(row, "decision_records", "[]"))
    remediation_raw = str(_column(row, "remediation_attempts", "[]"))
    raw_evidence_refs = str(_column(row, "raw_evidence_refs", "[]"))
    correlation_evidence_raw = json.loads(
        _column(row, "correlation_evidence", "[]")
    )
    artifacts_raw = json.loads(_column(row, "artifacts", "[]"))
    findings_raw = json.loads(_column(row, "findings", "[]"))
    artifacts = [
        CaseArtifact(
            type=str(item.get("type", "")), value=str(item.get("value", "")),
            host_id=str(item.get("host_id", "")), verification_status=str(item.get("verification_status", "unverified")),
            source=str(item.get("source", "manual")), added_by=str(item.get("added_by", "")),
            created_at=_dt_from_sql(item["created_at"]) if item.get("created_at") else None,
        )
        for item in artifacts_raw if isinstance(item, dict)
    ]
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
        correlation_fingerprints=list(
            json.loads(_column(row, "correlation_fingerprints", "[]"))
        ),
        correlation_evidence=[
            CorrelationEvidence(
                event_id=str(item.get("event_id", "")),
                fingerprint=str(item.get("fingerprint", "")),
                rule=str(item.get("rule", "")),
                fields=list(item.get("fields", [])),
                manual=bool(item.get("manual", False)),
                reason=str(item.get("reason", "")),
                request_id=str(item.get("request_id", "")),
            )
            for item in correlation_evidence_raw
            if isinstance(item, dict)
        ],
        related_cases=list(json.loads(_column(row, "related_cases", "[]"))),
        artifacts=artifacts,
        findings=[
            Finding(
                finding_id=str(item.get("finding_id", "")), text=str(item.get("text", "")),
                author=str(item.get("author", "")), created_at=_dt_from_sql(str(item["created_at"])),
                event_ids=list(item.get("event_ids", [])),
                artifacts=[
                    CaseArtifact(
                        type=str(artifact.get("type", "")), value=str(artifact.get("value", "")),
                        host_id=str(artifact.get("host_id", "")),
                        verification_status=str(artifact.get("verification_status", "unverified")),
                        source=str(artifact.get("source", "manual")), added_by=str(artifact.get("added_by", "")),
                        created_at=_dt_from_sql(artifact["created_at"]) if artifact.get("created_at") else None,
                    ) for artifact in item.get("artifacts", []) if isinstance(artifact, dict)
                ],
            ) for item in findings_raw if isinstance(item, dict)
        ],
        primary_asset_id=str(row["primary_asset_id"] or ""),
        trigger_operation=str(row["trigger_operation"] or ""),
        operator_id=str(_column(row, "operator_id", "")),
        invariant_hits=list(json.loads(row["invariant_hits"] or "[]")),
        invariant_hit_records=_deserialize_hit_records(hits_raw),
        observations=_deserialize_observations(observations_raw),
        manual_permits=_deserialize_manual_permits(permits_raw),
        formal_verdict_records=_deserialize_formal_verdict_records(verdict_records_raw),
        decision_records=_deserialize_decision_records(decisions_raw),
        remediation_attempts=_deserialize_remediation_attempts(remediation_raw),
        raw_evidence_refs=_deserialize_raw_evidence_refs(raw_evidence_refs),
        dq_score=float(row["dq_score"]),
        dq_partial=bool(row["dq_partial"]),
        dq_reasons=list(json.loads(row["dq_reasons"] or "[]")),
        # Колонка появилась позже: у дел, записанных до неё, векторов нет — это не ошибка,
        # сборка в таком случае работает как раньше.
        risk_vectors=dict(json.loads(_column(row, "risk_vectors", "") or "{}")),
        last_event_source=str(row["last_event_source"] or ""),
        pdf_last_sha256=str(_column(row, "pdf_last_sha256", "")),
        pdf_last_generated_at=str(_column(row, "pdf_last_generated_at", "")),
    )
