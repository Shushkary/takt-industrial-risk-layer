from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from takt.domain.entities.case import Case
from takt.domain.entities.compliance import CaseEvidenceChecklist, ComplianceDataQualityReport, ForensicReadinessReport
from takt.domain.entities.forensic import (
    ForensicBundle,
    ForensicBundleVerification,
    ForensicBundleVerificationIssue,
    ForensicEvidenceItem,
)
from takt.domain.services.forensic_verdict import case_forensic_verdict
from takt.infrastructure.export.gossopka import case_to_gossopka_card
from takt.infrastructure.export.siem_webhook import case_to_siem_payload
from takt.infrastructure.security.root_hash_signature import RootHashSignatureAdapter

_ZIP_TS = (1980, 1, 1, 0, 0, 0)
_VERIFY_MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
_VERIFY_MAX_FILES = 128
_VERIFY_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
_VERIFY_MAX_COMPRESSION_RATIO = 100.0


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def _utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _zip_write(zf: ZipFile, path: str, data: bytes) -> None:
    zi = ZipInfo(path, date_time=_ZIP_TS)
    zi.compress_type = ZIP_DEFLATED
    zf.writestr(zi, data)


def _case_payload(case: Case) -> dict[str, object]:
    forensic_verdict = case_forensic_verdict(case)
    return {
        "case_id": case.case_id,
        "status": case.status.value,
        "title": case.title,
        "risk_class": case.risk_class,
        "risk_score": case.risk_score,
        "created_at": _utc_iso(case.created_at),
        "event_ids": list(case.normalized_event_ids),
        "xai_summary": case.xai_summary,
        "audit_log": list(case.audit_log),
        "operator_action_history": _operator_action_history(case.audit_log),
        "formal_verdict_history": _formal_verdict_records_payload(case)
        or _formal_verdict_history(case.audit_log),
        "formal_verdict_records": _formal_verdict_records_payload(case),
        "fingerprint": case.burst_fingerprint,
        "primary_asset_id": case.primary_asset_id,
        "trigger_operation": case.trigger_operation,
        "operator_id": case.operator_id,
        "action_class": _action_class(case.trigger_operation),
        "invariant_hits": list(case.invariant_hits),
        "observations": [
            {"source": o.source, "ingest_trust": o.ingest_trust, "event_ids": list(o.event_ids)}
            for o in case.observations
        ],
        "manual_permits": [
            _manual_permit_payload(p)
            for p in case.manual_permits
        ],
        "formal_verdict": {
            "value": forensic_verdict.value,
            "source": forensic_verdict.source,
            "context_match": {
                "matched": forensic_verdict.match.matched,
                "score": forensic_verdict.match.score,
                "reasons": list(forensic_verdict.match.reasons),
                "source": forensic_verdict.match.source,
            },
            "counterfactual": forensic_verdict.counterfactual,
        },
        "decision_records": [
            {
                "ts": _utc_iso(r.ts),
                "actor": r.actor,
                "prev_status": r.prev_status,
                "next_status": r.next_status,
                "reason": r.reason,
                "request_id": r.request_id,
            }
            for r in case.decision_records
        ],
        "remediation_attempts": [
            {
                "attempt_id": a.attempt_id,
                "case_id": a.case_id,
                "kind": a.kind,
                "status": a.status,
                "actor": a.actor,
                "created_at": _utc_iso(a.created_at),
                "action": a.action,
                "result": a.result,
                "readiness_before": a.readiness_before,
                "readiness_after": a.readiness_after,
                "note": a.note,
                "request_id": a.request_id,
            }
            for a in case.remediation_attempts
        ],
        "invariant_hit_records": [
            {
                "invariant_id": r.invariant_id,
                "event_ref": r.event_ref,
                "ts": _utc_iso(r.ts),
                "score_contribution": r.score_contribution,
                "dq_score": r.dq_score,
                "dq_partial": r.dq_partial,
                "dq_reasons": list(r.dq_reasons),
            }
            for r in case.invariant_hit_records
        ],
        "data_quality": {
            "dq_score": case.dq_score,
            "partial_observability": case.dq_partial,
            "reasons": list(case.dq_reasons),
        },
        "last_event_source": case.last_event_source,
        "raw_evidence_refs": [
            {
                "evidence_id": r.evidence_id,
                "source": r.source,
                "media_type": r.media_type,
                "captured_at": _utc_iso(r.captured_at),
                "sha256": r.sha256,
                "size_bytes": r.size_bytes,
                "event_id": r.event_id,
                "note": r.note,
                "path": f"raw/{r.evidence_id}.bin",
            }
            for r in case.raw_evidence_refs
        ],
    }


def _organizational_document_payload(permit) -> dict[str, object]:
    doc = permit.organizational_document()
    return {
        "document_id": doc.document_id,
        "document_type": doc.document_type,
        "asset_id": doc.asset_id,
        "operation": doc.operation,
        "action_class": doc.action_class,
        "executor": doc.executor,
        "approver": doc.approver,
        "valid_from": doc.valid_from,
        "valid_to": doc.valid_to,
        "document_status": doc.document_status,
        "restrictions": doc.restrictions,
        "checksum_algorithm": doc.checksum_algorithm,
        "checksum": doc.checksum,
    }


def _manual_permit_payload(permit) -> dict[str, object]:
    return {
        "permit_id": permit.permit_id,
        "case_id": permit.case_id,
        "work_order_number": permit.work_order_number,
        "actor": permit.actor,
        "created_at": _utc_iso(permit.created_at),
        "asset_id": permit.asset_id,
        "operation": permit.operation,
        "action_class": permit.action_class,
        "verdict": permit.verdict,
        "confidence": permit.confidence,
        "rationale": permit.rationale,
        "counterfactual": permit.counterfactual,
        "counterfactual_struct": permit.counterfactual_struct,
        "organizational_context_sha256": permit.organizational_context_sha256,
        "organizational_context": _organizational_document_payload(permit),
        "note": permit.note,
    }


def _formal_verdict_records_payload(case: Case) -> list[dict[str, object]]:
    return [
        {
            "ts": _utc_iso(r.ts),
            "actor": r.actor,
            "prev": r.prev,
            "next": r.next,
            "score": r.score,
            "source": r.source,
            "permit_id": r.permit_id,
            "reason": r.reason,
        }
        for r in case.formal_verdict_records
    ]


def _case_evidence_moment(case: Case) -> datetime:
    """Момент, которым датируется **содержимое** доказательного пакета.

    Берётся из данных дела — последней записи его журнала, а при её отсутствии из времени
    создания, — а не из часов. Причина в требовании детерминизма: повторный прогон на тех же
    данных обязан дать то же агрегированное контрольное значение манифеста
    (`CLAUDE.md`, раздел «Детерминизм контура вердикта»). Пока содержимое датировалось
    часами, корневой хэш и `package_id` менялись каждую секунду, и манифест, выданный одним
    запросом, не совпадал с архивом, выданным следующим.

    Журнал дела и так входит в пакет (`audit.txt`) и покрыт цепочкой хэшей, поэтому новая
    зависимость от него ничего не добавляет: пакет меняется ровно тогда, когда менялось дело.

    Момент физической выгрузки при этом не теряется — он остаётся в `manifest.json`, который
    держит цепочку, но в неё не входит.
    """
    moments = [case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=UTC)]
    for entry in case.audit_log:
        head = str(entry).split(" | ", 1)[0].strip()
        try:
            parsed = datetime.fromisoformat(head)
        except ValueError:
            # Запись без разбираемой отметки времени — не повод отказывать в выгрузке.
            continue
        moments.append(parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC))
    return max(moments)


def _compliance_report_payload(
    report: ComplianceDataQualityReport, *, generated_at: datetime
) -> dict[str, object]:
    return {
        "format": "TAKT Compliance Data Quality Report",
        "format_version": "0.1",
        "generated_at": _utc_iso(generated_at),
        "total_cases": report.total_cases,
        "open_cases": report.open_cases,
        "by_status": dict(report.by_status),
        "by_risk_class": dict(report.by_risk_class),
        "avg_dq_score": report.avg_dq_score,
        "dq_partial_count": report.dq_partial_count,
        "dq_reasons": dict(report.dq_reasons),
        "cases_without_manual_permit": report.cases_without_manual_permit,
        "cases_with_forensic_bundle_audit": report.cases_with_forensic_bundle_audit,
        "high_risk_without_decision": report.high_risk_without_decision,
        "false_positive_count": report.false_positive_count,
        "expected_behavior_count": report.expected_behavior_count,
        "invariant_hits": dict(report.invariant_hits),
        "remediation_attempts_by_kind": dict(report.remediation_attempts_by_kind),
        "remediation_attempts_by_status": dict(report.remediation_attempts_by_status),
        "readiness_flags": [
            {
                "code": flag.code,
                "ok": flag.ok,
                "value": flag.value,
                "threshold": flag.threshold,
            }
            for flag in report.readiness_flags
        ],
    }


def _audit_actor(parts: list[str]) -> str:
    for part in parts[2:]:
        if part.startswith("actor="):
            return part.split("=", 1)[1]
    return ""


def _decode_audit_value(raw: str) -> str:
    return "" if raw == "-" else raw.replace("%20", " ")


def _operator_action_history(audit_log: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in audit_log:
        parts = [chunk.strip() for chunk in line.split(" | ")]
        if len(parts) < 2 or not parts[1].startswith("operator action "):
            continue
        tokens = parts[1].split()
        if len(tokens) < 3:
            continue
        entry = {"ts": parts[0], "action": tokens[2], "reason": "", "note": "", "actor": _audit_actor(parts)}
        for token in tokens[3:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if key in entry:
                entry[key] = _decode_audit_value(value)
        out.append(entry)
    return out


def _formal_verdict_history(audit_log: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    prefix = "formal verdict change "
    for line in audit_log:
        parts = [chunk.strip() for chunk in line.split(" | ")]
        if len(parts) < 2 or not parts[1].startswith(prefix):
            continue
        fields: dict[str, str] = {}
        for token in parts[1][len(prefix) :].split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            fields[key] = value
        out.append(
            {
                "ts": parts[0],
                "prev": fields.get("prev", ""),
                "next": fields.get("next", ""),
                "score": fields.get("score", ""),
                "source": fields.get("source", ""),
                "permit_id": fields.get("permit_id", ""),
                "actor": _audit_actor(parts),
            }
        )
    return out


def _forensic_readiness_payload(
    report: ForensicReadinessReport, *, generated_at: datetime
) -> dict[str, object]:
    return {
        "format": "TAKT Forensic Readiness Report",
        "format_version": "0.1",
        "generated_at": _utc_iso(generated_at),
        "total_cases": report.total_cases,
        "ready_cases": report.ready_cases,
        "not_ready_cases": report.not_ready_cases,
        "missing_by_code": dict(report.missing_by_code),
        "cases": [
            {
                "case_id": item.case_id,
                "status": item.status,
                "risk_class": item.risk_class,
                "risk_score": item.risk_score,
                "ready": item.ready,
                "missing": list(item.missing),
            }
            for item in report.cases
        ],
    }


def _case_evidence_checklist_payload(
    checklist: CaseEvidenceChecklist, *, generated_at: datetime
) -> dict[str, object]:
    return {
        "format": "TAKT Case Evidence Checklist",
        "format_version": "0.1",
        "generated_at": _utc_iso(generated_at),
        "case_id": checklist.case_id,
        "ready": checklist.ready,
        "remediation_summary": dict(checklist.remediation_summary),
        "items": [
            {
                "code": item.code,
                "ok": item.ok,
                "detail": item.detail,
                "remediation_kind": item.remediation_kind,
                "remediation_action": item.remediation_action,
                "remediation_attempted": item.remediation_attempted,
                "latest_remediation_status": item.latest_remediation_status,
            }
            for item in checklist.items
        ],
    }


def _chain_hashes(files: list[tuple[str, str, bytes]]) -> list[str]:
    out: list[str] = []
    prev = ""
    for path, _media_type, data in files:
        item_hash = _sha256_hex(data)
        chained = _sha256_hex(f"{prev}:{path}:{item_hash}:{len(data)}".encode())
        out.append(chained)
        prev = chained
    return out


def _action_class(operation: str) -> str:
    op = operation.strip().upper()
    if any(token in op for token in ("WRITE", "COIL", "SET", "START", "STOP", "RESET", "OPEN", "CLOSE")):
        return "управляющее воздействие"
    if any(token in op for token in ("ADMIN", "LOGIN", "USER", "CONFIG", "FIRMWARE")):
        return "администрирование"
    if any(token in op for token in ("READ", "POLL", "GET", "STATUS")):
        return "чтение/опрос"
    if any(token in op for token in ("NETFLOW", "IPFIX", "PING", "SNMP", "SYSLOG")):
        return "сетевое событие"
    return "общее действие"


def _manifest_item_classification(path: str) -> tuple[str, str, str]:
    if path == "case.json":
        return ("дело", "реестр дел ТАКТ", "основная карточка дела")
    if path == "siem.json":
        return ("экспорт SIEM", "адаптер SIEM ТАКТ", "машинный экспорт события")
    if path == "gossopka-card.json":
        return ("карточка инцидента", "адаптер ГосСОПКА ТАКТ", "карточка передачи инцидента")
    if path == "audit.txt":
        return ("аудиторский след", "журнал дела ТАКТ", "история действий и решений")
    if path.startswith("raw/"):
        return ("исходное доказательство", "исходный источник события", "первичный материал")
    if path == "evidence-index.json":
        return ("индекс доказательств", "реестр исходных доказательств ТАКТ", "описание первичных материалов")
    if path == "compliance-data-quality-report.json":
        return ("отчет о качестве данных", "модуль compliance ТАКТ", "оценка полноты наблюдения")
    if path == "forensic-readiness-report.json":
        return ("отчет о готовности доказательств", "модуль forensic readiness ТАКТ", "контроль пригодности пакета")
    if path == "case-evidence-checklist.json":
        return ("чек-лист доказательств", "модуль compliance ТАКТ", "перечень недостающих материалов")
    if path == "engagement.json":
        return ("аудиторское задание", "модуль аудиторских заданий ТАКТ", "контекст сервисного аудита")
    if path == "engagement-report.json":
        return ("отчет аудиторского задания", "модуль аудиторских заданий ТАКТ", "зафиксированный результат аудита")
    return ("дополнительный материал", "дополнительный источник", "дополнение к доказательному пакету")


def _issue(code: str, detail: str) -> ForensicBundleVerificationIssue:
    return ForensicBundleVerificationIssue(code=code, detail=detail)


def _unsafe_zip_path(path: str) -> bool:
    return not path or path.startswith("/") or "\\" in path or ".." in path.split("/")


def _zip_structure_issues(zf: ZipFile) -> list[ForensicBundleVerificationIssue]:
    infos = zf.infolist()
    issues: list[ForensicBundleVerificationIssue] = []
    if len(infos) > _VERIFY_MAX_FILES:
        issues.append(_issue("too_many_files", f"archive has {len(infos)} files; max is {_VERIFY_MAX_FILES}"))
    total_size = 0
    for info in infos:
        total_size += int(info.file_size)
        if _unsafe_zip_path(info.filename):
            issues.append(_issue("invalid_path", f"unsafe archive path: {info.filename!r}"))
        if info.compress_size > 0 and (info.file_size / info.compress_size) > _VERIFY_MAX_COMPRESSION_RATIO:
            issues.append(
                _issue(
                    "compression_ratio_exceeded",
                    f"{info.filename}: ratio {info.file_size / info.compress_size:.1f} exceeds {_VERIFY_MAX_COMPRESSION_RATIO:.1f}",
                )
            )
    if total_size > _VERIFY_MAX_UNCOMPRESSED_BYTES:
        issues.append(
            _issue(
                "uncompressed_size_exceeded",
                f"archive uncompressed size {total_size} exceeds {_VERIFY_MAX_UNCOMPRESSED_BYTES}",
            )
        )
    return issues


def _raw_evidence_files(case: Case) -> tuple[list[tuple[str, str, bytes]], dict[str, object]]:
    files: list[tuple[str, str, bytes]] = []
    index_items: list[dict[str, object]] = []
    for ref in case.raw_evidence_refs:
        path = f"raw/{ref.evidence_id}.bin"
        payload = base64.b64decode(ref.payload_b64.encode("ascii"), validate=False)
        files.append((path, ref.media_type or "application/octet-stream", payload))
        index_items.append(
            {
                "evidence_id": ref.evidence_id,
                "path": path,
                "source": ref.source,
                "event_id": ref.event_id,
                "captured_at": _utc_iso(ref.captured_at),
                "sha256": ref.sha256,
                "size_bytes": ref.size_bytes,
                "note": ref.note,
            }
        )
    return files, {"format": "TAKT Raw Evidence Index", "format_version": "0.1", "items": index_items}


def _process_suitability(signature_status: str) -> str:
    if signature_status in {"external_qualified_detached", "external_gost2012_detached"}:
        return "qualified_signature_attached_for_procedural_actions"
    if signature_status == "hmac_sha256_mvp":
        return "integrity_chain_present_non_qualified_signature"
    return "machine_readable_evidence_bundle_without_qualified_signature"


def _suitability_label(signature_status: str) -> str:
    if signature_status in {"external_qualified_detached", "external_gost2012_detached"}:
        return "пригоден"
    if signature_status == "hmac_sha256_mvp":
        return "условно пригоден"
    if signature_status == "unsigned_mvp":
        return "требует дополнительной проверки"
    return "непригоден"


def _suitability_checks(case: Case, *, signature_status: str, root_hash: str) -> tuple[dict[str, object], ...]:
    formal_verdict = case_forensic_verdict(case)
    has_operator_history = any(
        "operator action " in line or "formal verdict change " in line or "status -> " in line
        for line in case.audit_log
    )
    has_org_context_checksum = any(bool(p.organizational_context_sha256) for p in case.manual_permits)
    checks = (
        {
            "code": "normalized_event",
            "ok": bool(case.normalized_event_ids),
            "detail": f"event_ids={len(case.normalized_event_ids)}",
        },
        {
            "code": "observability",
            "ok": not case.dq_partial,
            "detail": f"dq_partial={case.dq_partial}",
        },
        {
            "code": "formal_verdict",
            "ok": bool(formal_verdict.value),
            "detail": formal_verdict.value,
        },
        {
            "code": "operator_history",
            "ok": has_operator_history,
            "detail": "operator action, formal verdict change or decision record present" if has_operator_history else "operator history absent",
        },
        {
            "code": "organizational_context_checksum",
            "ok": has_org_context_checksum,
            "detail": "manual permit checksum present" if has_org_context_checksum else "manual permit checksum absent",
        },
        {
            "code": "aggregate_checksum",
            "ok": len(root_hash) == 64,
            "detail": "root_hash_sha256 present" if len(root_hash) == 64 else "root_hash_sha256 invalid",
        },
        {
            "code": "signature",
            "ok": signature_status in {"hmac_sha256_mvp", "external_qualified_detached", "external_gost2012_detached"},
            "detail": signature_status,
        },
    )
    return checks


class ZipForensicBundleBuilder:
    """MVP forensic archive: deterministic ZIP with manifest and SHA-256 hash chain."""

    def __init__(self, signer: RootHashSignatureAdapter | None = None) -> None:
        self._signer = signer or RootHashSignatureAdapter()

    def build_case_bundle(
        self,
        case: Case,
        *,
        generated_at: datetime,
        compliance_report: ComplianceDataQualityReport | None = None,
        forensic_readiness_report: ForensicReadinessReport | None = None,
        case_evidence_checklist: CaseEvidenceChecklist | None = None,
        supplemental_files: list[tuple[str, str, bytes]] | None = None,
    ) -> tuple[ForensicBundle, bytes]:
        evidence_files: list[tuple[str, str, bytes]] = [
            ("case.json", "application/json", _json_bytes(_case_payload(case))),
            (
                "siem.json",
                "application/json",
                case_to_siem_payload(case).model_dump_json(indent=2).encode("utf-8"),
            ),
            ("audit.txt", "text/plain; charset=utf-8", "\n".join(case.audit_log).encode("utf-8")),
            (
                "findings.json", "application/json",
                _json_bytes([
                    {
                        "finding_id": item.finding_id, "text": item.text, "author": item.author,
                        "created_at": _utc_iso(item.created_at), "event_ids": list(item.event_ids),
                        "artifacts": [
                            {"type": artifact.type, "value": artifact.value, "host_id": artifact.host_id}
                            for artifact in item.artifacts
                        ],
                    } for item in case.findings
                ]),
            ),
            (
                "artifacts.json", "application/json",
                _json_bytes([
                    {
                        "type": item.type, "value": item.value, "host_id": item.host_id,
                        "verification_status": item.verification_status, "source": item.source,
                        "added_by": item.added_by,
                        "created_at": _utc_iso(item.created_at) if item.created_at else None,
                    } for item in case.artifacts
                ]),
            ),
        ]
        # Содержимое пакета датируется данными дела, а не часами: см. _case_evidence_moment.
        evidence_at = _case_evidence_moment(case)
        raw_files, raw_index = _raw_evidence_files(case)
        if raw_files:
            evidence_files.extend(raw_files)
            evidence_files.append(("evidence-index.json", "application/json", _json_bytes(raw_index)))
        if compliance_report is not None:
            evidence_files.append(
                (
                    "compliance-data-quality-report.json",
                    "application/json",
                    _json_bytes(_compliance_report_payload(compliance_report, generated_at=evidence_at)),
                )
            )
        if forensic_readiness_report is not None:
            evidence_files.append(
                (
                    "forensic-readiness-report.json",
                    "application/json",
                    _json_bytes(
                        _forensic_readiness_payload(forensic_readiness_report, generated_at=evidence_at)
                    ),
                )
            )
        if case_evidence_checklist is not None:
            evidence_files.append(
                (
                    "case-evidence-checklist.json",
                    "application/json",
                    _json_bytes(
                        _case_evidence_checklist_payload(case_evidence_checklist, generated_at=evidence_at)
                    ),
                )
            )
        if supplemental_files:
            for path, media_type, data in sorted(supplemental_files, key=lambda item: item[0]):
                evidence_files.append((path, media_type, data))
        gossopka_payload = _json_bytes(
            case_to_gossopka_card(
                case,
                generated_at=evidence_at,
            )
        )
        evidence_files.insert(2, ("gossopka-card.json", "application/json", gossopka_payload))
        chain_hashes = _chain_hashes(evidence_files)
        included_at = generated_at if generated_at.tzinfo else generated_at.replace(tzinfo=UTC)
        item_rows: list[ForensicEvidenceItem] = []
        for (path, media_type, data), chain_hash in zip(evidence_files, chain_hashes, strict=True):
            element_type, source, role = _manifest_item_classification(path)
            item_rows.append(
                ForensicEvidenceItem(
                    path=path,
                    element_type=element_type,
                    source=source,
                    role=role,
                    media_type=media_type,
                    sha256=_sha256_hex(data),
                    checksum_algorithm="SHA-256",
                    chain_sha256=chain_hash,
                    size_bytes=len(data),
                    included_at=included_at,
                )
            )
        items = tuple(item_rows)
        root_hash = items[-1].chain_sha256 if items else _sha256_hex(b"")
        signature = self._signer.build_signature(root_hash)
        signature_status = signature.signature_status
        signature_ref = signature.signature_ref
        meta = ForensicBundle(
            case_id=case.case_id,
            package_id=f"takt-{case.case_id}-{root_hash[:16]}",
            generated_at=generated_at if generated_at.tzinfo else generated_at.replace(tzinfo=UTC),
            root_hash_sha256=root_hash,
            signature_status=signature_status,
            process_suitability=_process_suitability(signature_status),
            suitability_label=_suitability_label(signature_status),
            suitability_checks=_suitability_checks(case, signature_status=signature_status, root_hash=root_hash),
            signature_ref=signature_ref,
            items=items,
        )
        manifest = {
            "format": "TAKT Forensic Bundle",
            "format_version": "0.2",
            "package_id": meta.package_id,
            "case_id": meta.case_id,
            "generated_at": _utc_iso(meta.generated_at),
            "root_hash_sha256": meta.root_hash_sha256,
            "signature_status": meta.signature_status,
            "signature_ref": meta.signature_ref,
            "process_suitability": meta.process_suitability,
            "suitability_label": meta.suitability_label,
            "suitability_checks": list(meta.suitability_checks),
            "items": [
                {
                    "path": item.path,
                    "element_type": item.element_type,
                    "source": item.source,
                    "role": item.role,
                    "media_type": item.media_type,
                    "sha256": item.sha256,
                    "checksum_algorithm": item.checksum_algorithm,
                    "chain_sha256": item.chain_sha256,
                    "size_bytes": item.size_bytes,
                    "included_at": _utc_iso(item.included_at),
                }
                for item in meta.items
            ],
        }
        out = BytesIO()
        with ZipFile(out, "w") as zf:
            _zip_write(zf, "manifest.json", _json_bytes(manifest))
            for path, _media_type, data in evidence_files:
                _zip_write(zf, path, data)
            if signature.payload is not None and signature_ref:
                _zip_write(zf, signature_ref, _json_bytes(signature.payload))
        return meta, out.getvalue()


class ZipForensicBundleVerifier:
    """Verifies a TAKT Forensic Bundle ZIP without extracting files to disk."""

    def __init__(self, signer: RootHashSignatureAdapter | None = None) -> None:
        self._signer = signer or RootHashSignatureAdapter()

    def verify_bundle(self, archive_bytes: bytes) -> ForensicBundleVerification:
        issues: list[ForensicBundleVerificationIssue] = []
        case_id = ""
        root_hash = ""
        signature_status = ""
        checked = 0
        if len(archive_bytes) > _VERIFY_MAX_ARCHIVE_BYTES:
            return ForensicBundleVerification(
                ok=False,
                case_id="",
                root_hash_sha256="",
                signature_status="",
                checked_items=0,
                issues=(
                    _issue(
                        "archive_size_exceeded",
                        f"archive size {len(archive_bytes)} exceeds {_VERIFY_MAX_ARCHIVE_BYTES}",
                    ),
                ),
            )
        try:
            with ZipFile(BytesIO(archive_bytes)) as zf:
                structure_issues = _zip_structure_issues(zf)
                if structure_issues:
                    return ForensicBundleVerification(
                        ok=False,
                        case_id="",
                        root_hash_sha256="",
                        signature_status="",
                        checked_items=0,
                        issues=tuple(structure_issues),
                    )
                try:
                    manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                except KeyError:
                    return ForensicBundleVerification(
                        ok=False,
                        case_id="",
                        root_hash_sha256="",
                        signature_status="",
                        checked_items=0,
                        issues=(_issue("missing_manifest", "manifest.json is absent"),),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    return ForensicBundleVerification(
                        ok=False,
                        case_id="",
                        root_hash_sha256="",
                        signature_status="",
                        checked_items=0,
                        issues=(_issue("invalid_manifest", str(e)),),
                    )
                case_id = str(manifest.get("case_id", ""))
                root_hash = str(manifest.get("root_hash_sha256", ""))
                signature_status = str(manifest.get("signature_status", ""))
                signature_ref = str(manifest.get("signature_ref", ""))
                raw_items = manifest.get("items")
                if not isinstance(raw_items, list) or not raw_items:
                    issues.append(_issue("empty_items", "manifest.items must be a non-empty list"))
                    raw_items = []
                prev_chain = ""
                for raw_item in raw_items:
                    if not isinstance(raw_item, dict):
                        issues.append(_issue("invalid_item", "manifest item is not an object"))
                        continue
                    path = str(raw_item.get("path", ""))
                    expected_sha = str(raw_item.get("sha256", ""))
                    expected_chain = str(raw_item.get("chain_sha256", ""))
                    expected_size = raw_item.get("size_bytes")
                    if path == "manifest.json" or _unsafe_zip_path(path):
                        issues.append(_issue("invalid_path", f"unsafe evidence path: {path!r}"))
                        continue
                    try:
                        data = zf.read(path)
                    except KeyError:
                        issues.append(_issue("missing_item", f"{path} is absent from archive"))
                        continue
                    checked += 1
                    actual_sha = _sha256_hex(data)
                    if actual_sha != expected_sha:
                        issues.append(_issue("sha256_mismatch", f"{path}: expected {expected_sha}, got {actual_sha}"))
                    if isinstance(expected_size, int) and len(data) != expected_size:
                        issues.append(_issue("size_mismatch", f"{path}: expected {expected_size}, got {len(data)}"))
                    actual_chain = _sha256_hex(f"{prev_chain}:{path}:{actual_sha}:{len(data)}".encode())
                    if actual_chain != expected_chain:
                        issues.append(_issue("chain_mismatch", f"{path}: expected {expected_chain}, got {actual_chain}"))
                    prev_chain = actual_chain
                if prev_chain and root_hash != prev_chain:
                    issues.append(_issue("root_hash_mismatch", f"expected {root_hash}, got {prev_chain}"))
                sig_payload: dict[str, object] | None = None
                if signature_status != "unsigned_mvp":
                    if not signature_ref:
                        issues.append(_issue("signature_ref_missing", "manifest.signature_ref is required"))
                    else:
                        try:
                            sig_payload = json.loads(zf.read(signature_ref).decode("utf-8"))
                        except KeyError:
                            issues.append(_issue("signature_missing", f"{signature_ref} is absent from archive"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as e:
                            issues.append(_issue("signature_invalid", str(e)))
                if not any(i.code in {"signature_ref_missing", "signature_missing", "signature_invalid"} for i in issues):
                    sig_result = self._signer.verify_signature(
                        signature_status=signature_status,
                        root_hash_sha256=root_hash,
                        signature_payload=sig_payload,
                    )
                    if not sig_result.ok:
                        issues.append(_issue(sig_result.issue_code or "signature_invalid", sig_result.issue_detail))
        except BadZipFile as e:
            return ForensicBundleVerification(
                ok=False,
                case_id="",
                root_hash_sha256="",
                signature_status="",
                checked_items=0,
                issues=(_issue("bad_zip", str(e)),),
            )
        return ForensicBundleVerification(
            ok=not issues,
            case_id=case_id,
            root_hash_sha256=root_hash,
            signature_status=signature_status,
            checked_items=checked,
            issues=tuple(issues),
        )
