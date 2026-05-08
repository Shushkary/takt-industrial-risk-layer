from __future__ import annotations

import hashlib
import json
import base64
from datetime import datetime, timezone
from io import BytesIO
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile, ZipInfo

from takt.domain.entities.case import Case, RawEvidenceRef
from takt.domain.entities.compliance import CaseEvidenceChecklist, ComplianceDataQualityReport, ForensicReadinessReport
from takt.domain.entities.forensic import (
    ForensicBundle,
    ForensicBundleVerification,
    ForensicBundleVerificationIssue,
    ForensicEvidenceItem,
)
from takt.infrastructure.export.gossopka import case_to_gossopka_card
from takt.infrastructure.export.siem_webhook import case_to_siem_payload
from takt.infrastructure.security.root_hash_signature import RootHashSignatureAdapter


_ZIP_TS = (1980, 1, 1, 0, 0, 0)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def _utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _zip_write(zf: ZipFile, path: str, data: bytes) -> None:
    zi = ZipInfo(path, date_time=_ZIP_TS)
    zi.compress_type = ZIP_DEFLATED
    zf.writestr(zi, data)


def _case_payload(case: Case) -> dict[str, object]:
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
        "fingerprint": case.burst_fingerprint,
        "primary_asset_id": case.primary_asset_id,
        "trigger_operation": case.trigger_operation,
        "invariant_hits": list(case.invariant_hits),
        "observations": [
            {"source": o.source, "ingest_trust": o.ingest_trust, "event_ids": list(o.event_ids)}
            for o in case.observations
        ],
        "manual_permits": [
            {
                "permit_id": p.permit_id,
                "case_id": p.case_id,
                "work_order_number": p.work_order_number,
                "actor": p.actor,
                "created_at": _utc_iso(p.created_at),
                "asset_id": p.asset_id,
                "operation": p.operation,
                "verdict": p.verdict,
                "confidence": p.confidence,
                "rationale": p.rationale,
                "counterfactual": p.counterfactual,
                "note": p.note,
            }
            for p in case.manual_permits
        ],
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


def _compliance_report_payload(report: ComplianceDataQualityReport) -> dict[str, object]:
    return {
        "format": "TAKT Compliance Data Quality Report",
        "format_version": "0.1",
        "generated_at": _utc_iso(report.generated_at),
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


def _forensic_readiness_payload(report: ForensicReadinessReport) -> dict[str, object]:
    return {
        "format": "TAKT Forensic Readiness Report",
        "format_version": "0.1",
        "generated_at": _utc_iso(report.generated_at),
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


def _case_evidence_checklist_payload(checklist: CaseEvidenceChecklist) -> dict[str, object]:
    return {
        "format": "TAKT Case Evidence Checklist",
        "format_version": "0.1",
        "generated_at": _utc_iso(checklist.generated_at),
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
        chained = _sha256_hex(f"{prev}:{path}:{item_hash}:{len(data)}".encode("utf-8"))
        out.append(chained)
        prev = chained
    return out


def _issue(code: str, detail: str) -> ForensicBundleVerificationIssue:
    return ForensicBundleVerificationIssue(code=code, detail=detail)


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
        ]
        raw_files, raw_index = _raw_evidence_files(case)
        if raw_files:
            evidence_files.extend(raw_files)
            evidence_files.append(("evidence-index.json", "application/json", _json_bytes(raw_index)))
        if compliance_report is not None:
            evidence_files.append(
                (
                    "compliance-data-quality-report.json",
                    "application/json",
                    _json_bytes(_compliance_report_payload(compliance_report)),
                )
            )
        if forensic_readiness_report is not None:
            evidence_files.append(
                (
                    "forensic-readiness-report.json",
                    "application/json",
                    _json_bytes(_forensic_readiness_payload(forensic_readiness_report)),
                )
            )
        if case_evidence_checklist is not None:
            evidence_files.append(
                (
                    "case-evidence-checklist.json",
                    "application/json",
                    _json_bytes(_case_evidence_checklist_payload(case_evidence_checklist)),
                )
            )
        if supplemental_files:
            for path, media_type, data in sorted(supplemental_files, key=lambda item: item[0]):
                evidence_files.append((path, media_type, data))
        gossopka_payload = _json_bytes(
            case_to_gossopka_card(
                case,
                generated_at=generated_at,
            )
        )
        evidence_files.insert(2, ("gossopka-card.json", "application/json", gossopka_payload))
        chain_hashes = _chain_hashes(evidence_files)
        items = tuple(
            ForensicEvidenceItem(
                path=path,
                media_type=media_type,
                sha256=_sha256_hex(data),
                chain_sha256=chain_hash,
                size_bytes=len(data),
            )
            for (path, media_type, data), chain_hash in zip(evidence_files, chain_hashes, strict=True)
        )
        root_hash = items[-1].chain_sha256 if items else _sha256_hex(b"")
        signature = self._signer.build_signature(root_hash)
        signature_status = signature.signature_status
        signature_ref = signature.signature_ref
        meta = ForensicBundle(
            case_id=case.case_id,
            generated_at=generated_at if generated_at.tzinfo else generated_at.replace(tzinfo=timezone.utc),
            root_hash_sha256=root_hash,
            signature_status=signature_status,
            process_suitability=_process_suitability(signature_status),
            signature_ref=signature_ref,
            items=items,
        )
        manifest = {
            "format": "TAKT Forensic Bundle",
            "format_version": "0.1",
            "case_id": meta.case_id,
            "generated_at": _utc_iso(meta.generated_at),
            "root_hash_sha256": meta.root_hash_sha256,
            "signature_status": meta.signature_status,
            "signature_ref": meta.signature_ref,
            "process_suitability": meta.process_suitability,
            "items": [
                {
                    "path": item.path,
                    "media_type": item.media_type,
                    "sha256": item.sha256,
                    "chain_sha256": item.chain_sha256,
                    "size_bytes": item.size_bytes,
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
        try:
            with ZipFile(BytesIO(archive_bytes)) as zf:
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
                    if not path or path == "manifest.json" or path.startswith("/") or ".." in path.split("/"):
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
                    actual_chain = _sha256_hex(f"{prev_chain}:{path}:{actual_sha}:{len(data)}".encode("utf-8"))
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
