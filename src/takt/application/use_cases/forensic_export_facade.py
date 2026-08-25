from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ForensicArchiveResponse:
    content: bytes
    media_type: str
    headers: dict[str, str]


class ForensicSupplementalFileError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@runtime_checkable
class ForensicBundleUseCaseProtocol(Protocol):
    def execute(
        self,
        case_id: str,
        *,
        actor: str,
        record_audit: bool,
        supplemental_files: list[tuple[str, str, bytes]],
    ) -> Any: ...


@runtime_checkable
class ForensicVerifyUseCaseProtocol(Protocol):
    def execute(self, raw: bytes) -> Any: ...


@runtime_checkable
class AuditEngagementUseCaseProtocol(Protocol):
    def get(self, engagement_id: str) -> Any: ...


class ForensicExportFacade:
    def __init__(
        self,
        *,
        forensic_uc: ForensicBundleUseCaseProtocol,
        forensic_verify_uc: ForensicVerifyUseCaseProtocol,
        audit_engagement_uc: AuditEngagementUseCaseProtocol | None = None,
    ) -> None:
        self._forensic_uc = forensic_uc
        self._forensic_verify_uc = forensic_verify_uc
        self._audit_engagement_uc = audit_engagement_uc

    def manifest(self, *, case_id: str, engagement_id: str = "") -> dict[str, Any]:
        bundle = self._build_bundle_metadata(
            case_id=case_id,
            engagement_id=engagement_id,
            actor="",
            record_audit=False,
        )
        return self._manifest_to_response(bundle)

    def archive(self, *, case_id: str, actor: str, engagement_id: str = "") -> ForensicArchiveResponse:
        supplemental_files = self._supplemental_files(case_id, engagement_id)
        out = self._forensic_uc.execute(
            case_id,
            actor=actor,
            record_audit=True,
            supplemental_files=supplemental_files,
        )
        root_hash = out.metadata.root_hash_sha256
        signature_status = out.metadata.signature_status
        return ForensicArchiveResponse(
            content=out.archive_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="takt-forensic-{case_id}.zip"',
                "X-TAKT-Forensic-Root-Hash": root_hash,
                "X-TAKT-Forensic-Signature-Status": signature_status,
            },
        )

    def verify_archive(self, raw: bytes) -> dict[str, Any]:
        if not raw:
            raise ValueError("empty archive body")
        result = self._forensic_verify_uc.execute(raw)
        return {
            "ok": result.ok,
            "case_id": result.case_id,
            "root_hash_sha256": result.root_hash_sha256,
            "signature_status": result.signature_status,
            "checked_items": result.checked_items,
            "issues": [{"code": issue.code, "detail": issue.detail} for issue in result.issues],
        }

    def _build_bundle_metadata(
        self,
        *,
        case_id: str,
        engagement_id: str,
        actor: str,
        record_audit: bool,
    ) -> Any:
        supplemental_files = self._supplemental_files(case_id, engagement_id)
        return self._forensic_uc.execute(
            case_id,
            actor=actor,
            record_audit=record_audit,
            supplemental_files=supplemental_files,
        ).metadata

    def _supplemental_files(self, case_id: str, engagement_id: str) -> list[tuple[str, str, bytes]]:
        eid = engagement_id.strip()
        if not eid:
            return []
        if self._audit_engagement_uc is not None:
            engagement = self._audit_engagement_uc.get(eid)
            if engagement is None:
                raise ForensicSupplementalFileError("engagement_not_found", "engagement not found")
            if case_id not in engagement.case_ids:
                raise ForensicSupplementalFileError("engagement_case_mismatch", "engagement is not linked to case")
            payload = self._audit_engagement_payload(engagement)
            files: list[tuple[str, str, bytes]] = [
                ("engagement.json", "application/json", self._json_bytes(payload)),
            ]
            if payload.get("final_report") is not None:
                files.append(("engagement-report.json", "application/json", self._json_bytes(payload["final_report"])))
            return files
        if self._audit_engagement_uc is None:
            return []
        return []

    @staticmethod
    def _audit_engagement_payload(item: Any) -> dict[str, Any]:
        return {
            "engagement_id": item.engagement_id,
            "created_at": item.created_at.astimezone(UTC).isoformat(timespec="seconds"),
            "status": item.status,
            "customer": item.customer,
            "scope": item.scope,
            "case_ids": list(item.case_ids),
            "nda_signed": item.nda_signed,
            "evidence_intake_checklist": list(item.evidence_intake_checklist),
            "stages": [
                {
                    "code": stage.code,
                    "title": stage.title,
                    "day_range": stage.day_range,
                    "status": stage.status,
                    "started_at": (
                        stage.started_at.astimezone(UTC).isoformat(timespec="seconds")
                        if stage.started_at
                        else None
                    ),
                    "completed_at": (
                        stage.completed_at.astimezone(UTC).isoformat(timespec="seconds")
                        if stage.completed_at
                        else None
                    ),
                    "note": stage.note,
                }
                for stage in item.stages
            ],
            "findings": list(item.findings),
            "final_report": (
                {
                    "title": item.final_report.title,
                    "uri": item.final_report.uri,
                    "summary": item.final_report.summary,
                    "generated_at": item.final_report.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
                }
                if item.final_report is not None
                else None
            ),
        }

    @staticmethod
    def _json_bytes(payload: object) -> bytes:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _manifest_to_response(bundle: Any) -> dict[str, Any]:
        return {
            "package_id": bundle.package_id,
            "case_id": bundle.case_id,
            "generated_at": bundle.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "root_hash_sha256": bundle.root_hash_sha256,
            "signature_status": bundle.signature_status,
            "signature_ref": bundle.signature_ref,
            "process_suitability": bundle.process_suitability,
            "suitability_label": bundle.suitability_label,
            "suitability_checks": list(bundle.suitability_checks),
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
                    "included_at": item.included_at.astimezone(UTC).isoformat(timespec="seconds"),
                }
                for item in bundle.items
            ],
        }
