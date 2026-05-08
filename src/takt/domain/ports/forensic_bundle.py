from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from takt.domain.entities.case import Case
from takt.domain.entities.compliance import CaseEvidenceChecklist, ComplianceDataQualityReport, ForensicReadinessReport
from takt.domain.entities.forensic import ForensicBundle, ForensicBundleVerification


@runtime_checkable
class ForensicBundleBuilderPort(Protocol):
    """Builds a tamper-evident forensic bundle for an already classified Risk Case."""

    def build_case_bundle(
        self,
        case: Case,
        *,
        generated_at: datetime,
        compliance_report: ComplianceDataQualityReport | None = None,
        forensic_readiness_report: ForensicReadinessReport | None = None,
        case_evidence_checklist: CaseEvidenceChecklist | None = None,
        supplemental_files: list[tuple[str, str, bytes]] | None = None,
    ) -> tuple[ForensicBundle, bytes]: ...


@runtime_checkable
class ForensicBundleVerifierPort(Protocol):
    """Verifies a forensic bundle archive without trusting its payload."""

    def verify_bundle(self, archive_bytes: bytes) -> ForensicBundleVerification: ...
