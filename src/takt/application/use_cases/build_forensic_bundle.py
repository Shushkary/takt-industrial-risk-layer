from __future__ import annotations

from dataclasses import dataclass

from takt.application.use_cases.compliance_report import (
    BuildCaseEvidenceChecklistUseCase,
    BuildComplianceDataQualityReportUseCase,
    BuildForensicReadinessReportUseCase,
)
from takt.domain.entities.forensic import ForensicBundle
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.forensic_bundle import ForensicBundleBuilderPort
from takt.domain.ports.system_ports import SystemClockPort


@dataclass(frozen=True, slots=True)
class ForensicBundleResult:
    metadata: ForensicBundle
    archive_bytes: bytes


class BuildForensicBundleUseCase:
    """Application use case: load a Risk Case and delegate archive construction to an output port."""

    def __init__(
        self,
        repo: CaseRepositoryPort,
        builder: ForensicBundleBuilderPort,
        clock: SystemClockPort,
        compliance_report: BuildComplianceDataQualityReportUseCase | None = None,
        forensic_readiness: BuildForensicReadinessReportUseCase | None = None,
        evidence_checklist: BuildCaseEvidenceChecklistUseCase | None = None,
    ) -> None:
        self._repo = repo
        self._builder = builder
        self._clock = clock
        self._compliance_report = compliance_report
        self._forensic_readiness = forensic_readiness
        self._evidence_checklist = evidence_checklist

    def execute(
        self,
        case_id: str,
        *,
        actor: str = "",
        record_audit: bool = True,
        supplemental_files: list[tuple[str, str, bytes]] | None = None,
    ) -> ForensicBundleResult:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id}")
        generated_at = self._clock.now_utc()
        report = self._compliance_report.execute() if self._compliance_report is not None else None
        readiness = self._forensic_readiness.execute() if self._forensic_readiness is not None else None
        checklist = self._evidence_checklist.execute(case_id) if self._evidence_checklist is not None else None
        meta, raw = self._builder.build_case_bundle(
            case,
            generated_at=generated_at,
            compliance_report=report,
            forensic_readiness_report=readiness,
            case_evidence_checklist=checklist,
            supplemental_files=supplemental_files,
        )
        if record_audit:
            case.append_audit(
                (
                    "forensic bundle generated "
                    f"root_hash={meta.root_hash_sha256} signature_status={meta.signature_status}"
                ),
                generated_at,
                actor=actor,
            )
            self._repo.save(case)
        return ForensicBundleResult(metadata=meta, archive_bytes=raw)
