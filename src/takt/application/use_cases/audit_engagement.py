from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from takt.domain.entities.audit_engagement import AuditEngagement, AuditFinalReport, AuditStage
from takt.domain.ports.audit_engagement_repository import AuditEngagementRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


@dataclass(frozen=True, slots=True)
class CreateAuditEngagementCommand:
    customer: str
    scope: str
    case_ids: list[str]
    nda_signed: bool
    evidence_intake_checklist: list[str]


@dataclass(frozen=True, slots=True)
class FinalizeAuditReportCommand:
    title: str
    uri: str
    summary: str


_DEFAULT_STAGES: tuple[tuple[str, str, str], ...] = (
    ("intake", "Intake and NDA", "1-2"),
    ("forensic_collection", "Forensic Collection and Correlation", "2-7"),
    ("reporting", "Final Report Preparation", "7-10"),
)


class ManageAuditEngagementUseCase:
    def __init__(self, repo: AuditEngagementRepositoryPort, clock: SystemClockPort, ids: IdProviderPort) -> None:
        self._repo = repo
        self._clock = clock
        self._ids = ids

    def create(self, command: CreateAuditEngagementCommand) -> AuditEngagement:
        now = self._clock.now_utc()
        stages = [
            AuditStage(
                code=code,
                title=title,
                day_range=day_range,
                status="in_progress" if idx == 0 else "pending",
                started_at=now if idx == 0 else None,
            )
            for idx, (code, title, day_range) in enumerate(_DEFAULT_STAGES)
        ]
        engagement = AuditEngagement(
            engagement_id=f"ae-{self._ids.new_case_id_short()}",
            created_at=now,
            status="active",
            customer=command.customer.strip(),
            scope=command.scope.strip(),
            case_ids=list(command.case_ids),
            nda_signed=command.nda_signed,
            evidence_intake_checklist=list(command.evidence_intake_checklist),
            stages=stages,
        )
        self._repo.save(engagement)
        return deepcopy(engagement)

    def get(self, engagement_id: str) -> AuditEngagement | None:
        item = self._repo.get(engagement_id)
        return deepcopy(item) if item is not None else None

    def list_all(self) -> list[AuditEngagement]:
        return [deepcopy(item) for item in self._repo.list_all()]

    def advance_stage(self, engagement_id: str, *, note: str = "") -> AuditEngagement:
        engagement = self._repo.get(engagement_id)
        if engagement is None:
            raise ValueError(f"unknown engagement {engagement_id}")
        now = self._clock.now_utc()
        current_idx = next((i for i, st in enumerate(engagement.stages) if st.status == "in_progress"), -1)
        if current_idx < 0:
            raise ValueError("engagement has no in-progress stage")
        engagement.stages[current_idx].status = "completed"
        engagement.stages[current_idx].completed_at = now
        if note.strip():
            engagement.stages[current_idx].note = note.strip()
        next_idx = current_idx + 1
        if next_idx < len(engagement.stages):
            engagement.stages[next_idx].status = "in_progress"
            if engagement.stages[next_idx].started_at is None:
                engagement.stages[next_idx].started_at = now
        else:
            engagement.status = "completed"
        self._repo.save(engagement)
        return deepcopy(engagement)

    def add_finding(self, engagement_id: str, finding: str) -> AuditEngagement:
        engagement = self._repo.get(engagement_id)
        if engagement is None:
            raise ValueError(f"unknown engagement {engagement_id}")
        text = finding.strip()
        if not text:
            raise ValueError("finding must not be empty")
        engagement.findings.append(text)
        self._repo.save(engagement)
        return deepcopy(engagement)

    def finalize_report(self, engagement_id: str, command: FinalizeAuditReportCommand) -> AuditEngagement:
        engagement = self._repo.get(engagement_id)
        if engagement is None:
            raise ValueError(f"unknown engagement {engagement_id}")
        now = self._clock.now_utc()
        engagement.final_report = AuditFinalReport(
            title=command.title.strip(),
            uri=command.uri.strip(),
            summary=command.summary.strip(),
            generated_at=now,
        )
        engagement.status = "completed"
        for stage in engagement.stages:
            if stage.status != "completed":
                stage.status = "completed"
                if stage.started_at is None:
                    stage.started_at = now
                if stage.completed_at is None:
                    stage.completed_at = now
        self._repo.save(engagement)
        return deepcopy(engagement)
