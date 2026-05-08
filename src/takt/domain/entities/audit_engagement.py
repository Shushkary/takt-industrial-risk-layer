from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class AuditStage:
    code: str
    title: str
    day_range: str
    status: str = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    note: str = ""


@dataclass(slots=True)
class AuditFinalReport:
    title: str
    uri: str
    summary: str
    generated_at: datetime


@dataclass(slots=True)
class AuditEngagement:
    engagement_id: str
    created_at: datetime
    status: str
    customer: str
    scope: str
    case_ids: list[str] = field(default_factory=list)
    nda_signed: bool = False
    evidence_intake_checklist: list[str] = field(default_factory=list)
    stages: list[AuditStage] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    final_report: AuditFinalReport | None = None
