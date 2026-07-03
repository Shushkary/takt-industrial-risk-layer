from __future__ import annotations

from pydantic import BaseModel, Field


class AuditEngagementCreateBody(BaseModel):
    customer: str = Field(min_length=1, max_length=256)
    scope: str = Field(min_length=1, max_length=5000)
    case_ids: list[str] = Field(default_factory=list, max_length=200)
    nda_signed: bool = False
    evidence_intake_checklist: list[str] = Field(default_factory=list, max_length=200)


class AuditStageOut(BaseModel):
    code: str
    title: str
    day_range: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    note: str = ""


class AuditFinalReportOut(BaseModel):
    title: str
    uri: str
    summary: str
    generated_at: str


class AuditEngagementOut(BaseModel):
    engagement_id: str
    created_at: str
    status: str
    customer: str
    scope: str
    case_ids: list[str]
    nda_signed: bool
    evidence_intake_checklist: list[str]
    stages: list[AuditStageOut]
    findings: list[str]
    final_report: AuditFinalReportOut | None = None


class AuditStageAdvanceBody(BaseModel):
    note: str = Field(default="", max_length=2000)


class AuditFindingBody(BaseModel):
    finding: str = Field(min_length=1, max_length=4000)


class AuditFinalizeReportBody(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    uri: str = Field(min_length=1, max_length=2000)
    summary: str = Field(default="", max_length=8000)


class AuditEngagementReportOut(BaseModel):
    format: str
    generated_at: str
    engagement: AuditEngagementOut
    findings_count: int
    stages_completed: int
    stages_total: int
    nda_signed: bool
    has_final_report: bool
