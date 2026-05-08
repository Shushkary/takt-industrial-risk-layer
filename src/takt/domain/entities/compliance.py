from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ComplianceReadinessFlag:
    code: str
    ok: bool
    value: int | float | str | bool
    threshold: int | float | str | bool


@dataclass(frozen=True, slots=True)
class ComplianceDataQualityReport:
    generated_at: datetime
    total_cases: int
    open_cases: int
    by_status: dict[str, int] = field(default_factory=dict)
    by_risk_class: dict[str, int] = field(default_factory=dict)
    avg_dq_score: float = 0.0
    dq_partial_count: int = 0
    dq_reasons: dict[str, int] = field(default_factory=dict)
    cases_without_manual_permit: int = 0
    cases_with_forensic_bundle_audit: int = 0
    high_risk_without_decision: int = 0
    false_positive_count: int = 0
    expected_behavior_count: int = 0
    invariant_hits: dict[str, int] = field(default_factory=dict)
    remediation_attempts_by_kind: dict[str, int] = field(default_factory=dict)
    remediation_attempts_by_status: dict[str, int] = field(default_factory=dict)
    readiness_flags: tuple[ComplianceReadinessFlag, ...] = ()


@dataclass(frozen=True, slots=True)
class ForensicReadinessCase:
    case_id: str
    status: str
    risk_class: str
    risk_score: float
    ready: bool
    missing: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ForensicReadinessReport:
    generated_at: datetime
    total_cases: int
    ready_cases: int
    not_ready_cases: int
    missing_by_code: dict[str, int] = field(default_factory=dict)
    cases: tuple[ForensicReadinessCase, ...] = ()


@dataclass(frozen=True, slots=True)
class CaseEvidenceChecklistItem:
    code: str
    ok: bool
    detail: str
    remediation_kind: str = ""
    remediation_action: str = ""
    remediation_attempted: bool = False
    latest_remediation_status: str = ""


@dataclass(frozen=True, slots=True)
class CaseEvidenceChecklist:
    generated_at: datetime
    case_id: str
    ready: bool
    remediation_summary: dict[str, int] = field(default_factory=dict)
    items: tuple[CaseEvidenceChecklistItem, ...] = ()
