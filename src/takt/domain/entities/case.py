from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class CaseStatus(StrEnum):
    NEW = "NEW"
    TRIAGE = "TRIAGE"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXPECTED_BEHAVIOR = "EXPECTED_BEHAVIOR"


@dataclass(slots=True)
class Observation:
    """Наблюдение от канала данных (source) в рамках одного физического инцидента."""

    source: str
    ingest_trust: float
    event_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InvariantHitRecord:
    """Одно срабатывание инварианта с привязкой к событию и снимку DQ."""

    invariant_id: str
    event_ref: str
    ts: datetime
    score_contribution: float
    dq_score: float
    dq_partial: bool
    dq_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ManualPermit:
    permit_id: str
    case_id: str
    work_order_number: str
    actor: str
    created_at: datetime
    asset_id: str
    operation: str
    verdict: str
    confidence: float
    rationale: str
    counterfactual: str
    note: str = ""


@dataclass(slots=True)
class CaseDecisionRecord:
    ts: datetime
    actor: str
    prev_status: str
    next_status: str
    reason: str
    request_id: str = ""


@dataclass(slots=True)
class RemediationAttempt:
    attempt_id: str
    case_id: str
    kind: str
    status: str
    actor: str
    created_at: datetime
    action: str
    result: str
    readiness_before: bool | None = None
    readiness_after: bool | None = None
    note: str = ""
    request_id: str = ""


@dataclass(slots=True)
class RawEvidenceRef:
    """Reference to immutable raw evidence payload captured at ingest time."""

    evidence_id: str
    source: str
    media_type: str
    captured_at: datetime
    payload_b64: str
    sha256: str
    size_bytes: int
    event_id: str = ""
    note: str = ""


@dataclass(slots=True)
class Case:
    """Карточка инцидента (HITL)."""

    case_id: str
    status: CaseStatus
    title: str
    risk_class: str
    risk_score: float
    created_at: datetime
    normalized_event_ids: list[str] = field(default_factory=list)
    xai_summary: str = ""
    audit_log: list[str] = field(default_factory=list)
    burst_fingerprint: str = ""
    primary_asset_id: str = ""
    trigger_operation: str = ""
    invariant_hits: list[str] = field(default_factory=list)
    invariant_hit_records: list[InvariantHitRecord] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    dq_score: float = 1.0
    dq_partial: bool = False
    dq_reasons: list[str] = field(default_factory=list)
    last_event_source: str = ""
    manual_permits: list[ManualPermit] = field(default_factory=list)
    decision_records: list[CaseDecisionRecord] = field(default_factory=list)
    remediation_attempts: list[RemediationAttempt] = field(default_factory=list)
    raw_evidence_refs: list[RawEvidenceRef] = field(default_factory=list)
    pdf_last_sha256: str = ""
    pdf_last_generated_at: str = ""

    def append_audit(self, line: str, ts: datetime, *, actor: str = "") -> None:
        prefix = ts.isoformat(timespec="seconds")
        if actor:
            line = f"{line} | actor={actor}"
        self.audit_log.append(f"{prefix} | {line}")
