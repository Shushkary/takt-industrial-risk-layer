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
    MERGED = "MERGED"


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
class OrganizationalContextDocument:
    document_id: str
    document_type: str
    asset_id: str
    operation: str
    action_class: str
    executor: str
    approver: str
    valid_from: str
    valid_to: str
    document_status: str
    restrictions: str
    checksum_algorithm: str = "SHA-256"
    checksum: str = ""


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
    action_class: str = ""
    executor: str = ""
    approver: str = ""
    valid_from: str = ""
    valid_to: str = ""
    document_status: str = ""
    restrictions: str = ""
    organizational_context_sha256: str = ""
    note: str = ""

    def organizational_document(self) -> OrganizationalContextDocument:
        return OrganizationalContextDocument(
            document_id=self.work_order_number,
            document_type="ручной наряд",
            asset_id=self.asset_id,
            operation=self.operation,
            action_class=self.action_class,
            executor=self.executor,
            approver=self.approver,
            valid_from=self.valid_from,
            valid_to=self.valid_to,
            document_status=self.document_status,
            restrictions=self.restrictions,
            checksum=self.organizational_context_sha256,
        )


@dataclass(slots=True)
class CaseDecisionRecord:
    ts: datetime
    actor: str
    prev_status: str
    next_status: str
    reason: str
    request_id: str = ""


@dataclass(slots=True)
class FormalVerdictRecord:
    ts: datetime
    actor: str
    prev: str
    next: str
    score: float
    source: str
    permit_id: str = ""
    reason: str = ""


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
class CorrelationEvidence:
    event_id: str
    fingerprint: str
    rule: str
    fields: list[str] = field(default_factory=list)
    manual: bool = False
    reason: str = ""
    request_id: str = ""


@dataclass(slots=True)
class CaseArtifact:
    type: str
    value: str
    host_id: str = ""
    verification_status: str = "unverified"
    source: str = "manual"
    added_by: str = ""
    created_at: datetime | None = None


@dataclass(slots=True)
class Finding:
    finding_id: str
    text: str
    author: str
    created_at: datetime
    event_ids: list[str] = field(default_factory=list)
    artifacts: list[CaseArtifact] = field(default_factory=list)


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
    correlation_fingerprints: list[str] = field(default_factory=list)
    correlation_evidence: list[CorrelationEvidence] = field(default_factory=list)
    related_cases: list[str] = field(default_factory=list)
    artifacts: list[CaseArtifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    primary_asset_id: str = ""
    trigger_operation: str = ""
    operator_id: str = ""
    invariant_hits: list[str] = field(default_factory=list)
    invariant_hit_records: list[InvariantHitRecord] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    dq_score: float = 1.0
    dq_partial: bool = False
    dq_reasons: list[str] = field(default_factory=list)
    last_event_source: str = ""
    manual_permits: list[ManualPermit] = field(default_factory=list)
    formal_verdict_records: list[FormalVerdictRecord] = field(default_factory=list)
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
