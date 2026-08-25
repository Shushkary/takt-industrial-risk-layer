from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

_EXPORT_FULL_MAX = 10_000


class InvariantHitDetail(BaseModel):
    id: str
    title_ru: str


class ObservationDetail(BaseModel):
    source: str
    ingest_trust: float
    event_ids: list[str]


class CorrelationEvidenceDetail(BaseModel):
    event_id: str
    fingerprint: str
    rule: str
    fields: list[str] = Field(default_factory=list)
    manual: bool = False
    reason: str = ""
    request_id: str = ""


class CaseArtifactDetail(BaseModel):
    type: str
    value: str
    host_id: str = ""
    verification_status: str = "unverified"
    source: str = "manual"
    added_by: str = ""
    created_at: str | None = None


class FindingDetail(BaseModel):
    finding_id: str
    text: str
    author: str
    created_at: str
    event_ids: list[str] = Field(default_factory=list)
    artifacts: list[CaseArtifactDetail] = Field(default_factory=list)


class InvariantHitRecordDetail(BaseModel):
    invariant_id: str
    event_ref: str
    ts: str
    score_contribution: float
    dq_score: float
    dq_partial: bool
    dq_reasons: list[str]


class ManualPermitDetail(BaseModel):
    permit_id: str
    case_id: str
    work_order_number: str
    actor: str
    created_at: str
    asset_id: str = ""
    operation: str = ""
    action_class: str = ""
    verdict: str = "undetermined"
    confidence: float = 0.5
    rationale: str = ""
    counterfactual: str = ""
    executor: str = ""
    approver: str = ""
    valid_from: str = ""
    valid_to: str = ""
    document_status: str = ""
    restrictions: str = ""
    organizational_context_sha256: str = ""
    note: str = ""


class CaseDecisionRecordDetail(BaseModel):
    ts: str
    actor: str
    prev_status: str
    next_status: str
    reason: str = ""
    request_id: str = ""


class FormalVerdictRecordDetail(BaseModel):
    ts: str
    actor: str
    prev: str
    next: str
    score: float
    source: str
    permit_id: str = ""
    reason: str = ""


class ContextMatchDetail(BaseModel):
    matched: bool
    score: float
    reasons: list[str] = Field(default_factory=list)
    source: str = ""


class CaseForensicVerdictDetail(BaseModel):
    value: str
    source: str
    context_match: ContextMatchDetail
    counterfactual: str = ""


class ConfidenceComponentDetail(BaseModel):
    key: str
    title_ru: str
    value: float
    weight: float
    contribution: float
    reasons: list[str] = Field(default_factory=list)


class MissingContextItemDetail(BaseModel):
    """Чего не хватает, чтобы снять неопределённость, и где это взять."""

    kind: str
    text: str
    required_document: str | None = None
    sanctioning_party: str | None = None
    admissible_window: str | None = None


class VerdictConfidenceDetail(BaseModel):
    """Обоснованность вывода: одна величина, её разложение и маршрут добора контекста.

    `missing` непуст ровно тогда, когда `verdict` = `UNDET`.
    """

    verdict: str
    score: float
    grade: str
    components: list[ConfidenceComponentDetail] = Field(default_factory=list)
    missing: list[MissingContextItemDetail] = Field(default_factory=list)


class EvidenceSummaryDetail(BaseModel):
    raw_evidence_count: int
    organizational_documents: int
    audit_entries: int
    forensic_bundle_exported: bool


class BriefDecisionDetail(BaseModel):
    ts: str
    actor: str
    prev_status: str
    next_status: str
    reason: str = ""


class BriefMeasureDetail(BaseModel):
    kind: str
    status: str
    action: str = ""
    result: str = ""
    actor: str = ""


class DecisionBriefDetail(BaseModel):
    """Сводка для лица, принимающего решение: что произошло, чему верить, чем подтверждено, чего не хватает."""

    case_id: str
    title: str
    status: str
    created_at: str
    risk_class: str
    risk_score: float
    verdict: str
    verdict_value: str
    confidence_score: float
    confidence_grade: str
    invariants: list[str] = Field(default_factory=list)
    explanation: str = ""
    evidence: EvidenceSummaryDetail
    missing: list[MissingContextItemDetail] = Field(default_factory=list)
    measures: list[BriefMeasureDetail] = Field(default_factory=list)
    last_decision: BriefDecisionDetail | None = None
    boundary_note: str


class RemediationAttemptDetail(BaseModel):
    attempt_id: str
    case_id: str
    kind: str
    status: str
    actor: str
    created_at: str
    action: str = ""
    result: str = ""
    readiness_before: bool | None = None
    readiness_after: bool | None = None
    note: str = ""
    request_id: str = ""


class AssessResponse(BaseModel):
    risk_score: float
    risk_class: str
    invariant_hits: list[str]
    invariant_details: list[InvariantHitDetail]
    xai_what: str
    xai_why: str
    case_id: str
    dq_score: float
    dq_partial: bool
    merged_into_existing: bool


class CaseSummary(BaseModel):
    case_id: str
    status: str
    title: str
    risk_class: str
    risk_score: float
    fingerprint: str
    primary_asset_id: str
    trigger_operation: str
    operator_id: str = ""
    last_event_source: str
    invariant_hits_count: int
    event_count: int
    created_at: str
    dq_score: float
    dq_partial: bool


class CaseDetail(BaseModel):
    case_id: str
    status: str
    title: str
    risk_class: str
    risk_score: float
    event_ids: list[str]
    invariant_hits: list[str]
    invariant_details: list[InvariantHitDetail]
    observations: list[ObservationDetail] = Field(default_factory=list)
    correlation_fingerprints: list[str] = Field(default_factory=list)
    correlation_evidence: list[CorrelationEvidenceDetail] = Field(default_factory=list)
    related_cases: list[str] = Field(default_factory=list)
    artifacts: list[CaseArtifactDetail] = Field(default_factory=list)
    findings: list[FindingDetail] = Field(default_factory=list)
    manual_permits: list[ManualPermitDetail] = Field(default_factory=list)
    formal_verdict: CaseForensicVerdictDetail | None = None
    verdict_confidence: VerdictConfidenceDetail | None = None
    formal_verdict_records: list[FormalVerdictRecordDetail] = Field(default_factory=list)
    decision_records: list[CaseDecisionRecordDetail] = Field(default_factory=list)
    remediation_attempts: list[RemediationAttemptDetail] = Field(default_factory=list)
    invariant_hit_records: list[InvariantHitRecordDetail] = Field(default_factory=list)
    xai_summary: str
    audit_log: list[str]
    fingerprint: str
    primary_asset_id: str
    trigger_operation: str
    operator_id: str = ""
    last_event_source: str
    created_at: str
    dq_score: float
    dq_partial: bool
    dq_reasons: list[str]
    allowed_status_transitions: list[str] = Field(default_factory=list)
    pdf_last_sha256: str = ""
    pdf_last_generated_at: str = ""


class CasesFullExportResponse(BaseModel):
    exported_at: str
    count: int
    total_in_repo: int
    offset: int = 0
    limit: int | None = None
    cases: list[CaseDetail]


class CasesImportBody(BaseModel):
    cases: list[CaseDetail] = Field(
        max_length=_EXPORT_FULL_MAX,
        description=f"Карточки в формате выгрузки (не более {_EXPORT_FULL_MAX}).",
    )
    mode: Literal["upsert", "skip_existing"] = Field(
        default="upsert",
        description="upsert - запись/перезапись по case_id; skip_existing - пропуск уже существующих.",
    )


class CasesImportResponse(BaseModel):
    imported: int
    skipped: int
    mode: str


class CasesStatsResponse(BaseModel):
    total: int
    open: int
    by_status: dict[str, int]
    by_risk_class: dict[str, int]
    avg_risk_score: float
    avg_dq_score: float
    dq_partial_count: int
    normalized_events_total: int
    distinct_invariant_hits: int
    invariant_hits_occurrences_total: int
    by_last_event_source: dict[str, int]


class CaseGroupOut(BaseModel):
    """Однотипные дела одной строкой очереди.

    Группировка — способ показа, а не сборки: ни одно дело при этом не меняется и не
    сливается с другим. Нужна потому, что собственная дедупликация продукта работает по
    `burst_fingerprint` с корзиной времени и не сводит одинаковые срабатывания, попавшие в
    разные минуты.
    """

    key: str
    primary_asset_id: str
    """Актив группы; пустой в разрезе по операции, когда активов несколько."""

    assets: int
    """Сколько различных активов попало в группу."""

    trigger_operation: str
    risk_class: str
    cases: int
    events: int
    max_risk_score: float
    top_case_id: str
    first_created_at: str
    last_created_at: str
    by_status: dict[str, int]
