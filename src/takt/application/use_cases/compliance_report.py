from __future__ import annotations

from collections import Counter

from takt.domain.entities.case import Case, CaseStatus, RemediationAttempt
from takt.domain.entities.compliance import (
    CaseEvidenceChecklist,
    CaseEvidenceChecklistItem,
    ComplianceDataQualityReport,
    ComplianceReadinessFlag,
    ForensicReadinessCase,
    ForensicReadinessReport,
)
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort

FORENSIC_READINESS_MISSING_CODES = frozenset(
    {
        "complete_observability",
        "invariant_evidence",
        "hitl_decision",
        "manual_permit",
        "forensic_bundle_audit",
    }
)

REMEDIATION_KIND_DESCRIPTIONS: dict[str, str] = {
    "attach_manual_permit": "Прикрепить ручной наряд к делу.",
    "generate_forensic_bundle": "Сформировать доказательный ZIP-пакет и записать корневой хэш в аудиторский след.",
    "ingest_telemetry": "Загрузить дополнительную доверенную телеметрию для закрытия частичной наблюдаемости.",
    "rerun_assessment": "Повторить оценку при наличии доказательств по инвариантам.",
    "submit_decision": "Зафиксировать решение оператора с обязательным основанием.",
}


class BuildComplianceDataQualityReportUseCase:
    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort) -> None:
        self._repo = repo
        self._clock = clock

    def execute(self) -> ComplianceDataQualityReport:
        cases = list(self._repo.list_all())
        total = len(cases)
        by_status = Counter(c.status.value for c in cases)
        by_risk_class = Counter(c.risk_class.upper() for c in cases)
        dq_reasons = Counter(reason for c in cases for reason in c.dq_reasons)
        invariant_hits = Counter(hit for c in cases for hit in c.invariant_hits)
        remediation_by_kind = Counter(attempt.kind for c in cases for attempt in c.remediation_attempts)
        remediation_by_status = Counter(attempt.status for c in cases for attempt in c.remediation_attempts)
        avg_dq = sum(c.dq_score for c in cases) / total if total else 0.0
        high_risk_without_decision = sum(1 for c in cases if _is_high_risk(c) and not c.decision_records)
        forensic_ready = sum(1 for c in cases if _has_forensic_bundle_audit(c))
        without_manual_permit = sum(1 for c in cases if not c.manual_permits)
        dq_partial = sum(1 for c in cases if c.dq_partial)

        return ComplianceDataQualityReport(
            generated_at=self._clock.now_utc(),
            total_cases=total,
            open_cases=sum(1 for c in cases if c.status in (CaseStatus.NEW, CaseStatus.TRIAGE)),
            by_status=dict(sorted(by_status.items())),
            by_risk_class=dict(sorted(by_risk_class.items())),
            avg_dq_score=avg_dq,
            dq_partial_count=dq_partial,
            dq_reasons=dict(sorted(dq_reasons.items())),
            cases_without_manual_permit=without_manual_permit,
            cases_with_forensic_bundle_audit=forensic_ready,
            high_risk_without_decision=high_risk_without_decision,
            false_positive_count=by_status.get(CaseStatus.FALSE_POSITIVE.value, 0),
            expected_behavior_count=by_status.get(CaseStatus.EXPECTED_BEHAVIOR.value, 0),
            invariant_hits=dict(sorted(invariant_hits.items())),
            remediation_attempts_by_kind=dict(sorted(remediation_by_kind.items())),
            remediation_attempts_by_status=dict(sorted(remediation_by_status.items())),
            readiness_flags=(
                ComplianceReadinessFlag(
                    code="dq_avg_at_least_0_80",
                    ok=avg_dq >= 0.80 or total == 0,
                    value=round(avg_dq, 4),
                    threshold=0.80,
                ),
                ComplianceReadinessFlag(
                    code="no_partial_observability",
                    ok=dq_partial == 0,
                    value=dq_partial,
                    threshold=0,
                ),
                ComplianceReadinessFlag(
                    code="high_risk_has_hitl_decision",
                    ok=high_risk_without_decision == 0,
                    value=high_risk_without_decision,
                    threshold=0,
                ),
                ComplianceReadinessFlag(
                    code="forensic_bundle_generated_for_all_cases",
                    ok=forensic_ready == total,
                    value=forensic_ready,
                    threshold=total,
                ),
            ),
        )


class BuildForensicReadinessReportUseCase:
    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort) -> None:
        self._repo = repo
        self._clock = clock

    def execute(self, *, only_not_ready: bool = False, missing_code: str = "") -> ForensicReadinessReport:
        items = tuple(_forensic_readiness_case(c) for c in self._repo.list_all())
        ready = sum(1 for item in items if item.ready)
        missing_by_code = Counter(code for item in items for code in item.missing)
        out_items = items
        if only_not_ready:
            out_items = tuple(item for item in out_items if not item.ready)
        code = missing_code.strip()
        if code:
            if code not in FORENSIC_READINESS_MISSING_CODES:
                allowed = ", ".join(sorted(FORENSIC_READINESS_MISSING_CODES))
                raise ValueError(f"invalid missing_code; use one of: {allowed}")
            out_items = tuple(item for item in out_items if code in item.missing)
        return ForensicReadinessReport(
            generated_at=self._clock.now_utc(),
            total_cases=len(items),
            ready_cases=ready,
            not_ready_cases=len(items) - ready,
            missing_by_code=dict(sorted(missing_by_code.items())),
            cases=tuple(sorted(out_items, key=lambda item: (item.ready, item.case_id))),
        )


class BuildCaseEvidenceChecklistUseCase:
    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort) -> None:
        self._repo = repo
        self._clock = clock

    def execute(self, case_id: str) -> CaseEvidenceChecklist:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id}")
        latest_attempt_by_kind = _latest_remediation_attempt_by_kind(case)
        items = tuple(
            _with_remediation_attempt(item, latest_attempt_by_kind)
            for item in (
                CaseEvidenceChecklistItem(
                    code="complete_observability",
                    ok=not case.dq_partial,
                    detail="dq_partial=false" if not case.dq_partial else "dq_partial=true",
                    remediation_kind="ingest_telemetry" if case.dq_partial else "",
                    remediation_action="загрузить дополнительную доверенную телеметрию по затронутому активу"
                    if case.dq_partial
                    else "",
                ),
                CaseEvidenceChecklistItem(
                    code="invariant_evidence",
                    ok=bool(case.invariant_hits),
                    detail=f"invariant_hits={len(case.invariant_hits)}",
                    remediation_kind="rerun_assessment" if not case.invariant_hits else "",
                    remediation_action="повторить оценку с доказательствами по инвариантам перед экспортом пакета"
                    if not case.invariant_hits
                    else "",
                ),
                CaseEvidenceChecklistItem(
                    code="hitl_decision",
                    ok=(not _is_high_risk(case)) or bool(case.decision_records),
                    detail=f"decision_records={len(case.decision_records)}",
                    remediation_kind="submit_decision" if _is_high_risk(case) and not case.decision_records else "",
                    remediation_action=f"POST /cases/{case.case_id}/decision с основанием оператора"
                    if _is_high_risk(case) and not case.decision_records
                    else "",
                ),
                CaseEvidenceChecklistItem(
                    code="manual_permit",
                    ok=bool(case.manual_permits),
                    detail=f"manual_permits={len(case.manual_permits)}",
                    remediation_kind="attach_manual_permit" if not case.manual_permits else "",
                    remediation_action=f"POST /cases/{case.case_id}/manual-permits с номером наряда"
                    if not case.manual_permits
                    else "",
                ),
                CaseEvidenceChecklistItem(
                    code="forensic_bundle_audit",
                    ok=_has_forensic_bundle_audit(case),
                    detail="аудиторский след содержит корневой хэш доказательного пакета"
                    if _has_forensic_bundle_audit(case)
                    else "в аудиторском следе нет корневого хэша доказательного пакета",
                    remediation_kind="generate_forensic_bundle" if not _has_forensic_bundle_audit(case) else "",
                    remediation_action=f"GET /cases/{case.case_id}/forensic-bundle.zip"
                    if not _has_forensic_bundle_audit(case)
                    else "",
                ),
            )
        )
        return CaseEvidenceChecklist(
            generated_at=self._clock.now_utc(),
            case_id=case.case_id,
            ready=all(item.ok for item in items),
            remediation_summary=dict(
                sorted(Counter(item.remediation_kind for item in items if item.remediation_kind).items())
            ),
            items=items,
        )


def _forensic_readiness_case(case: Case) -> ForensicReadinessCase:
    missing: list[str] = []
    if case.dq_partial:
        missing.append("complete_observability")
    if not case.invariant_hits:
        missing.append("invariant_evidence")
    if _is_high_risk(case) and not case.decision_records:
        missing.append("hitl_decision")
    if not case.manual_permits:
        missing.append("manual_permit")
    if not _has_forensic_bundle_audit(case):
        missing.append("forensic_bundle_audit")
    return ForensicReadinessCase(
        case_id=case.case_id,
        status=case.status.value,
        risk_class=case.risk_class,
        risk_score=case.risk_score,
        ready=not missing,
        missing=tuple(missing),
    )


def _is_high_risk(case: Case) -> bool:
    return case.risk_class.upper() in {"HIGH", "CRITICAL"} or case.risk_score >= 0.75


def _has_forensic_bundle_audit(case: Case) -> bool:
    return any("forensic bundle generated root_hash=" in line for line in case.audit_log)


def _latest_remediation_attempt_by_kind(case: Case) -> dict[str, RemediationAttempt]:
    latest: dict[str, RemediationAttempt] = {}
    for attempt in case.remediation_attempts:
        if not attempt.kind:
            continue
        current = latest.get(attempt.kind)
        if current is None or attempt.created_at > current.created_at:
            latest[attempt.kind] = attempt
    return latest


def _with_remediation_attempt(
    item: CaseEvidenceChecklistItem,
    latest_attempt_by_kind: dict[str, RemediationAttempt],
) -> CaseEvidenceChecklistItem:
    attempt = latest_attempt_by_kind.get(item.remediation_kind) if item.remediation_kind else None
    if attempt is None:
        return item
    return CaseEvidenceChecklistItem(
        code=item.code,
        ok=item.ok,
        detail=item.detail,
        remediation_kind=item.remediation_kind,
        remediation_action=item.remediation_action,
        remediation_attempted=True,
        latest_remediation_status=attempt.status,
    )
