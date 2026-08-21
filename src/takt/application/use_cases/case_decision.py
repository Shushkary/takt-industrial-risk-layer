from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from takt.domain.entities.case import Case, CaseDecisionRecord, CaseStatus
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.services.case_lifecycle import transition_case
from takt.domain.services.verdict_confidence import verdict_confidence


@dataclass(frozen=True, slots=True)
class CaseDecisionOutcome:
    """Итог решения по делу для наблюдаемости пути клиента.

    Отдаётся вызывающему слою, чтобы бизнес-метрики снимались в адаптере, а слой применения
    не зависел от инфраструктуры. Разрыв G-4 из ``docs/customer_value_map.md``: «стало ли
    лучше» измеряется временем до решения, а не задержкой конвейера.

    ``seconds_to_first_decision`` заполняется только у первого решения по делу — это и есть
    время, которое клиент называет «расследование заняло N». Последующие смены статуса
    измеряют уже работу над решённым делом и в этот показатель не входят.
    """

    case_id: str
    prev_status: str
    next_status: str
    verdict: str
    confidence_score: float
    confidence_grade: str
    first_decision: bool
    seconds_to_first_decision: float | None


def _seconds_to_decision(case: Case, decided_at: datetime) -> float | None:
    """Время от создания дела до решения. ``None``, если моменты несопоставимы."""
    created_at = case.created_at
    if created_at is None:
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if decided_at.tzinfo is None:
        decided_at = decided_at.replace(tzinfo=UTC)
    elapsed = (decided_at - created_at).total_seconds()
    return elapsed if elapsed >= 0.0 else None


class SubmitCaseDecisionUseCase:
    def __init__(self, repo: CaseRepositoryPort, baseline: ExpectedBehaviorPort) -> None:
        self._repo = repo
        self._baseline = baseline

    def execute(
        self,
        case_id: str,
        new_status: CaseStatus,
        clock: datetime,
        *,
        actor: str = "",
        reason: str = "",
        request_id: str = "",
    ) -> CaseDecisionOutcome:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id}")
        prev = case.status.value
        transition_case(case, new_status)
        case.decision_records.append(
            CaseDecisionRecord(
                ts=clock,
                actor=actor.strip() or "unknown",
                prev_status=prev,
                next_status=new_status.value,
                reason=reason.strip(),
                request_id=request_id.strip(),
            )
        )
        case.append_audit(f"status -> {new_status.value}", clock, actor=actor)
        if new_status == CaseStatus.EXPECTED_BEHAVIOR and case.primary_asset_id:
            self._baseline.mark_expected(case.primary_asset_id, case.trigger_operation)
            case.append_audit("baseline updated (EXPECTED_BEHAVIOR)", clock)
        self._repo.save(case)
        op_rec = getattr(self._repo, "record_operation_event", None)
        if callable(op_rec):
            op_rec(
                operation_type="decision",
                entity_id=case.case_id,
                actor=actor.strip() or "unknown",
                payload_json=json.dumps(
                    {
                        "case_id": case.case_id,
                        "prev_status": prev,
                        "next_status": new_status.value,
                        "reason": reason.strip(),
                        "request_id": request_id.strip(),
                        "ts": clock.isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                created_at=clock.isoformat(timespec="seconds"),
            )
        confidence = verdict_confidence(case)
        first_decision = len(case.decision_records) == 1
        return CaseDecisionOutcome(
            case_id=case.case_id,
            prev_status=prev,
            next_status=new_status.value,
            verdict=confidence.verdict,
            confidence_score=confidence.score,
            confidence_grade=confidence.grade,
            first_decision=first_decision,
            seconds_to_first_decision=_seconds_to_decision(case, clock) if first_decision else None,
        )
