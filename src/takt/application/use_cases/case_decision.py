from __future__ import annotations

import json
from datetime import datetime

from takt.domain.entities.case import CaseDecisionRecord, CaseStatus
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.services.case_lifecycle import transition_case


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
    ) -> None:
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
