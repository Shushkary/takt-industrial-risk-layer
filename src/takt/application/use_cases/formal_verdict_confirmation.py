from __future__ import annotations

import json
from dataclasses import dataclass

from takt.domain.entities.case import FormalVerdictRecord
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort
from takt.domain.services.forensic_verdict import case_forensic_verdict

_ALLOWED_FORMAL_VERDICTS = {"легитимное", "нелегитимное", "неопределённое"}


@dataclass(frozen=True, slots=True)
class ConfirmFormalVerdictCommand:
    case_id: str
    actor: str
    verdict: str
    confidence: float
    reason: str
    note: str = ""


class ConfirmFormalVerdictUseCase:
    """Фиксирует ручное подтверждение формального вердикта без активного управления объектом."""

    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort) -> None:
        self._repo = repo
        self._clock = clock

    def execute(self, cmd: ConfirmFormalVerdictCommand) -> FormalVerdictRecord:
        case = self._repo.get(cmd.case_id)
        if case is None:
            raise ValueError(f"unknown case {cmd.case_id}")
        verdict = cmd.verdict.strip().lower()
        if verdict not in _ALLOWED_FORMAL_VERDICTS:
            raise ValueError("formal verdict must be one of: легитимное, нелегитимное, неопределённое")
        if cmd.confidence < 0.0 or cmd.confidence > 1.0:
            raise ValueError("confidence must be between 0 and 1")
        reason = cmd.reason.strip()
        if not reason:
            raise ValueError("reason is required")
        actor = cmd.actor.strip() or "unknown"
        previous = case_forensic_verdict(case).value
        ts = self._clock.now_utc()
        record = FormalVerdictRecord(
            ts=ts,
            actor=actor,
            prev=previous,
            next=verdict,
            score=cmd.confidence,
            source="operator_confirmation",
            reason=reason,
        )
        case.formal_verdict_records.append(record)
        encoded_reason = _audit_value(reason)
        encoded_note = _audit_value(cmd.note.strip())
        case.append_audit(
            (
                "formal verdict change "
                f"prev={previous} next={verdict} score={cmd.confidence:.2f} "
                f"source=operator_confirmation permit_id=- reason={encoded_reason}"
            ),
            ts,
            actor=actor,
        )
        case.append_audit(
            f"operator action formal_verdict_confirmation reason={encoded_reason} note={encoded_note}",
            ts,
            actor=actor,
        )
        self._repo.save(case)
        op_rec = getattr(self._repo, "record_operation_event", None)
        if callable(op_rec):
            op_rec(
                operation_type="formal_verdict",
                entity_id=case.case_id,
                actor=actor,
                payload_json=json.dumps(
                    {
                        "case_id": case.case_id,
                        "prev": previous,
                        "next": verdict,
                        "score": cmd.confidence,
                        "reason": reason,
                        "note": cmd.note.strip(),
                        "ts": ts.isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                created_at=ts.isoformat(timespec="seconds"),
            )
        return record


def _audit_value(value: str) -> str:
    return value.replace(" ", "%20") if value else "-"
