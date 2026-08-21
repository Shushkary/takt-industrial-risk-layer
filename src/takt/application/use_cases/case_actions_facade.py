from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from takt.application.use_cases.formal_verdict_confirmation import ConfirmFormalVerdictCommand
from takt.application.use_cases.manual_permit import AttachManualPermitCommand
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort


@dataclass(frozen=True, slots=True)
class OperatorActionCommand:
    case_id: str
    action: str
    actor: str
    reason: str = ""
    note: str = ""


class CaseActionsFacade:
    def __init__(
        self,
        *,
        repo: CaseRepositoryPort,
        clock: SystemClockPort,
        manual_permit_uc: Any,
        formal_verdict_confirmation_uc: Any,
        decision_uc: Any,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._manual_permit_uc = manual_permit_uc
        self._formal_verdict_confirmation_uc = formal_verdict_confirmation_uc
        self._decision_uc = decision_uc

    def attach_manual_permit(self, cmd: AttachManualPermitCommand) -> Any:
        return self._manual_permit_uc.execute(cmd)

    def record_operator_action(self, cmd: OperatorActionCommand) -> dict[str, str]:
        case = self._repo.get(cmd.case_id)
        if case is None:
            raise ValueError("case not found")
        reason = cmd.reason.strip()
        note = cmd.note.strip()
        if cmd.action == "additional_review" and not reason:
            raise ValueError("reason is required")
        actor = cmd.actor.strip() or "unknown"
        encoded_reason = _audit_value(reason)
        encoded_note = _audit_value(note)
        ts = self._clock.now_utc()
        case.append_audit(
            f"operator action {cmd.action} reason={encoded_reason} note={encoded_note}",
            ts,
            actor=actor,
        )
        self._repo.save(case)
        op_rec = getattr(self._repo, "record_operation_event", None)
        if callable(op_rec):
            op_rec(
                operation_type="operator_action",
                entity_id=case.case_id,
                actor=actor,
                payload_json=json.dumps(
                    {
                        "case_id": case.case_id,
                        "action": cmd.action,
                        "reason": reason,
                        "note": note,
                        "ts": ts.isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                created_at=ts.isoformat(timespec="seconds"),
            )
        return {
            "case_id": cmd.case_id,
            "action": cmd.action,
            "actor": actor,
            "reason": reason,
            "note": note,
            "ts": ts.isoformat(timespec="seconds"),
        }

    def confirm_formal_verdict(self, cmd: ConfirmFormalVerdictCommand) -> Any:
        return self._formal_verdict_confirmation_uc.execute(cmd)

    def operator_action_history(self, case_id: str) -> dict[str, Any]:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError("case not found")
        entries = [entry for line in case.audit_log if (entry := _operator_action_entry(line)) is not None]
        return {"case_id": case_id, "entries": entries}

    def formal_verdict_history(self, case_id: str) -> tuple[Any, ...]:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError("case not found")
        if case.formal_verdict_records:
            return tuple(case.formal_verdict_records)
        return tuple(entry for line in case.audit_log if (entry := _formal_verdict_history_entry(line)) is not None)

    def submit_decision(
        self,
        *,
        case_id: str,
        status: Any,
        actor: str,
        reason: str,
        request_id: str,
    ) -> Any:
        return self._decision_uc.execute(
            case_id,
            status,
            self._clock.now_utc(),
            actor=actor,
            reason=reason,
            request_id=request_id,
        )


def _audit_value(value: str) -> str:
    return value.replace(" ", "%20") if value else "-"


def _operator_action_entry(line: str) -> dict[str, str] | None:
    parts = [chunk.strip() for chunk in line.split(" | ")]
    if len(parts) < 2 or not parts[1].startswith("operator action "):
        return None
    tokens = parts[1].split()
    if len(tokens) < 3:
        return None
    entry = {"ts": parts[0], "action": tokens[2], "reason": "", "note": "", "actor": ""}
    for token in tokens[3:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in entry:
            entry[key] = "" if value == "-" else value.replace("%20", " ")
    for part in parts[2:]:
        if part.startswith("actor="):
            entry["actor"] = part.split("=", 1)[1]
    return entry


def _formal_verdict_history_entry(line: str) -> dict[str, str] | None:
    parts = [chunk.strip() for chunk in line.split(" | ")]
    if len(parts) < 2 or not parts[1].startswith("formal verdict change "):
        return None
    fields: dict[str, str] = {}
    for token in parts[1].removeprefix("formal verdict change ").split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    actor = ""
    for part in parts[2:]:
        if part.startswith("actor="):
            actor = part.split("=", 1)[1]
    return {
        "ts": parts[0],
        "prev": fields.get("prev", ""),
        "next": fields.get("next", ""),
        "score": fields.get("score", ""),
        "source": fields.get("source", ""),
        "permit_id": fields.get("permit_id", ""),
        "actor": actor,
    }
