from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NamedTuple

from takt.domain.entities.case import FormalVerdictRecord, ManualPermit, VerdictCounterfactual
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort
from takt.domain.services.forensic_verdict import case_forensic_verdict


@dataclass(frozen=True, slots=True)
class AttachManualPermitCommand:
    case_id: str
    work_order_number: str
    actor: str
    asset_id: str = ""
    operation: str = ""
    action_class: str = ""
    executor: str = ""
    approver: str = ""
    valid_from: str = ""
    valid_to: str = ""
    document_status: str = ""
    restrictions: str = ""
    note: str = ""


class _PermitVerdict(NamedTuple):
    verdict: str
    confidence: float
    rationale: str
    counterfactual: str
    counterfactual_struct: dict[str, object]


_MISMATCH_TEXT = {
    "asset": "актив наряда {actual!r} не совпадает с активом дела {expected!r}",
    "operation": "операция наряда {actual!r} не совпадает с операцией дела {expected!r}",
    "action_class": "класс действия наряда {actual!r} не совпадает с классом действия дела {expected!r}",
    "executor": "исполнитель наряда {actual!r} не совпадает с исполнителем события {expected!r}",
}


def _mismatch_text(m: dict[str, str]) -> str:
    template = _MISMATCH_TEXT.get(
        m["field"],
        "{field} наряда {actual!r} не совпадает с {field} дела {expected!r}",
    )
    return template.format(field=m["field"], actual=m["actual"], expected=m["expected"])


class AttachManualPermitUseCase:
    """Прикрепляет введенный оператором наряд к делу и рассчитывает базовый вердикт легитимности."""

    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort, ids: IdProviderPort) -> None:
        self._repo = repo
        self._clock = clock
        self._ids = ids

    def execute(self, cmd: AttachManualPermitCommand) -> ManualPermit:
        case = self._repo.get(cmd.case_id)
        if case is None:
            raise ValueError(f"unknown case {cmd.case_id}")
        work_order = cmd.work_order_number.strip()
        if not work_order:
            raise ValueError("work_order_number is required")
        asset = cmd.asset_id.strip()
        operation = cmd.operation.strip().upper()
        action_class = cmd.action_class.strip() or _action_class(operation or case.trigger_operation)
        document_status = cmd.document_status.strip() or "не указан"
        restrictions = cmd.restrictions.strip()
        previous_formal_verdict = case_forensic_verdict(case).value
        verdict_result = self._verdict(
            case_asset=case.primary_asset_id,
            case_operation=case.trigger_operation,
            case_action_class=_action_class(case.trigger_operation),
            case_operator_id=case.operator_id,
            case_created_at=case.created_at,
            permit_asset=asset,
            permit_operation=operation,
            permit_action_class=action_class,
            executor=cmd.executor.strip(),
            approver=cmd.approver.strip(),
            valid_from=cmd.valid_from.strip(),
            valid_to=cmd.valid_to.strip(),
            document_status=document_status,
            restrictions=restrictions,
            work_order_number=work_order,
        )
        permit = ManualPermit(
            permit_id=self._ids.new_case_id_short(),
            case_id=case.case_id,
            work_order_number=work_order,
            actor=cmd.actor.strip() or "unknown",
            created_at=self._clock.now_utc(),
            asset_id=asset,
            operation=operation,
            verdict=verdict_result.verdict,
            confidence=verdict_result.confidence,
            rationale=verdict_result.rationale,
            counterfactual=verdict_result.counterfactual,
            counterfactual_struct=verdict_result.counterfactual_struct,
            action_class=action_class,
            executor=cmd.executor.strip(),
            approver=cmd.approver.strip(),
            valid_from=cmd.valid_from.strip(),
            valid_to=cmd.valid_to.strip(),
            document_status=document_status,
            restrictions=restrictions,
            organizational_context_sha256=_organizational_context_sha256(
                document_id=work_order,
                asset_id=asset,
                operation=operation,
                action_class=action_class,
                executor=cmd.executor.strip(),
                approver=cmd.approver.strip(),
                valid_from=cmd.valid_from.strip(),
                valid_to=cmd.valid_to.strip(),
                document_status=document_status,
                restrictions=restrictions,
            ),
            note=cmd.note.strip(),
        )
        case.manual_permits.append(permit)
        next_formal_verdict = case_forensic_verdict(case).value
        case.formal_verdict_records.append(
            FormalVerdictRecord(
                ts=permit.created_at,
                actor=permit.actor,
                prev=previous_formal_verdict,
                next=next_formal_verdict,
                score=verdict_result.confidence,
                source="manual_permit",
                permit_id=permit.permit_id,
                reason=verdict_result.rationale,
            )
        )
        case.append_audit(
            f"manual permit {work_order} attached verdict={verdict_result.verdict} confidence={verdict_result.confidence:.2f}",
            permit.created_at,
            actor=permit.actor,
        )
        case.append_audit(
            (
                "formal verdict change "
                f"prev={previous_formal_verdict} next={next_formal_verdict} "
                f"score={verdict_result.confidence:.2f} source=manual_permit permit_id={permit.permit_id}"
            ),
            permit.created_at,
            actor=permit.actor,
        )
        self._repo.save(case)
        op_rec = getattr(self._repo, "record_operation_event", None)
        if callable(op_rec):
            op_rec(
                operation_type="manual_permit",
                entity_id=case.case_id,
                actor=permit.actor,
                payload_json=json.dumps(
                    {
                        "case_id": case.case_id,
                        "permit_id": permit.permit_id,
                        "work_order_number": permit.work_order_number,
                        "asset_id": permit.asset_id,
                        "operation": permit.operation,
                        "verdict": permit.verdict,
                        "formal_verdict_prev": previous_formal_verdict,
                        "formal_verdict_next": next_formal_verdict,
                        "ts": permit.created_at.isoformat(timespec="seconds"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                created_at=permit.created_at.isoformat(timespec="seconds"),
            )
        return permit

    @staticmethod
    def _verdict(
        *,
        case_asset: str,
        case_operation: str,
        case_action_class: str,
        case_operator_id: str,
        case_created_at: datetime,
        permit_asset: str,
        permit_operation: str,
        permit_action_class: str = "",
        executor: str = "",
        approver: str = "",
        valid_from: str = "",
        valid_to: str = "",
        document_status: str = "",
        restrictions: str = "",
        work_order_number: str = "",
    ) -> _PermitVerdict:
        if not permit_asset and not permit_operation and not permit_action_class:
            # Наряд не привязан к активу/операции — сверка с делом невозможна.
            # Структура несёт только факты самого наряда (текста-объяснения нет).
            cf = VerdictCounterfactual(
                verdict="undetermined",
                asset=permit_asset or None,
                operation=permit_operation or None,
                action_class=permit_action_class or None,
                executor=executor or None,
                required_document=work_order_number or None,
            )
            return _PermitVerdict(
                verdict="undetermined",
                confidence=0.5,
                rationale="Наряд указан без привязки к активу и операции; сверка с делом невозможна.",
                counterfactual="Вывод стал бы легитимным при совпадении актива и операции наряда с делом.",
                counterfactual_struct=cf.to_dict(),
            )

        asset_ok = not permit_asset or permit_asset.strip().lower() == case_asset.strip().lower()
        op_ok = not permit_operation or permit_operation.strip().upper() == case_operation.strip().upper()
        class_ok = not permit_action_class or permit_action_class.strip().lower() == case_action_class.strip().lower()
        executor_ok = not (case_operator_id and executor) or executor.strip().lower() == case_operator_id.strip().lower()
        status_ok = document_status.strip().lower() in {
            "",
            "не указан",
            "active",
            "approved",
            "действует",
            "утвержден",
            "утверждён",
        }
        window_ok, window_reason = _window_contains(case_created_at, valid_from, valid_to)
        org_context_complete = bool(
            executor and approver and valid_from and valid_to and status_ok and window_ok and not restrictions
        )

        if asset_ok and op_ok and class_ok and executor_ok and org_context_complete:
            admissible_window = f"{valid_from}..{valid_to}" if (valid_from and valid_to) else None
            cf = VerdictCounterfactual(
                verdict="legitimate",
                asset=permit_asset or None,
                operation=permit_operation or None,
                action_class=permit_action_class or None,
                executor=executor or None,
                sanctioning_party=approver or None,
                admissible_window=admissible_window,
                required_document=work_order_number or None,
            )
            return _PermitVerdict(
                verdict="legitimate",
                confidence=0.95,
                rationale=(
                    "Актив, операция, исполнитель, утверждающий, окно работ и статус наряда "
                    "совпадают с делом либо не противоречат ему."
                ),
                counterfactual=(
                    "Вывод стал бы нелегитимным при расхождении актива, операции, исполнителя, "
                    "окна работ, утверждающего или при наличии ограничений."
                ),
                counterfactual_struct=cf.to_dict(),
            )

        if asset_ok and op_ok and class_ok and executor_ok:
            # Актив/операция/исполнитель совпали, но не хватает организационного контекста.
            # Структура = список конкретно не выполненных условий; текст строится из неё.
            unmet: list[str] = []
            if not executor:
                unmet.append("исполнитель")
            if not approver:
                unmet.append("утверждающий")
            if not valid_from or not valid_to:
                unmet.append("окно работ")
            elif not window_ok:
                unmet.append(window_reason)
            if not status_ok:
                unmet.append("действующий статус документа")
            if restrictions:
                unmet.append("отсутствие ограничений")
            if valid_from and valid_to and not window_ok:
                admissible_window = window_reason
            elif valid_from and valid_to:
                admissible_window = f"{valid_from}..{valid_to}"
            else:
                admissible_window = None
            cf = VerdictCounterfactual(
                verdict="undetermined",
                unmet_conditions=tuple(unmet),
                asset=permit_asset or None,
                operation=permit_operation or None,
                action_class=permit_action_class or None,
                executor=executor or None,
                sanctioning_party=approver or None,
                admissible_window=admissible_window,
                required_document=work_order_number or None,
                restrictions_present=restrictions or None,
            )
            rationale = "Актив и операция совпадают, но организационный контекст неполный: " + ", ".join(unmet) + "."
            counterfactual = "Вывод стал бы легитимным при полном наряде с " + ", ".join(unmet) + "."
            return _PermitVerdict(
                verdict="undetermined",
                confidence=0.7,
                rationale=rationale,
                counterfactual=counterfactual,
                counterfactual_struct=cf.to_dict(),
            )

        # Несовпадение с делом — расхождения по конкретным полям.
        mismatches: list[dict[str, str]] = []
        if not asset_ok:
            mismatches.append({"field": "asset", "expected": case_asset or "", "actual": permit_asset})
        if not op_ok:
            mismatches.append({"field": "operation", "expected": case_operation or "", "actual": permit_operation})
        if not class_ok:
            mismatches.append({"field": "action_class", "expected": case_action_class or "", "actual": permit_action_class})
        if not executor_ok:
            mismatches.append({"field": "executor", "expected": case_operator_id or "", "actual": executor})
        cf = VerdictCounterfactual(
            verdict="illegitimate",
            mismatches=tuple(mismatches),
            asset=permit_asset or None,
            operation=permit_operation or None,
            action_class=permit_action_class or None,
            executor=executor or None,
            required_document=work_order_number or None,
        )
        mismatch_texts = [_mismatch_text(m) for m in mismatches]
        rationale = "; ".join(mismatch_texts)
        counterfactual = "Вывод стал бы легитимным при совпадении актива и операции наряда с делом."
        return _PermitVerdict(
            verdict="illegitimate",
            confidence=0.65,
            rationale=rationale,
            counterfactual=counterfactual,
            counterfactual_struct=cf.to_dict(),
        )


def _parse_dt(raw: str) -> datetime | None:
    if not raw.strip():
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _window_contains(case_created_at: datetime, valid_from: str, valid_to: str) -> tuple[bool, str]:
    start = _parse_dt(valid_from)
    end = _parse_dt(valid_to)
    if start is None or end is None:
        return False, "окно работ не распознано"
    case_ts = case_created_at
    if case_ts.tzinfo is None:
        case_ts = case_ts.replace(tzinfo=UTC)
    case_ts = case_ts.astimezone(UTC)
    if start > end:
        return False, "начало окна работ позже окончания"
    if not (start <= case_ts <= end):
        return False, "событие вне окна работ"
    return True, ""


def _action_class(operation: str) -> str:
    op = operation.strip().upper()
    if any(token in op for token in ("WRITE", "COIL", "SET", "START", "STOP", "RESET", "OPEN", "CLOSE")):
        return "управляющее воздействие"
    if any(token in op for token in ("ADMIN", "LOGIN", "USER", "CONFIG", "FIRMWARE")):
        return "администрирование"
    if any(token in op for token in ("READ", "POLL", "GET", "STATUS")):
        return "чтение/опрос"
    if any(token in op for token in ("NETFLOW", "IPFIX", "PING", "SNMP", "SYSLOG")):
        return "сетевое событие"
    return "общее действие"


def _organizational_context_sha256(
    *,
    document_id: str,
    asset_id: str,
    operation: str,
    action_class: str,
    executor: str,
    approver: str,
    valid_from: str,
    valid_to: str,
    document_status: str,
    restrictions: str,
) -> str:
    payload = {
        "document_id": document_id,
        "document_type": "ручной наряд",
        "asset_id": asset_id,
        "operation": operation,
        "action_class": action_class,
        "executor": executor,
        "approver": approver,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "document_status": document_status,
        "restrictions": restrictions,
    }
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
