from __future__ import annotations

from dataclasses import dataclass

from takt.domain.entities.case import ManualPermit
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


@dataclass(frozen=True, slots=True)
class AttachManualPermitCommand:
    case_id: str
    work_order_number: str
    actor: str
    asset_id: str = ""
    operation: str = ""
    note: str = ""


class AttachManualPermitUseCase:
    """Attach an operator-entered work permit to a Risk Case and compute a basic legitimacy verdict."""

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
        verdict, confidence, rationale, counterfactual = self._verdict(
            case_asset=case.primary_asset_id,
            case_operation=case.trigger_operation,
            permit_asset=asset,
            permit_operation=operation,
        )
        permit = ManualPermit(
            permit_id=self._ids.new_case_id_short(),
            case_id=case.case_id,
            work_order_number=work_order,
            actor=cmd.actor.strip() or "unknown",
            created_at=self._clock.now_utc(),
            asset_id=asset,
            operation=operation,
            verdict=verdict,
            confidence=confidence,
            rationale=rationale,
            counterfactual=counterfactual,
            note=cmd.note.strip(),
        )
        case.manual_permits.append(permit)
        case.append_audit(
            f"manual permit {work_order} attached verdict={verdict} confidence={confidence:.2f}",
            permit.created_at,
            actor=permit.actor,
        )
        self._repo.save(case)
        return permit

    @staticmethod
    def _verdict(
        *,
        case_asset: str,
        case_operation: str,
        permit_asset: str,
        permit_operation: str,
    ) -> tuple[str, float, str, str]:
        if not permit_asset and not permit_operation:
            return (
                "undetermined",
                0.5,
                "Наряд указан без привязки к активу и операции; сверка с кейсом невозможна.",
                "Вывод стал бы легитимным при совпадении актива и операции наряда с Risk Case.",
            )
        asset_ok = not permit_asset or permit_asset.strip().lower() == case_asset.strip().lower()
        op_ok = not permit_operation or permit_operation.strip().upper() == case_operation.strip().upper()
        if asset_ok and op_ok:
            return (
                "legitimate",
                0.85,
                "Актив и операция наряда совпадают с Risk Case либо не противоречат ему.",
                "Вывод стал бы нелегитимным при расхождении актива или операции с Risk Case.",
            )
        mismatches: list[str] = []
        if not asset_ok:
            mismatches.append(f"актив наряда {permit_asset!r} не совпадает с активом кейса {case_asset!r}")
        if not op_ok:
            mismatches.append(f"операция наряда {permit_operation!r} не совпадает с операцией кейса {case_operation!r}")
        return (
            "illegitimate",
            0.65,
            "; ".join(mismatches),
            "Вывод стал бы легитимным при совпадении актива и операции наряда с Risk Case.",
        )
