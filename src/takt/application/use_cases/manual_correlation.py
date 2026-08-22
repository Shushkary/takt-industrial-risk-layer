from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime

from takt.application.system_defaults import default_id_provider
from takt.domain.entities.case import Case, CaseStatus, CorrelationEvidence
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort


@dataclass(frozen=True, slots=True)
class ManualCorrelationCommand:
    case_id: str
    reason: str
    actor: str
    request_id: str = ""
    event_id: str = ""
    source_case_id: str = ""
    event_ids: tuple[str, ...] = ()


class ManualCorrelationUseCase:
    def __init__(self, repo: CaseRepositoryPort, ids: IdProviderPort = default_id_provider) -> None:
        self._repo = repo
        self._ids = ids

    @staticmethod
    def _validate(cmd: ManualCorrelationCommand) -> str:
        reason = cmd.reason.strip()
        if not reason:
            raise ValueError("reason is required")
        return reason

    def _case(self, case_id: str) -> Case:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case: {case_id}")
        return case

    @staticmethod
    def _already_applied(case: Case, request_id: str) -> bool:
        rid = request_id.strip()
        return bool(rid) and any(item.manual and item.request_id == rid for item in case.correlation_evidence)

    @staticmethod
    def _carried_evidence(
        source: Case, *, keep: set[str], covered: set[str], action: str
    ) -> list[CorrelationEvidence]:
        """Записи об отборе, переносимые вместе с событиями в другой кейс.

        Без переноса кейс после объединения или разделения не мог ответить, чем было отобрано
        событие: механизм оставался записанным в исходном кейсе, а на вкладке цепочки все
        перенесённые события выглядели как «основание не записано».

        Переносятся только записи о событиях, которые действительно оказались в кейсе-приёмнике
        и ещё не имеют там собственной записи. Записи уровня кейса (объединение, разделение)
        описывают операции над исходным кейсом и не переносятся.

        Идентификатор запроса при переносе снимается: это ключ идемпотентности команды к
        конкретному кейсу, и в чужом кейсе он заставил бы `_already_applied` считать
        применённой команду, которой там не было.
        """
        carried: list[CorrelationEvidence] = []
        for item in source.correlation_evidence:
            if not item.event_id or item.event_id not in keep or item.event_id in covered:
                continue
            origin = f"перенесено при {action} из кейса {source.case_id}"
            moved = deepcopy(item)
            moved.reason = f"{origin}: {item.reason}" if item.reason else origin
            moved.request_id = ""
            carried.append(moved)
        return carried

    @staticmethod
    def _recalculate(case: Case) -> None:
        remaining = set(case.normalized_event_ids)
        case.invariant_hit_records = [item for item in case.invariant_hit_records if item.event_ref in remaining]
        case.invariant_hits = sorted({item.invariant_id for item in case.invariant_hit_records})
        case.risk_score = max((item.score_contribution for item in case.invariant_hit_records), default=0.0)

    def _save_with_audit(self, case: Case, *, action: str, cmd: ManualCorrelationCommand, clock: datetime) -> None:
        case.append_audit(f"manual correlation {action}: {cmd.reason.strip()}", clock, actor=cmd.actor)
        self._repo.save(case)
        record = getattr(self._repo, "record_operation_event", None)
        if callable(record):
            record(
                operation_type=f"correlation.{action}", entity_id=case.case_id,
                actor=cmd.actor,
                payload_json=json.dumps({"reason": cmd.reason.strip(), "request_id": cmd.request_id}),
                created_at=clock.isoformat(),
            )

    def detach(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        case = self._case(cmd.case_id)
        if self._already_applied(case, cmd.request_id):
            return case
        if cmd.event_id not in case.normalized_event_ids:
            raise ValueError(f"event is not attached: {cmd.event_id}")
        case.normalized_event_ids = [item for item in case.normalized_event_ids if item != cmd.event_id]
        for observation in case.observations:
            observation.event_ids = [item for item in observation.event_ids if item != cmd.event_id]
        case.observations = [item for item in case.observations if item.event_ids]
        case.correlation_evidence.append(CorrelationEvidence(
            event_id=cmd.event_id, fingerprint="", rule="manual_detach", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        ))
        self._recalculate(case)
        self._save_with_audit(case, action="detach", cmd=cmd, clock=clock)
        return case

    def attach(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        case = self._case(cmd.case_id)
        if self._already_applied(case, cmd.request_id) or cmd.event_id in case.normalized_event_ids:
            return case
        case.normalized_event_ids.append(cmd.event_id)
        case.correlation_evidence.append(CorrelationEvidence(
            event_id=cmd.event_id, fingerprint="", rule="manual_attach", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        ))
        self._save_with_audit(case, action="attach", cmd=cmd, clock=clock)
        return case

    def merge(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        target = self._case(cmd.case_id)
        if self._already_applied(target, cmd.request_id):
            return target
        source = self._case(cmd.source_case_id)
        if source.case_id == target.case_id:
            return target
        target.normalized_event_ids = list(dict.fromkeys([*target.normalized_event_ids, *source.normalized_event_ids]))
        target.observations.extend(deepcopy(source.observations))
        target.invariant_hit_records.extend(deepcopy(source.invariant_hit_records))
        target.correlation_fingerprints = list(dict.fromkeys([*target.correlation_fingerprints, *source.correlation_fingerprints]))
        target.related_cases = list(dict.fromkeys([*target.related_cases, source.case_id]))
        target.correlation_evidence.extend(
            self._carried_evidence(
                source,
                keep=set(target.normalized_event_ids),
                covered={item.event_id for item in target.correlation_evidence if item.event_id},
                action="объединении",
            )
        )
        target.correlation_evidence.append(CorrelationEvidence(
            event_id="", fingerprint="", rule="manual_merge", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        ))
        target.risk_score = max(target.risk_score, source.risk_score)
        source.status = CaseStatus.MERGED
        source.related_cases = list(dict.fromkeys([*source.related_cases, target.case_id]))
        self._save_with_audit(source, action="merge_source", cmd=cmd, clock=clock)
        self._save_with_audit(target, action="merge", cmd=cmd, clock=clock)
        return target

    def split(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        source = self._case(cmd.case_id)
        selected = list(dict.fromkeys(cmd.event_ids))
        if not selected or any(event_id not in source.normalized_event_ids for event_id in selected):
            raise ValueError("split events must be attached to the source case")
        new_case = deepcopy(source)
        new_case.case_id = self._ids.new_case_id_short()
        new_case.status = CaseStatus.NEW
        new_case.normalized_event_ids = selected
        new_case.related_cases = [source.case_id]
        new_case.observations = [deepcopy(item) for item in source.observations]
        for observation in new_case.observations:
            observation.event_ids = [event_id for event_id in observation.event_ids if event_id in selected]
        new_case.observations = [item for item in new_case.observations if item.event_ids]
        new_case.correlation_evidence = [
            *self._carried_evidence(source, keep=set(selected), covered=set(), action="разделении"),
            CorrelationEvidence(
                event_id="", fingerprint="", rule="manual_split", manual=True,
                reason=reason, request_id=cmd.request_id.strip(),
            ),
        ]
        source.normalized_event_ids = [event_id for event_id in source.normalized_event_ids if event_id not in selected]
        source.related_cases = list(dict.fromkeys([*source.related_cases, new_case.case_id]))
        self._recalculate(source)
        self._recalculate(new_case)
        self._save_with_audit(source, action="split_source", cmd=cmd, clock=clock)
        self._save_with_audit(new_case, action="split", cmd=cmd, clock=clock)
        return new_case
