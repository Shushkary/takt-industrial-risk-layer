"""Ручная корректировка состава дела: attach, detach, merge, split.

Операции меняют не только список событий, но и принадлежность доказательств. Аудит
«След смены» (разрыв D01) показал, что раньше менялся только список: split копировал в
дочернее дело находку о событии, которое там не осталось, вместе с её артефактом; наблюдения
исходного дела продолжали ссылаться на ушедшие события; attach принимал несуществующий
идентификатор; merge переносил события, но оставлял находки и артефакты источника позади.
Результат — расследование и экспорт с доказательствами другого состава событий.

Контракт, который держит этот модуль (проверяется
`tests/test_manual_correlation_integrity.py`):

1. **Доказательство идёт за своими событиями.** Находка уходит в то дело, где собраны все её
   события; ни одного не ушло — остаётся на месте.
2. **Разошедшийся состав помечается, а не переписывается.** Находка, чьи события разошлись по
   обоим делам, остаётся в исходном и помечается исторической: состава, о котором её писали,
   больше нет. То же после отсоединения последнего её события. Удалять запись аналитика
   нельзя — это материал доказательства.
3. **Дочернее дело заводится сейчас.** Оно не наследует журнал, решения, наряды и вердикты
   исходного: чужая история не становится его историей. Связь остаётся через `related_cases`.
4. **Событие проверяется на существование**, когда хранилище событий подключено. Без
   хранилища проверка невозможна, и операция ведёт себя как прежде — молча выдумывать отказ
   хуже, чем его отсутствие.
5. **Повтор запроса определён.** Тот же `request_id` не создаёт второго дочернего дела и не
   удваивает перенос доказательств.
6. **Изменение применяется целиком.** Дела, затронутые одной операцией, сохраняются вместе:
   сбой между записями не оставляет источник закрытым, а цель — без его событий.

Пересчёт риска и вердикта этот модуль не трогает за пределами уже существовавшего
`_recalculate` (срез записей срабатываний по оставшимся событиям): границы защищённого ядра —
предмет отдельного согласования, а не правки заодно.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from takt.application.system_defaults import default_id_provider
from takt.domain.entities.case import Case, CaseStatus, CorrelationEvidence, Finding
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort


class EventExistencePort(Protocol):
    """Хранилище принятых событий — ровно в той части, что нужна проверке существования."""

    def events_by_ids(self, event_ids: list[str]) -> list: ...


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
    def __init__(
        self,
        repo: CaseRepositoryPort,
        ids: IdProviderPort = default_id_provider,
        *,
        events: EventExistencePort | None = None,
    ) -> None:
        self._repo = repo
        self._ids = ids
        self._events = events

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

    def _require_known_event(self, event_id: str) -> None:
        """Событие, которого нет в хранилище, дало бы делу ссылку в никуда.

        Проверка условна: в поставке без постоянного хранилища событий спрашивать не у кого.
        Отказывать в такой поставке значило бы запретить операцию там, где она допустима.
        """
        if self._events is None:
            return
        if not self._events.events_by_ids([event_id]):
            raise ValueError(f"unknown event: {event_id}")

    @staticmethod
    def _already_applied(case: Case, request_id: str) -> bool:
        rid = request_id.strip()
        return bool(rid) and any(item.manual and item.request_id == rid for item in case.correlation_evidence)

    @staticmethod
    def _recalculate(case: Case) -> None:
        remaining = set(case.normalized_event_ids)
        case.invariant_hit_records = [item for item in case.invariant_hit_records if item.event_ref in remaining]
        case.invariant_hits = sorted({item.invariant_id for item in case.invariant_hit_records})
        case.risk_score = max((item.score_contribution for item in case.invariant_hit_records), default=0.0)

    @staticmethod
    def _drop_events_from_observations(case: Case, removed: set[str]) -> None:
        for observation in case.observations:
            observation.event_ids = [item for item in observation.event_ids if item not in removed]
        case.observations = [item for item in case.observations if item.event_ids]

    @staticmethod
    def _mark_historical(finding: Finding, origin_case_id: str) -> Finding:
        finding.historical = True
        finding.origin_case_id = finding.origin_case_id or origin_case_id
        return finding

    def _save_all(self, cases: list[Case]) -> None:
        """Затронутые дела сохраняются вместе.

        Хранилище может уметь пакетную запись (`save_all`) — тогда она и используется. Иначе
        дела пишутся по очереди, а при сбое возвращается снимок, снятый до первой записи:
        полусохранённое состояние — это дело с чужим составом событий, и молча оставлять его
        нельзя.
        """
        save_all = getattr(self._repo, "save_all", None)
        if callable(save_all):
            save_all(cases)
            return
        snapshot = [self._repo.get(case.case_id) for case in cases]
        written: list[Case] = []
        try:
            for case in cases:
                self._repo.save(case)
                written.append(case)
        except Exception:
            for case, previous in zip(cases, snapshot, strict=True):
                if previous is not None and case in written:
                    self._repo.save(previous)
            raise

    def _audit_lines(self, cases: list[Case], *, action: str, cmd: ManualCorrelationCommand, clock: datetime) -> None:
        for case in cases:
            case.append_audit(f"manual correlation {action}: {cmd.reason.strip()}", clock, actor=cmd.actor)

    def _record_operation(self, case: Case, *, action: str, cmd: ManualCorrelationCommand, clock: datetime) -> None:
        record = getattr(self._repo, "record_operation_event", None)
        if callable(record):
            record(
                operation_type=f"correlation.{action}", entity_id=case.case_id,
                actor=cmd.actor,
                payload_json=json.dumps({"reason": cmd.reason.strip(), "request_id": cmd.request_id}),
                created_at=clock.isoformat(),
            )

    def _save_with_audit(self, case: Case, *, action: str, cmd: ManualCorrelationCommand, clock: datetime) -> None:
        self._audit_lines([case], action=action, cmd=cmd, clock=clock)
        self._save_all([case])
        self._record_operation(case, action=action, cmd=cmd, clock=clock)

    # --- операции ----------------------------------------------------------

    def detach(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        case = self._case(cmd.case_id)
        if self._already_applied(case, cmd.request_id):
            return case
        if cmd.event_id not in case.normalized_event_ids:
            raise ValueError(f"event is not attached: {cmd.event_id}")
        case.normalized_event_ids = [item for item in case.normalized_event_ids if item != cmd.event_id]
        self._drop_events_from_observations(case, {cmd.event_id})
        # Ссылка на отсоединённое событие висячая: она снимается, а сама находка остаётся.
        # Оставшаяся без событий помечается исторической — читающий должен видеть, что состав,
        # о котором её писали, в деле больше не собран.
        for finding in case.findings:
            if cmd.event_id not in finding.event_ids:
                continue
            finding.event_ids = [item for item in finding.event_ids if item != cmd.event_id]
            if not finding.event_ids:
                self._mark_historical(finding, case.case_id)
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
        self._require_known_event(cmd.event_id)
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
        # События источника ушли в целевое дело — доказательства идут за ними. Происхождение
        # сохраняется: читающий должен видеть, в каком деле находку записали.
        known_findings = {item.finding_id for item in target.findings}
        for finding in deepcopy(source.findings):
            if finding.finding_id in known_findings:
                continue
            finding.origin_case_id = finding.origin_case_id or source.case_id
            target.findings.append(finding)
        known_artifacts = {(item.type, item.value, item.host_id) for item in target.artifacts}
        for artifact in deepcopy(source.artifacts):
            if (artifact.type, artifact.value, artifact.host_id) in known_artifacts:
                continue
            target.artifacts.append(artifact)
        target.correlation_evidence.append(CorrelationEvidence(
            event_id="", fingerprint="", rule="manual_merge", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        ))
        target.risk_score = max(target.risk_score, source.risk_score)
        source.status = CaseStatus.MERGED
        source.related_cases = list(dict.fromkeys([*source.related_cases, target.case_id]))
        self._audit_lines([source], action="merge_source", cmd=cmd, clock=clock)
        self._audit_lines([target], action="merge", cmd=cmd, clock=clock)
        self._save_all([source, target])
        self._record_operation(source, action="merge_source", cmd=cmd, clock=clock)
        self._record_operation(target, action="merge", cmd=cmd, clock=clock)
        return target

    def _existing_split_child(self, source: Case, request_id: str) -> Case | None:
        """Дочернее дело предыдущего такого же запроса.

        Повтор split раньше заводил новое дело на каждый вызов: сеть моргнула — в очереди два
        одинаковых дела, и какое из них настоящее, интерфейс не говорит.
        """
        rid = request_id.strip()
        if not rid:
            return None
        for case_id in source.related_cases:
            candidate = self._repo.get(case_id)
            if candidate is None:
                continue
            if any(item.manual and item.rule == "manual_split" and item.request_id == rid
                   for item in candidate.correlation_evidence):
                return candidate
        return None

    def split(self, cmd: ManualCorrelationCommand, *, clock: datetime) -> Case:
        reason = self._validate(cmd)
        source = self._case(cmd.case_id)
        existing = self._existing_split_child(source, cmd.request_id)
        if existing is not None:
            return existing
        selected = list(dict.fromkeys(cmd.event_ids))
        if not selected or any(event_id not in source.normalized_event_ids for event_id in selected):
            raise ValueError("split events must be attached to the source case")
        moved = set(selected)

        # Дочернее дело собирается полем за полем, а не копией исходного целиком: копия
        # приносила чужой журнал, решения, наряды и вердикты — историю дела, которого у
        # нового ещё нет.
        new_case = Case(
            case_id=self._ids.new_case_id_short(),
            status=CaseStatus.NEW,
            title=source.title,
            risk_class=source.risk_class,
            risk_score=source.risk_score,
            created_at=source.created_at,
            normalized_event_ids=selected,
            xai_summary=source.xai_summary,
            burst_fingerprint=source.burst_fingerprint,
            correlation_fingerprints=list(source.correlation_fingerprints),
            related_cases=[source.case_id],
            primary_asset_id=source.primary_asset_id,
            trigger_operation=source.trigger_operation,
            operator_id=source.operator_id,
            invariant_hits=list(source.invariant_hits),
            invariant_hit_records=deepcopy(source.invariant_hit_records),
            observations=deepcopy(source.observations),
            dq_score=source.dq_score,
            dq_partial=source.dq_partial,
            dq_reasons=list(source.dq_reasons),
            risk_vectors=dict(source.risk_vectors),
            last_event_source=source.last_event_source,
        )
        for observation in new_case.observations:
            observation.event_ids = [event_id for event_id in observation.event_ids if event_id in moved]
        new_case.observations = [item for item in new_case.observations if item.event_ids]
        new_case.correlation_evidence = [CorrelationEvidence(
            event_id="", fingerprint="", rule="manual_split", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        )]

        # Находка идёт за своими событиями. Разошедшийся состав остаётся в исходном деле с
        # пометкой: приписать его любому из двух дел значило бы назвать доказательством то,
        # чего в этом деле уже нет.
        kept: list[Finding] = []
        for finding in source.findings:
            events = set(finding.event_ids)
            if events and events <= moved:
                finding.origin_case_id = finding.origin_case_id or source.case_id
                new_case.findings.append(finding)
                continue
            if events & moved:
                self._mark_historical(finding, source.case_id)
            kept.append(finding)
        source.findings = kept

        source.normalized_event_ids = [event_id for event_id in source.normalized_event_ids if event_id not in moved]
        self._drop_events_from_observations(source, moved)
        source.related_cases = list(dict.fromkeys([*source.related_cases, new_case.case_id]))
        source.correlation_evidence.append(CorrelationEvidence(
            event_id="", fingerprint="", rule="manual_split_source", manual=True,
            reason=reason, request_id=cmd.request_id.strip(),
        ))
        self._recalculate(source)
        self._recalculate(new_case)
        self._audit_lines([source], action="split_source", cmd=cmd, clock=clock)
        self._audit_lines([new_case], action="split", cmd=cmd, clock=clock)
        self._save_all([source, new_case])
        self._record_operation(source, action="split_source", cmd=cmd, clock=clock)
        self._record_operation(new_case, action="split", cmd=cmd, clock=clock)
        return new_case
