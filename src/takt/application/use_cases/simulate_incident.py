"""Хронология инцидента с объяснением: что произошло и чем это было выделено.

Окно расследования отвечает на вопрос «что в кейсе». Симуляция отвечает на другой:
«почему продукт отобрал именно это». Для каждого шага цепочки собирается разбор — какой
механизм его выделил (пивот по отличительной сущности, расширение до уровня узла,
срабатывание инварианта) и на каком основании.

Фазы цепочки атаки и техники ATT&CK берутся из разметки события и не вычисляются здесь:
если источник фазу не проставил, шаг в хронологию не попадает, а его наличие видно в
счётчиках. Продукт не додумывает за источник.

Границы продукта не двигаются: это чтение и объяснение уже принятых данных, никаких
действий и никаких вердиктов от имени системы.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from takt.application.use_cases.investigation_effort import (
    AnalystSession,
    ManualProcessModel,
    analyst_session_from_audit,
    evaluate_effort,
)
from takt.domain.entities.case import Case
from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.kill_chain import (
    PHASE_FIELD,
    PHASE_ORDER,
    TECHNIQUE_FIELD,
    KillChainPhase,
    parse_phase,
    parse_technique,
    phase_index,
    phase_title_ru,
)

# Как называется механизм отбора в объяснении для аналитика.
#
# Значения приходят из трёх мест: сборка инцидента пивотом (`pivot`, `host-expansion`),
# ручная корректировка связей аналитиком (`manual_*`) и конвейер приёма, который кладёт в
# `rule` имя сработавшего правила корреляции из отпечатка `corr:<правило>:<хэш>`.
_SELECTOR_TITLES = {
    "pivot": "пивот по отличительной сущности",
    "host-expansion": "расширение разбора до уровня узла",
    "manual_attach": "ручная привязка аналитиком",
    "manual_detach": "ручная отвязка аналитиком",
    "manual_merge": "объединение кейсов аналитиком",
    "manual_split": "разделение кейса аналитиком",
}

# Записи о связывании нет вообще. Это не то же самое, что незнакомый механизм: механизм может
# быть записан и просто не иметь названия в словаре выше.
_NO_EVIDENCE_TITLE = "основание не записано"

_NO_EVIDENCE_REASON = (
    "записи о связывании нет: так бывает у события, которым кейс был создан конвейером"
    " приёма, и у событий, перенесённых в кейс при объединении"
)


class EventByIdsPort(Protocol):
    """Чтение принятых событий по идентификаторам."""

    def events_by_ids(self, event_ids: list[str]) -> list[NormalizedEvent]: ...


@dataclass(slots=True)
class SimulateIncidentUseCase:
    """Собирает хронологию цепочки с объяснением отбора и метриками трудоёмкости."""

    events: EventByIdsPort
    model: ManualProcessModel | None = None

    def execute(self, case: Case, *, seconds_per_action: float | None = None) -> dict[str, Any]:
        events = self.events.events_by_ids(list(case.normalized_event_ids))
        by_id = {event.event_id: event for event in events}
        evidence = {item.event_id: item for item in case.correlation_evidence}
        hits: dict[str, list[str]] = {}
        for record in case.invariant_hit_records:
            hits.setdefault(record.event_ref, []).append(record.invariant_id)

        steps: list[dict[str, Any]] = []
        without_phase = 0
        for event in sorted(events, key=lambda item: (item.observed_at, item.event_id)):
            phase = parse_phase(event.payload.get(PHASE_FIELD))
            if phase is None:
                without_phase += 1
                continue
            steps.append(
                _step(
                    order=len(steps) + 1,
                    event=event,
                    phase=phase,
                    evidence=evidence.get(event.event_id),
                    invariants=sorted(set(hits.get(event.event_id, ()))),
                )
            )

        session = analyst_session_from_audit(list(case.audit_log))
        effort = evaluate_effort(
            sources=len({observation.source for observation in case.observations}),
            entities=len([item for item in case.artifacts if item.source == "pivot-seed"]),
            events=len(case.normalized_event_ids),
            session=session,
            model=self.model,
            seconds_per_action=seconds_per_action,
        )

        return {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status.value,
            "risk_class": case.risk_class,
            "risk_score": case.risk_score,
            "events_total": len(case.normalized_event_ids),
            "events_resolved": len(by_id),
            "events_without_phase": without_phase,
            "chain_length": len(steps),
            "phases": _phase_summary(steps),
            "steps": steps,
            "invariants": sorted(set(case.invariant_hits)),
            "effort": effort,
            "response_options": _response_options(case, events),
        }


def _selector_title(selector: str) -> str:
    """Как назвать механизм отбора аналитику.

    Незнакомое непустое значение — это имя правила корреляции конвейера приёма. Назвать его
    правилом честнее, чем объявить основание незаписанным: запись есть, и раньше кейс,
    собранный конвейером, а не пивотом, показывал необъяснённым каждый свой шаг.
    """
    if not selector:
        return _NO_EVIDENCE_TITLE
    return _SELECTOR_TITLES.get(selector) or f"правило корреляции «{selector}»"


def _selector_reason(selector: str, recorded: str) -> str:
    """Основание отбора словами. Записанное не переписывается, пустое — объясняется."""
    if recorded:
        return recorded
    if not selector:
        return _NO_EVIDENCE_REASON
    if selector in _SELECTOR_TITLES:
        return ""
    # Имя правила уже названо в заголовке — здесь важно, откуда взялась связь.
    return "отнесено конвейером приёма по совпадению признаков"


def _step(
    *,
    order: int,
    event: NormalizedEvent,
    phase: KillChainPhase,
    evidence: Any,
    invariants: Sequence[str],
) -> dict[str, Any]:
    entities = event.entities
    selector = getattr(evidence, "rule", "") if evidence is not None else ""
    return {
        "order": order,
        "event_id": event.event_id,
        "observed_at": event.observed_at.isoformat(),
        "source": event.source.value,
        "operation": event.operation,
        "protocol": event.protocol,
        "attack_phase": phase.value,
        "attack_phase_title_ru": phase_title_ru(phase),
        "mitre_technique": parse_technique(event.payload.get(TECHNIQUE_FIELD)),
        "entities": (
            {name: getattr(entities, name) for name in entities.__slots__} if entities else {}
        ),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
        "detection_explanation": {
            "selected_by": selector,
            "selected_by_title_ru": _selector_title(selector),
            "matched_entities": list(getattr(evidence, "fields", []) or []),
            "reason": _selector_reason(
                selector, getattr(evidence, "reason", "") if evidence is not None else ""
            ),
            "invariants": list(invariants),
        },
    }


def _phase_summary(steps: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Фазы в порядке развития атаки — только те, что встречаются в цепочке."""
    counts: dict[str, int] = {}
    for step in steps:
        counts[step["attack_phase"]] = counts.get(step["attack_phase"], 0) + 1
    present = [phase for phase in PHASE_ORDER if phase.value in counts]
    return [
        {
            "phase": phase.value,
            "title_ru": phase_title_ru(phase),
            "events": counts[phase.value],
            "order": phase_index(phase),
        }
        for phase in present
    ]


def _response_options(case: Case, events: Sequence[NormalizedEvent]) -> list[dict[str, str]]:
    """Применимые действия по отличительным сущностям инцидента.

    Строятся по артефактам пивота, а не по всем сущностям кейса: события, добранные
    расширением до уровня узла, содержат штатную активность, и предлагать по ним действия
    означало бы трогать непричастных. Это перечень рекомендаций — ТАКТ их не выполняет.
    """
    seeds = [item for item in case.artifacts if item.source == "pivot-seed"]
    hosts = [item.value for item in seeds if item.type == "host" and ":" not in item.value]
    objects = [item.value for item in seeds if item.type == "host" and ":" in item.value]
    users = [item.value for item in seeds if item.type == "user"]
    addresses = [item.value for item in seeds if item.type == "address"]

    options: list[dict[str, str]] = []
    if hosts:
        options.append({"kind": "isolate_host", "title": "Изоляция узлов", "objects": ", ".join(hosts)})
    if users:
        options.append({"kind": "reset_account", "title": "Сброс учётных записей", "objects": ", ".join(users)})
    if addresses:
        options.append({"kind": "block_address", "title": "Блокировка адресов", "objects": ", ".join(addresses)})
    if objects or any(event.source.value == "ot" for event in events):
        options.append(
            {
                "kind": "freeze_pipeline",
                "title": "Заморозка конвейера сборки до проверки объектов",
                "objects": ", ".join(objects),
            }
        )
    return options
