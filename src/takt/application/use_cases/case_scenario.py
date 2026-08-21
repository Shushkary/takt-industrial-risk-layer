"""Экспорт закрытого дела в фикстуру регресса.

Этап 7 пути клиента (``docs/customer_value_map.md``, разрыв G-6): «нет накопления проверенных
знаний». Закрытое дело с подтверждённым вердиктом — самое дорогое, что накапливает заказчик:
за ним стоит разбор аналитика и решение человека. Но пока его нельзя переиспользовать,
следующий релиз может тихо перестать ловить тот же сценарий, и узнает об этом заказчик, а не мы.

Фикстура — это события дела плюс ожидаемый исход. Прогоняет её
``tests/test_case_scenarios.py`` на **боевых** весах из ``config/risk_weights.yaml``: изменение
весов, ломающее накопленный сценарий, роняет тест.

**Контекстные события хранятся вместе с делом.** Инварианты вроде серии неуспешных
аутентификаций срабатывают не по одному событию, а по скользящему окну предшествующих. В деле
таких событий может не быть — окно шире, чем бакет слияния. Прогон только по событиям дела
показал бы отсутствие срабатывания и сделал бы регресс ложно-зелёным, поэтому фикстура несёт
предысторию отдельным полем ``context_events``: она проигрывается первой и не входит в ожидаемый
исход.

Что не становится сценарием:

- незакрытое дело — это гипотеза, а не знание;
- дело без подтверждения человеком — подтверждает вердикт оператор, а не конвейер;
- дело, подтверждённое как неопределённое — честный вердикт, но эталоном регресса быть не может.

Закрепив любое из них, мы зафиксировали бы в регрессе собственную ошибку и потом защищали бы её
как эталон.

Модуль чистый: без ввода-вывода, из состава дела и уже прочитанных событий.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.domain.services.forensic_verdict import case_forensic_verdict

SCENARIO_SCHEMA_VERSION = 1

# Дело разобрано: оператор довёл его до одного из терминальных состояний.
_CLOSED_STATUSES = frozenset(
    {CaseStatus.CONFIRMED, CaseStatus.FALSE_POSITIVE, CaseStatus.EXPECTED_BEHAVIOR}
)

_TRIAD_BY_VERDICT = {
    "легитимное": "LEG",
    "нелегитимное": "ILLEG",
    "неопределённое": "UNDET",
}

_ENTITY_FIELDS = ("host_id", "user_id", "process_id", "parent_process_id", "src_address", "dst_address")


def event_to_dict(event: NormalizedEvent) -> dict[str, Any]:
    """Каноническое представление события. Тот же вид отдаёт ``GET /events/search``."""
    entities = event.entities
    return {
        "event_id": event.event_id,
        "observed_at": event.observed_at.isoformat(),
        "source": event.source.value,
        "protocol": event.protocol,
        "operation": event.operation,
        "payload_size": event.payload_size,
        "payload": dict(event.payload),
        "operator_id": event.operator_id,
        "entities": ({name: getattr(entities, name) for name in _ENTITY_FIELDS} if entities else None),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
        "ingest_trust": event.ingest_trust,
    }


def event_from_dict(data: Mapping[str, Any]) -> NormalizedEvent:
    """Обратное преобразование. Неизвестный источник или тип артефакта — ошибка, не заглушка.

    Фикстура читается регрессом: молча подставив ``unknown``, мы получили бы зелёный тест на
    испорченных данных.
    """
    raw_entities = data.get("entities")
    entities = (
        EventEntities(**{name: raw_entities.get(name) for name in _ENTITY_FIELDS})
        if isinstance(raw_entities, Mapping)
        else None
    )
    return NormalizedEvent(
        event_id=str(data["event_id"]),
        observed_at=datetime.fromisoformat(str(data["observed_at"])),
        source=EventSource(str(data["source"])),
        protocol=str(data["protocol"]),
        operation=str(data["operation"]),
        payload_size=int(data["payload_size"]),
        payload=dict(data.get("payload") or {}),
        operator_id=str(data.get("operator_id") or ""),
        entities=entities,
        artifacts=tuple(
            EventArtifact(ArtifactType(str(item["type"])), str(item["value"]))
            for item in data.get("artifacts") or []
        ),
        ingest_trust=float(data.get("ingest_trust", 1.0)),
    )


def build_case_scenario(
    case: Case,
    events: Iterable[NormalizedEvent],
    *,
    context_events: Iterable[NormalizedEvent] = (),
) -> dict[str, Any]:
    """Собрать фикстуру регресса из закрытого дела с подтверждённым вердиктом.

    ``context_events`` — предыстория из хранилища событий: то, что видел движок к моменту
    разбора. Из неё отбирается только предшествующее последнему событию дела; события самого
    дела в предысторию не дублируются.
    """
    if case.status not in _CLOSED_STATUSES:
        allowed = ", ".join(sorted(status.value for status in _CLOSED_STATUSES))
        raise ValueError(f"case {case.case_id} is not closed: status must be one of {allowed}")

    confirmation = _operator_confirmation(case)
    if confirmation is None:
        raise ValueError(f"case {case.case_id} has no operator confirmation of the formal verdict")

    verdict = _TRIAD_BY_VERDICT.get(case_forensic_verdict(case).value, "UNDET")
    if verdict == "UNDET":
        raise ValueError(f"case {case.case_id} is confirmed as undetermined and cannot be a reference scenario")

    ordered = sorted(events, key=lambda event: (event.observed_at, event.event_id))
    if not ordered:
        raise ValueError(f"case {case.case_id} has no events to replay")

    own_ids = {event.event_id for event in ordered}
    last_moment = ordered[-1].observed_at
    context = sorted(
        (
            event
            for event in context_events
            if event.event_id not in own_ids and event.observed_at <= last_moment
        ),
        key=lambda event: (event.observed_at, event.event_id),
    )

    return {
        "context_events": [event_to_dict(event) for event in context],
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "source_case_id": case.case_id,
        "title": case.title,
        "confirmed_by": confirmation.actor,
        "confirmed_at": confirmation.ts.isoformat(timespec="seconds"),
        "confirmation_reason": confirmation.reason,
        "expected": {
            "verdict": verdict,
            "risk_class": case.risk_class,
            "invariant_hits": sorted(case.invariant_hits),
        },
        "organizational_context": [
            {
                "work_order_number": permit.work_order_number,
                "verdict": permit.verdict,
                "organizational_context_sha256": permit.organizational_context_sha256,
            }
            for permit in case.manual_permits
        ],
        "events": [event_to_dict(event) for event in ordered],
    }


def _operator_confirmation(case: Case) -> Any | None:
    """Последнее подтверждение вердикта человеком. Автоматические записи не считаются."""
    for record in reversed(case.formal_verdict_records):
        if record.source == "operator_confirmation":
            return record
    return None
