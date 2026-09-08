"""Реконструкция цепочки: что данные позволяют утверждать, а что — только предположить.

Раньше любое событие с заполненным ``process_id`` становилось шагом «запуск процесса»
независимо от операции, а точка входа выбиралась эвристикой и показывалась без границ
доказательств. Аудит «След смены» (разрыв D05) назвал следствие: временная последовательность
выглядела как доказанная цепочка запуска и проникновения. Для доказательного пакета это хуже
отсутствия реконструкции — там, где данные позволяют сказать «процесс наблюдался», было
сказано «процесс был запущен».

Границы, которые держит этот модуль:

- **запуск** подтверждается операцией события; всё остальное с процессом — наблюдение;
- **сетевое перемещение** требует пары адресов: из одного адреса направление не следует;
- **неизвестный родитель** остаётся неизвестным. Подставить вместо него пользователя или узел
  значило бы выдать догадку за наблюдение;
- **точка входа** — гипотеза, и она помечена гипотезой. Первое по времени событие дела точкой
  входа не является: оно просто первое;
- **последнее наблюдение** не объявляется текущим присутствием злоумышленника;
- у шага сохраняются **все** события-основания, а у цепочки — **диапазон** доступной истории:
  вывод сделан в границах дела, за ними реконструкция ничего не знает.

Признаки операций перечислены здесь, а не угадываются по подстроке произвольной длины: список
короткий, читаемый и расширяется явно при подключении нового источника.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from takt.domain.entities.event import NormalizedEvent

PROCESS_SPAWN = "process_spawn"
PROCESS_OBSERVED = "process_observed"
NETWORK_MOVE = "network_move"

ENTRY_HYPOTHESIS = "hypothesis"
ENTRY_UNDETERMINED = "undetermined"

# Операции, которыми источники называют запуск процесса. Совпадение проверяется по слову
# целиком после приведения к верхнему регистру: `OBSERVED` запуском не является, и подстрочное
# совпадение («PROCESS») зачислило бы в запуски любое событие о процессе.
_SPAWN_OPERATIONS = frozenset({
    "PROCESS_CREATE",
    "PROCESS_START",
    "PROCESS_SPAWN",
    "PROCESS_LAUNCH",
    "CREATE_PROCESS",
    "EXEC",
    "EXECVE",
})


@dataclass(slots=True)
class _Step:
    kind: str
    from_entity: str
    to_entity: str
    from_entity_known: bool
    operation: str
    source: str
    observed_at: str
    event_ids: list[str] = field(default_factory=list)


def is_spawn_operation(operation: str) -> bool:
    return (operation or "").strip().upper() in _SPAWN_OPERATIONS


def reconstruct_attack_chain(events: Sequence[NormalizedEvent]) -> dict:
    ordered = sorted(events, key=lambda event: (event.observed_at, event.event_id))
    process_ids = {
        event.entities.process_id for event in ordered if event.entities and event.entities.process_id
    }
    # Ребро описывается своими концами и видом, а не событием: одно и то же перемещение
    # наблюдается многократно, и по одному event_id его не проверить.
    steps: dict[tuple[str, str, str], _Step] = {}
    artifact_rows: dict[tuple[str, str], dict[str, str]] = {}
    entry_point = ""
    entry_reason = ""

    def remember(kind: str, from_entity: str, to_entity: str, *, known: bool, event: NormalizedEvent) -> None:
        key = (kind, from_entity, to_entity)
        step = steps.get(key)
        if step is None:
            step = _Step(
                kind=kind, from_entity=from_entity, to_entity=to_entity, from_entity_known=known,
                operation=event.operation, source=event.source.value,
                observed_at=event.observed_at.isoformat(),
            )
            steps[key] = step
        step.event_ids.append(event.event_id)

    for event in ordered:
        entities = event.entities
        if entities is not None and entities.process_id:
            parent = entities.parent_process_id or ""
            if is_spawn_operation(event.operation):
                remember(
                    PROCESS_SPAWN, parent, entities.process_id, known=bool(parent), event=event
                )
                # Точка входа — процесс, родителя которого в деле не наблюдалось. Это остаётся
                # гипотезой: отсутствие родителя в составе дела не означает его отсутствия
                # вообще, история дела ограничена его же событиями.
                if not entry_point and (not parent or parent not in process_ids):
                    entry_point = entities.process_id
                    entry_reason = (
                        "родитель процесса в составе дела не наблюдался; за пределами дела история не проверялась"
                    )
            else:
                remember(
                    PROCESS_OBSERVED, entities.host_id or "", entities.process_id,
                    known=bool(entities.host_id), event=event,
                )
        if entities is not None and entities.src_address and entities.dst_address:
            remember(NETWORK_MOVE, entities.src_address, entities.dst_address, known=True, event=event)
            if not entry_point:
                entry_point = entities.src_address
                entry_reason = "первое наблюдавшееся сетевое обращение; более раннего источника в деле нет"
        for artifact in event.artifacts:
            artifact_rows[(artifact.type.value, artifact.value)] = {
                "type": artifact.type.value, "value": artifact.value, "event_id": event.event_id,
            }

    numbered = [
        {
            "order": index, "kind": step.kind, "event_id": step.event_ids[0],
            "event_ids": list(step.event_ids),
            "observed_at": step.observed_at, "source": step.source,
            "from_entity": step.from_entity, "from_entity_known": step.from_entity_known,
            "to_entity": step.to_entity, "operation": step.operation,
        }
        for index, step in enumerate(steps.values(), start=1)
    ]
    last = numbered[-1] if numbered else None
    return {
        "entry_point": entry_point,
        # Гипотеза остаётся гипотезой: «Точка входа» без этой пометки читается как факт.
        "entry_point_status": ENTRY_HYPOTHESIS if entry_point else ENTRY_UNDETERMINED,
        "entry_point_reason": entry_reason,
        "steps": numbered,
        # Последнее наблюдение, а не текущее присутствие злоумышленника: продукт наблюдает
        # события, а не состояние сети.
        "last_observed": {
            "value": last["to_entity"] if last else "",
            "observed_at": last["observed_at"] if last else "",
        },
        # Границы вывода: за пределами этого диапазона реконструкция ничего не знает.
        "history": {
            "from": ordered[0].observed_at.isoformat() if ordered else "",
            "to": ordered[-1].observed_at.isoformat() if ordered else "",
            "events": len(ordered),
        },
        "artifacts": list(artifact_rows.values()),
    }
