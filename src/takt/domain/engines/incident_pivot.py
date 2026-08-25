"""Сборка инцидента пивотом по сущностям.

Отвечает на вопрос «какие события из потока относятся к этому инциденту».
Работает в два шага, соответствующих реальному ходу разбора:

1. **Отличительные сущности.** События, где встречается сущность, характерная
   именно для инцидента (скомпрометированная учётная запись, адрес C2, объект
   релизного конвейера). Такие сущности почти не встречаются в фоне, поэтому
   шаг даёт высокую точность и не тянет посторонние события.
2. **Переход на уровень узла.** Часть событий не несёт отличительных признаков —
   типичный пример — сетевой поток между двумя внутренними узлами: те же адреса
   и узлы встречаются в фоновом трафике. Такие события присоединяются, когда
   аналитик осознанно расширяет разбор до уровня узла в окне инцидента; вместе с
   ними неизбежно приходит легитимная активность тех же узлов, и её отсеивает
   человек.

Такое разделение — не техническое ограничение, а суть работы: автоматика
собирает надёжное ядро, а расширение до уровня сущности остаётся решением
аналитика. Чистые функции: без сети, ОС и инфраструктурных зависимостей.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from takt.domain.entities.event import NormalizedEvent

# Поля сущностей, по которым возможен пивот.
PIVOT_ENTITY_FIELDS = ("host_id", "user_id", "src_address", "dst_address")


@dataclass(frozen=True, slots=True)
class PivotKey:
    """Сущность в виде «поле — значение»; значение нормализовано к нижнему регистру."""

    field: str
    value: str

    @staticmethod
    def of(field: str, value: str) -> PivotKey:
        return PivotKey(field, str(value).strip().lower())


def entity_keys(event: NormalizedEvent) -> set[PivotKey]:
    """Все сущности события: поля entities плюс артефакты как `artifact:<тип>`."""
    keys: set[PivotKey] = set()
    entities = event.entities
    if entities is not None:
        for field in PIVOT_ENTITY_FIELDS:
            value = getattr(entities, field, None)
            if value:
                keys.add(PivotKey.of(field, value))
    for artifact in event.artifacts:
        if artifact.value.strip():
            keys.add(PivotKey.of(f"artifact:{artifact.type.value}", artifact.value))
    return keys


def assemble_by_pivot(
    events: Iterable[NormalizedEvent],
    pivots: Iterable[PivotKey],
) -> list[NormalizedEvent]:
    """Ядро инцидента: события, содержащие хотя бы одну отличительную сущность.

    Один шаг, без транзитивного расширения. Транзитивный обход по общим
    сущностям на реальном потоке вырождается: узлы и внутренние адреса делятся
    с фоном, и охват лавинообразно растёт вместе с шумом.
    """
    wanted = set(pivots)
    selected = [event for event in events if entity_keys(event) & wanted]
    return sorted(selected, key=lambda event: (event.observed_at, event.event_id))


def expand_to_hosts(
    events: Iterable[NormalizedEvent],
    core: Sequence[NormalizedEvent],
    hosts: Iterable[str],
    *,
    padding_sec: int = 0,
) -> list[NormalizedEvent]:
    """Расширение разбора до уровня узла в окне уже собранного ядра.

    Возвращает ядро плюс события указанных узлов, попавшие во временное окно
    инцидента. Приводит к появлению легитимной активности тех же узлов — это
    ожидаемая плата за полноту, решение об отсеве принимает аналитик.
    """
    if not core:
        return []
    wanted_hosts = {str(host).strip().lower() for host in hosts if str(host).strip()}
    start = min(event.observed_at for event in core) - timedelta(seconds=padding_sec)
    end = max(event.observed_at for event in core) + timedelta(seconds=padding_sec)

    selected = {event.event_id: event for event in core}
    for event in events:
        if event.event_id in selected:
            continue
        if not (start <= event.observed_at <= end):
            continue
        entities = event.entities
        host = str(getattr(entities, "host_id", "") or "").strip().lower() if entities else ""
        if host and host in wanted_hosts:
            selected[event.event_id] = event
    return sorted(selected.values(), key=lambda event: (event.observed_at, event.event_id))
