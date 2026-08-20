"""Трудоёмкость разбора инцидента: замер по журналу против модели ручного процесса.

Две величины сведены в одном месте, и граница между ними держится строго.

**Замер.** Число ручных действий в ТАКТ берётся из журнала кейса — append-only записей с
хэш-цепочкой. Ручное действие отличается меткой `actor=`: её несут только записи, сделанные
человеком; автоматические операции конвейера её не имеют, а методика прямо исключает их из
счёта.

**Расчёт.** Числа текущего процесса даёт модель с явными коэффициентами, опирающаяся на
состав самого кейса. Это оценка, а не замер: методика
(`docs/pt_techlab/baseline_methodology.md`) требует парного прогона с наблюдателем, тремя
аналитиками и тремя инцидентами.

**Время не выводится из действий по умолчанию.** Коэффициент «секунд на действие» в методике
не задан и никем не измерялся, поэтому значения по умолчанию у него нет. Оценка времени
появляется, только если коэффициент передан явно, и всегда помечается как модельная.
Требование `docs/product_boundary.md`: числовая характеристика без ссылки на измерение
в материалы не идёт.

Чистый модуль: без ввода-вывода, работает с уже прочитанными строками журнала.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

# Метка ручного действия в записи журнала: `... | actor=<кто>`. Ставится `Case.append_audit`,
# когда действие выполнил человек.
ACTOR_MARK = "| actor="


@dataclass(frozen=True, slots=True)
class ManualProcessModel:
    """Модель ручного разбора того же инцидента без ТАКТ.

    Каждый коэффициент — число действий по определению методики: клик, переключение между
    системами, ручной ввод или копирование идентификатора, запуск поиска. Значения по
    умолчанию равны единице — одно действие на один шаг. Менять их имеет смысл только по
    результатам наблюдения за процессом конкретного заказчика.
    """

    open_system: int = 1
    """Открыть консоль источника — по одному действию на класс источника."""

    search_entity_in_system: int = 1
    """Поиск одной отличительной сущности в одной системе."""

    carry_identifier: int = 1
    """Перенос идентификатора в следующую систему: копирование и вставка."""

    note_event: int = 1
    """Занести относящееся событие в рабочую заметку."""

    summarize: int = 1
    """Свести итог разбора."""

    def actions(self, *, sources: int, entities: int, events: int) -> dict[str, int]:
        """Разбор действий по шагам. Ключи попадают в вывод, чтобы модель была проверяема."""
        carries = entities * max(sources - 1, 0)
        return {
            "открыть консоли источников": self.open_system * sources,
            "поиск сущностей по системам": self.search_entity_in_system * entities * sources,
            "перенос идентификаторов между системами": self.carry_identifier * carries,
            "фиксация событий в заметке": self.note_event * events,
            "сведение итога": self.summarize,
        }


@dataclass(frozen=True, slots=True)
class AnalystSession:
    """Ручные действия аналитика в ТАКТ по журналу кейса."""

    actions: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    lines: tuple[str, ...] = ()

    @property
    def seconds(self) -> float | None:
        """Активное время сессии. None, если действий меньше двух — интервала нет."""
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


def _parse_line_time(line: str) -> datetime | None:
    """Время из префикса записи журнала: `<ISO> | <текст>`."""
    prefix = line.split(" | ", 1)[0].strip()
    try:
        return datetime.fromisoformat(prefix)
    except ValueError:
        return None


def analyst_session_from_audit(audit_lines: Sequence[str]) -> AnalystSession:
    """Ручные действия из журнала: только записи с меткой актора."""
    manual = [line for line in audit_lines if ACTOR_MARK in line]
    moments = [moment for moment in (_parse_line_time(line) for line in manual) if moment is not None]
    return AnalystSession(
        actions=len(manual),
        started_at=min(moments) if moments else None,
        finished_at=max(moments) if moments else None,
        lines=tuple(manual),
    )


def reduction_percent(current: float, takt: float) -> float | None:
    """Сокращение в процентах. None, если базовое значение нулевое — делить не на что."""
    if current <= 0:
        return None
    return (current - takt) / current * 100.0


def evaluate_effort(
    *,
    sources: int,
    entities: int,
    events: int,
    session: AnalystSession,
    model: ManualProcessModel | None = None,
    observed: dict[str, Any] | None = None,
    seconds_per_action: float | None = None,
) -> dict[str, Any]:
    """Сводка трудоёмкости по одному инциденту.

    `seconds_per_action` — коэффициент модельной оценки времени. По умолчанию его нет:
    в методике он не задан. Если передан, оценка помечается как модельная и не выдаётся
    за измеренную величину.
    """
    model = model or ManualProcessModel()
    breakdown = model.actions(sources=sources, entities=entities, events=events)
    current_actions = sum(breakdown.values())
    takt_actions = session.actions

    observed = observed or {}
    current_seconds = observed.get("current_seconds")
    takt_seconds = observed.get("takt_seconds", session.seconds)
    if observed.get("current_actions") is not None:
        current_actions = int(observed["current_actions"])
    if observed.get("takt_actions") is not None:
        takt_actions = int(observed["takt_actions"])

    modelled_current_seconds: float | None = None
    modelled_takt_seconds: float | None = None
    if seconds_per_action is not None and seconds_per_action > 0:
        modelled_current_seconds = current_actions * seconds_per_action
        modelled_takt_seconds = takt_actions * seconds_per_action

    dominant_step, dominant_count = (
        max(breakdown.items(), key=lambda item: item[1]) if breakdown else ("", 0)
    )
    return {
        "sources": sources,
        "entities": entities,
        "events": events,
        "model_breakdown": breakdown,
        "current_actions": current_actions,
        "current_actions_measured": observed.get("current_actions") is not None,
        "takt_actions": takt_actions,
        "takt_actions_measured": observed.get("takt_actions") is None,
        "reduction_actions_percent": reduction_percent(current_actions, takt_actions),
        "current_seconds": current_seconds,
        "takt_seconds": takt_seconds,
        "reduction_time_percent": (
            reduction_percent(current_seconds, takt_seconds)
            if current_seconds is not None and takt_seconds is not None
            else None
        ),
        "seconds_per_action": seconds_per_action,
        "modelled_current_seconds": modelled_current_seconds,
        "modelled_takt_seconds": modelled_takt_seconds,
        "time_is_modelled": seconds_per_action is not None and seconds_per_action > 0,
        "dominant_step": dominant_step,
        "dominant_step_actions": dominant_count,
        "caveats": [
            "Числа текущего процесса получены моделью с явными коэффициентами и заменяются"
            " наблюдёнными значениями.",
            "В журнал попадают действия, меняющие состояние кейса; навигационные клики в нём"
            " не отражаются, поэтому число действий в ТАКТ — нижняя граница, а сокращение —"
            " верхняя.",
            "Оценка времени модельная: коэффициент «секунд на действие» не измерялся."
            if seconds_per_action
            else "Время не рассчитано: коэффициент «секунд на действие» не измерялся.",
            "Расчёт не заменяет парный прогон с наблюдателем по"
            " docs/pt_techlab/baseline_methodology.md.",
        ],
    }
