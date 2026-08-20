"""Сокращение ручных действий на разборе INC-002: замер по журналу против модели.

Что здесь считается замером, а что — расчётом, различается строго.

**Замер.** Число ручных действий в ТАКТ берётся из журнала кейса: append-only записи с
хэш-цепочкой (`case_audit_ledger`). Ручное действие отличается меткой `actor=` — её несут
только записи, сделанные человеком; автоматические операции конвейера её не имеют, а
методика прямо исключает их из счёта.

**Расчёт.** Числа для текущего процесса (без ТАКТ) получены моделью: у неё явные
коэффициенты, они печатаются вместе с результатом и проверяемы. Это оценка, а не замер.
Методика (`docs/pt_techlab/baseline_methodology.md`) требует парного прогона с
наблюдателем, тремя аналитиками и тремя инцидентами; расчёт его не заменяет и служит
ориентиром до его проведения.

**Время не моделируется.** Перевод действий в секунды требует коэффициента «секунд на
действие», которого никто не измерял. Величина `T` выводится только из наблюдённых
значений (`--observed`); без них в таблице стоит прочерк. Выдуманная цифра
производительности запрещена `docs/product_boundary.md`.

Запуск:

    python -m scripts.eval_baseline_inc002 --case-id INC-002
    python -m scripts.eval_baseline_inc002 --case-id INC-002 --observed observed.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Метка ручного действия в записи журнала. Ставится `Case.append_audit`, когда действие
# выполнил человек: `... | actor=<кто>`.
_ACTOR_MARK = "| actor="


@dataclass(frozen=True, slots=True)
class ManualProcessModel:
    """Модель ручного разбора того же инцидента без ТАКТ.

    Каждый коэффициент — число действий по определению методики (клик, переключение между
    системами, ручной ввод или копирование идентификатора, запуск поиска). Значения по
    умолчанию равны единице: одно действие на один шаг. Менять их имеет смысл только по
    результатам наблюдения за конкретным процессом заказчика.
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
    lines: tuple[str, ...] = field(default=())

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


def analyst_session_from_audit(audit_lines: list[str]) -> AnalystSession:
    """Ручные действия из журнала: только записи с меткой актора."""
    manual = [line for line in audit_lines if _ACTOR_MARK in line]
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


def evaluate(
    *,
    sources: int,
    entities: int,
    events: int,
    session: AnalystSession,
    model: ManualProcessModel | None = None,
    observed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Сводка по одному инциденту."""
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
    }


def _case_facts(case: Any, workspace_events: list[Any]) -> tuple[int, int, int]:
    """Состав кейса: классов источников, отличительных сущностей, событий."""
    sources = len({observation.source for observation in case.observations})
    entities = len([item for item in case.artifacts if item.source == "pivot-seed"])
    return sources, entities, len(case.normalized_event_ids)


def _render(result: dict[str, Any], case_id: str) -> str:
    lines: list[str] = []
    lines.append(f"Инцидент: {case_id}")
    lines.append(
        f"Состав: источников {result['sources']}, отличительных сущностей {result['entities']}, "
        f"событий {result['events']}"
    )
    lines.append("")
    lines.append("Ручные действия, текущий процесс (расчёт по модели):")
    for step, count in result["model_breakdown"].items():
        lines.append(f"  {step:<44} {count:>5}")
    lines.append(f"  {'итого':<44} {result['current_actions']:>5}")
    lines.append("")

    takt_mark = "замер по журналу" if result["takt_actions_measured"] else "наблюдение"
    lines.append(f"Ручные действия в ТАКТ ({takt_mark}): {result['takt_actions']}")
    reduction = result["reduction_actions_percent"]
    if reduction is None:
        lines.append("Сокращение действий: не определено (базовое значение равно нулю)")
    else:
        target = "цель ≥ 30% достигнута" if reduction >= 30.0 else "цель ≥ 30% не достигнута"
        lines.append(f"Сокращение действий: {reduction:.1f}%  ({target})")
    lines.append("")

    if result["current_seconds"] is None:
        lines.append(
            "Время: не измерено. Оно требует парного прогона с наблюдателем — "
            "docs/pt_techlab/baseline_methodology.md. Модель время не считает: "
            "коэффициента «секунд на действие» никто не измерял."
        )
    else:
        lines.append(
            f"Время: текущий процесс {result['current_seconds']:.0f} с, "
            f"ТАКТ {result['takt_seconds']:.0f} с, "
            f"сокращение {result['reduction_time_percent']:.1f}%"
        )
    lines.append("")
    lines.append("Границы применимости результата:")
    lines.append(
        "  - числа текущего процесса получены моделью с явными коэффициентами и заменяются"
        " наблюдёнными значениями через --observed;"
    )
    lines.append(
        "  - в журнал попадают действия, меняющие состояние кейса; навигационные клики"
        " (открыть кейс, открыть карточку сущности) в нём не отражаются, поэтому число"
        " действий в ТАКТ — нижняя граница, а сокращение — верхняя;"
    )
    if result["current_actions"]:
        step, count = max(result["model_breakdown"].items(), key=lambda item: item[1])
        share = count / result["current_actions"] * 100.0
        lines.append(
            f"  - в модели преобладает шаг «{step}»: {count} из"
            f" {result['current_actions']} действий ({share:.0f}%);"
        )
    lines.append(
        "  - расчёт не заменяет парный прогон с наблюдателем по"
        " docs/pt_techlab/baseline_methodology.md."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Сокращение ручных действий на разборе инцидента")
    parser.add_argument("--case-id", default="INC-002")
    parser.add_argument(
        "--observed",
        type=Path,
        default=None,
        help="JSON с наблюдёнными значениями: current_actions, takt_actions, current_seconds, takt_seconds",
    )
    parser.add_argument("--json", action="store_true", help="вывести результат в JSON")
    args = parser.parse_args()

    from takt.interface_adapters.api.main import create_app

    app = create_app()
    try:
        case = app.state.repo.get(args.case_id)
        if case is None:
            print(f"error: кейс {args.case_id} не найден", file=sys.stderr)
            return 1
        sources, entities, events = _case_facts(case, [])
        if entities == 0:
            print(
                "warning: у кейса нет отличительных сущностей (артефактов с source=pivot-seed); "
                "модель ручного процесса опирается на них",
                file=sys.stderr,
            )
        session = analyst_session_from_audit(list(case.audit_log))
        if session.actions == 0:
            print(
                "warning: в журнале кейса нет ручных действий — сессия аналитика не записана, "
                "сравнивать не с чем",
                file=sys.stderr,
            )
        observed = json.loads(args.observed.read_text(encoding="utf-8")) if args.observed else None
        result = evaluate(
            sources=sources, entities=entities, events=events, session=session, observed=observed
        )
    finally:
        for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
            resource = getattr(app.state, attr, None)
            close = getattr(resource, "close", None)
            if callable(close):
                close()

    print(json.dumps(result, ensure_ascii=False, indent=2, default=str) if args.json else _render(result, args.case_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
