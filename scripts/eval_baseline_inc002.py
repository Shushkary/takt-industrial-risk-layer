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

Расчёт живёт в `takt.application.use_cases.investigation_effort`; здесь — только чтение
кейса и вывод. Той же логикой пользуется эндпоинт `GET /cases/{id}/simulation`, поэтому
цифры в отчёте и в интерфейсе не могут разойтись.

Запуск:

    python -m scripts.eval_baseline_inc002 --case-id INC-002
    python -m scripts.eval_baseline_inc002 --case-id INC-002 --observed observed.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from takt.application.use_cases.investigation_effort import (
    analyst_session_from_audit,
    evaluate_effort,
)


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
        result = evaluate_effort(
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
