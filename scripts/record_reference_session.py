"""Опорная сессия разбора: минимум действий, которых требует интерфейс на этом сценарии.

Зачем. Число действий в ТАКТ берётся из журнала кейса, а журнал заполняется только когда
кто-то работал. Без записанной сессии сравнение с ручным процессом опирается на пустоту, и
цифра в отчёте меняется от прогона к прогону. Скрипт воспроизводит одну и ту же сессию,
поэтому результат `scripts/eval_baseline_inc002.py` и вкладки «Цепочка атаки» повторяем.

Чем это не является. Это не замер работы живого аналитика и не эталон трудоёмкости: сюда
входят только действия, меняющие состояние кейса, — те, что попадают в append-only журнал.
Навигация (открыть кейс, открыть карточку сущности) состояние не меняет и не записывается,
поэтому полученное число — нижняя граница. Так и помечено в выводе оценки.

Состав сессии соответствует разбору INC-002: принять кейс в работу, отметить сверку с
журналами источников, зафиксировать находку по каждой отличительной сущности, вынести
решение. Вердикт остаётся за человеком — скрипт лишь повторяет то, что человек сделал бы
руками, и не выполняет никаких действий над инфраструктурой.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta

from takt.domain.entities.case import CaseStatus
from takt.interface_adapters.api.main import create_app

# Пауза между действиями. Задаёт только порядок записей в журнале; временем разбора
# не является и в оценку трудоёмкости как измеренная величина не идёт.
_STEP = timedelta(seconds=30)


def run(*, case_id: str, actor: str) -> int:
    app = create_app()
    repo = app.state.repo
    try:
        case = repo.get(case_id)
        if case is None:
            print(f"error: кейс {case_id} не найден", file=sys.stderr)
            return 1

        seeds = [item for item in case.artifacts if item.source == "pivot-seed"]
        if not seeds:
            print(
                "error: у кейса нет отличительных сущностей — сначала собери инцидент "
                "(python -m takt.tools.assemble_incident)",
                file=sys.stderr,
            )
            return 1

        moment = datetime.now(UTC)
        actions = 0

        case.append_audit("case taken for investigation", moment, actor=actor)
        actions += 1

        moment += _STEP
        case.append_audit("chain cross-checked with source journals", moment, actor=actor)
        actions += 1

        for seed in seeds:
            moment += _STEP
            case.append_audit(f"finding appended: {seed.type}:{seed.value}", moment, actor=actor)
            actions += 1

        moment += _STEP
        case.status = CaseStatus.CONFIRMED
        case.append_audit(f"status -> {CaseStatus.CONFIRMED.value}", moment, actor=actor)
        actions += 1

        repo.save(case)
    finally:
        for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
            resource = getattr(app.state, attr, None)
            close = getattr(resource, "close", None)
            if callable(close):
                close()

    print(f"recorded case={case_id} actions={actions} actor={actor}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Записать опорную сессию разбора инцидента")
    parser.add_argument("--case-id", default="INC-002")
    parser.add_argument("--actor", default="analyst.reference")
    args = parser.parse_args()
    return run(case_id=args.case_id, actor=args.actor)


if __name__ == "__main__":
    raise SystemExit(main())
