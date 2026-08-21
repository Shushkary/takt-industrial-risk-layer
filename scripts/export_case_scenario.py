#!/usr/bin/env python3
"""
Закрытое дело — в фикстуру регресса (`docs/customer_value_map.md`, разрыв G-6).

Забирает дело из боевого хранилища, проверяет, что оно закрыто и вердикт подтверждён
человеком, и кладёт сценарий в `tests/fixtures/case_scenarios/`. С этого момента
`tests/test_case_scenarios.py` прогоняет его на боевых весах при каждом запуске тестов:
изменение, ломающее накопленный случай заказчика, роняет тест здесь, а не всплывает
после релиза.

Сценарием становится только разобранное дело. Незакрытое дело, дело без подтверждения
оператором и дело, подтверждённое как неопределённое, скрипт отклоняет — иначе в регресс
попала бы гипотеза, которую потом пришлось бы защищать как эталон.

Usage:
    python scripts/export_case_scenario.py --case-id CASE [--db PATH] [--out DIR] [--force]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from takt.application.use_cases.case_scenario import build_case_scenario  # noqa: E402
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore  # noqa: E402
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore  # noqa: E402

_DEFAULT_DB = ROOT / "data" / "takt.db"
_DEFAULT_OUT = ROOT / "tests" / "fixtures" / "case_scenarios"


def export(*, case_id: str, db_path: Path, out_dir: Path, force: bool) -> Path:
    if not db_path.is_file():
        raise SystemExit(f"хранилище не найдено: {db_path}")

    repo = SqliteCaseStore(str(db_path))
    events_store = SqliteRecentEventStore(str(db_path))
    try:
        case = repo.get(case_id)
        if case is None:
            raise SystemExit(f"дело не найдено: {case_id}")
        events = events_store.events_by_ids(case.normalized_event_ids)
        scenario = build_case_scenario(case, events)
    except ValueError as e:
        raise SystemExit(f"дело не может стать сценарием: {e}") from e
    finally:
        events_store.close()

    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{case_id}.json"
    if target.exists() and not force:
        raise SystemExit(f"файл уже существует, добавьте --force: {target}")

    target.write_text(
        json.dumps(scenario, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case-id", required=True, help="идентификатор закрытого подтверждённого дела")
    parser.add_argument("--db", type=Path, default=_DEFAULT_DB, help=f"путь к sqlite (по умолчанию {_DEFAULT_DB})")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT, help="каталог фикстур")
    parser.add_argument("--force", action="store_true", help="перезаписать существующую фикстуру")
    args = parser.parse_args(argv)

    target = export(case_id=args.case_id, db_path=args.db, out_dir=args.out, force=args.force)
    print(f"сценарий записан: {target}")
    print("прогон: python -m pytest -q tests/test_case_scenarios.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
