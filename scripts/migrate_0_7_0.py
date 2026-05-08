#!/usr/bin/env python3
"""Идемпотентное приведение файла SQLite кейсов к схеме v2 и слияние дублирующих открытых карточек.

Запуск:
  python scripts/migrate_0_7_0.py path/to/takt_cases.db
  python scripts/migrate_0_7_0.py path/to/takt_cases.db --bucket-sec 300

Под капотом открывается SqliteCaseStore (CREATE/ALTER как при старте API), затем
`merge_duplicate_open_cases_v070` — сворачивает открытые кейсы с одной парой
(актив, операция) в одном UTC-бакете (legacy `source|…` vs единый bucketed-ключ).
Повторный запуск не создаёт дублей.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description="Migrate TAKT SQLite case DB to v0.7.x schema + merge duplicates.")
    p.add_argument("db_path", type=Path, help="Path to SQLite cases database file")
    p.add_argument("--bucket-sec", type=int, default=300, help="Time bucket for merge grouping (default 300)")
    args = p.parse_args()
    path = args.db_path.resolve()
    if not path.parent.is_dir():
        print(f"error: parent directory does not exist: {path.parent}", file=sys.stderr)
        raise SystemExit(2)

    from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

    store = SqliteCaseStore(path)
    try:
        merged = store.merge_duplicate_open_cases_v070(bucket_sec=int(args.bucket_sec))
        print(f"schema_version={store.db_schema_version()} merged_open_case_groups={merged}")
    finally:
        store.close()


if __name__ == "__main__":
    main()
