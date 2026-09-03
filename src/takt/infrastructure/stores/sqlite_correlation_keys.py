"""Дельта-запись ключей корреляции дела (`case_correlation_keys`).

Раньше `SqliteCaseStore.save` на каждый вызов делал `DELETE FROM case_correlation_keys
WHERE case_id = ?`, а затем заново вставлял все ключи дела — O(число ключей дела) на
**каждое** событие, независимо от того, появился ли у дела хоть один новый ключ. Ключи
практически всегда только накапливаются (`dict.fromkeys` в `ProcessEventUseCase` берёт
объединение), поэтому на растущем деле полная перезапись росла вместе с ним: замер на
корпусе INC-002 (`tests/fixtures/pt_techlab/inc_002/`) при включённой SOC-корреляции
показал рост с 27 до 222 мс на событие, а полный приём 1030 событий — с 31 до 268 секунд.

Пишется только дельта: новые ключи вставляются, ключи, которых у дела больше нет, —
удаляются. Для подавляющего большинства сохранений (ключи не изменились или только
добавились) второй набор пуст, и запрос к `case_correlation_keys` не выполняется вовсе.
"""

from __future__ import annotations

import sqlite3

from takt.domain.entities.case import Case


def case_fingerprints(case: Case) -> frozenset[str]:
    return frozenset(fp for fp in (case.burst_fingerprint, *case.correlation_fingerprints) if fp)


def reindex_correlation_keys(conn: sqlite3.Connection, case: Case, existing: Case | None) -> None:
    new_keys = case_fingerprints(case)
    old_keys = case_fingerprints(existing) if existing is not None else frozenset()
    if new_keys == old_keys:
        return
    for fingerprint in old_keys - new_keys:
        conn.execute(
            "DELETE FROM case_correlation_keys WHERE case_id = ? AND fingerprint = ?",
            (case.case_id, fingerprint),
        )
    for fingerprint in new_keys - old_keys:
        conn.execute(
            "INSERT OR IGNORE INTO case_correlation_keys (fingerprint, case_id) VALUES (?, ?)",
            (fingerprint, case.case_id),
        )
