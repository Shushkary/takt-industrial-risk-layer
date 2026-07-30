"""Dead-letter store: изоляция невалидных записей (нарушения инвариантов).

При ``InvariantViolation`` сырые данные не теряются и не роняют поток — они
попадают в таблицу ``dead_letters`` с типом и деталями ошибки для последующего
разбора администратором (эндпоинт ``/api/v1/admin/dead-letters``).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """Запись dead-letter."""

    id: int
    raw_data: str
    error_type: str
    error_detail: str
    ts: str


@runtime_checkable
class DeadLetterStore(Protocol):
    def record(self, *, raw_data: str, error_type: str, error_detail: str, ts: datetime) -> DeadLetter: ...

    def list(self, *, limit: int = 100) -> list[DeadLetter]: ...


class InMemoryDeadLetterStore:
    """Реализация dead-letter store в памяти (для тестов/memory-режима)."""

    def __init__(self) -> None:
        self._rows: list[DeadLetter] = []
        self._seq = 0

    def record(self, *, raw_data: str, error_type: str, error_detail: str, ts: datetime) -> DeadLetter:
        self._seq += 1
        dl = DeadLetter(
            id=self._seq,
            raw_data=raw_data,
            error_type=error_type,
            error_detail=error_detail,
            ts=ts.isoformat(),
        )
        self._rows.append(dl)
        return dl

    def list(self, *, limit: int = 100) -> list[DeadLetter]:
        bounded = max(1, min(int(limit), 1000))
        return list(reversed(self._rows))[:bounded]


class SqliteDeadLetterStore:
    """Реализация dead-letter store поверх SQLite."""

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dead_letters (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  raw_data TEXT NOT NULL,
                  error_type TEXT NOT NULL,
                  error_detail TEXT NOT NULL,
                  ts TEXT NOT NULL
                )
                """
            )

    def record(self, *, raw_data: str, error_type: str, error_detail: str, ts: datetime) -> DeadLetter:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO dead_letters (raw_data, error_type, error_detail, ts) VALUES (?, ?, ?, ?)",
                (raw_data, error_type, error_detail, ts.isoformat()),
            )
            row_id = int(cur.lastrowid or 0)
        return DeadLetter(id=row_id, raw_data=raw_data, error_type=error_type, error_detail=error_detail, ts=ts.isoformat())

    def list(self, *, limit: int = 100) -> list[DeadLetter]:
        bounded = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, raw_data, error_type, error_detail, ts FROM dead_letters ORDER BY id DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        return [
            DeadLetter(
                id=int(r["id"]),
                raw_data=r["raw_data"],
                error_type=r["error_type"],
                error_detail=r["error_detail"],
                ts=r["ts"],
            )
            for r in rows
        ]
