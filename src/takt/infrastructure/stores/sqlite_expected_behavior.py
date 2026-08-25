from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
)
from takt.infrastructure.stores.sqlite_connection import (
    configure_sqlite_connection as _configure_sqlite_connection,
)
from takt.infrastructure.stores.sqlite_schema import ensure_expected_behavior_schema


class SqliteExpectedBehavior(ExpectedBehaviorPort):
    """SQLite expected-behavior adapter backed by the same database as cases."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._closed = False
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        _configure_sqlite_connection(self._conn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ensure_expected_behavior_schema(self._conn)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    def mark_expected(self, asset_id: str, operation: str) -> None:
        aid = (asset_id or "").lower().strip()
        op = (operation or "").upper().strip()
        if not aid or not op:
            return
        with self._lock:
            if self._closed:
                raise RuntimeError("SqliteExpectedBehavior connection is closed")
            self._conn.execute(
                """
                INSERT OR REPLACE INTO expected_behavior (asset_id_norm, operation_upper)
                VALUES (?, ?)
                """,
                (aid, op),
            )

    def is_expected(self, asset_id: str, operation: str) -> bool:
        aid = (asset_id or "").lower().strip()
        op = (operation or "").upper().strip()
        if not aid or not op:
            return False
        with self._lock:
            if self._closed:
                raise RuntimeError("SqliteExpectedBehavior connection is closed")
            cur = self._conn.execute(
                """
                SELECT 1 FROM expected_behavior
                WHERE asset_id_norm = ? AND operation_upper = ?
                LIMIT 1
                """,
                (aid, op),
            )
            return cur.fetchone() is not None
