from __future__ import annotations

import contextlib
import os
import sqlite3
from datetime import UTC, datetime


def sqlite_busy_timeout_ms_from_env() -> int:
    """TAKT_SQLITE_BUSY_TIMEOUT_MS parsed in milliseconds for SQLite connections."""
    raw = os.environ.get("TAKT_SQLITE_BUSY_TIMEOUT_MS", "").strip()
    if not raw:
        return 5000
    try:
        value = int(raw, 10)
    except ValueError:
        return 5000
    if value < 100 or value > 300_000:
        return 5000
    return value


def configure_sqlite_connection(conn: sqlite3.Connection) -> None:
    ms = sqlite_busy_timeout_ms_from_env()
    conn.execute(f"PRAGMA busy_timeout={int(ms)}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")


def checkpoint_wal_best_effort(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")


def dt_to_sql(dt: datetime) -> str:
    """Момент времени в текстовом виде для SQLite — всегда в UTC.

    Раньше здесь стоял `astimezone()` без аргумента, то есть запись шла в локальной зоне
    машины. Два следствия. Первое: событие, принятое в UTC, возвращалось клиенту со
    смещением сервера, и цепочка инцидента в интерфейсе читалась не в тех сутках.
    Второе, важнее: `observed_at` — текстовая колонка, и выборки сортируются по ней
    лексикографически. Записи с разными смещениями (переезд БД, переход на летнее время)
    упорядочивались по написанию, а не по моменту времени, и порядок событий в кейсе
    оказывался неверным.

    Записи, сделанные прежней версией, читаются по-прежнему: смещение в строке есть, и
    `dt_from_sql` восстанавливает момент правильно.
    """
    if dt.tzinfo is None:
        return dt.isoformat(timespec="seconds")
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _now_utc() -> datetime:
    return datetime.now(UTC)


def dt_from_sql(raw: str) -> datetime:
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cur.fetchall()}
