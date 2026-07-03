from __future__ import annotations

import os
import sqlite3
from datetime import datetime


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
    conn.execute("PRAGMA busy_timeout=%d" % int(ms))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")


def checkpoint_wal_best_effort(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass


def dt_to_sql(dt: datetime) -> str:
    if dt.tzinfo is None:
        return dt.isoformat(timespec="seconds")
    return dt.astimezone().isoformat(timespec="seconds")


def dt_from_sql(raw: str) -> datetime:
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.execute("PRAGMA table_info(%s)" % table)
    return {str(row[1]) for row in cur.fetchall()}
