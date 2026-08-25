"""Append-only журнал безопасности (ФСТЭК 239/31, Спринт 1): SQLite + опциональный файловый вывод."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def security_log_file_path_from_env() -> Path | None:
    raw = os.environ.get("TAKT_SECURITY_LOG_FILE", "").strip()
    if not raw:
        return None
    return Path(raw).expanduser()


@dataclass(slots=True)
class SecurityLogHealth:
    status: str
    entries_last_hour: int
    backend: str


class SecurityLogService:
    """
    Запись событий в таблицу **security_log** (при SQLite-пути) и/или в файл (**TAKT_SECURITY_LOG_FILE**).
    Формат строки: JSON (поля в духе structured-data RFC 5424).
    """

    def __init__(self, *, sqlite_db_path: Path | None, file_path: Path | None) -> None:
        self._lock = threading.Lock()
        self._hostname = socket.gethostname()
        self._procid = os.getpid()
        self._appname = "takt"
        self._file_path = file_path
        self._file_handle: Any = None
        self._conn: sqlite3.Connection | None = None
        self._memory: deque[dict[str, Any]] = deque(maxlen=50_000)
        self._sqlite_ok = False

        if file_path is not None:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(  # noqa: SIM115 — длинноживущий appender
                file_path,
                "a",
                encoding="utf-8",
            )

        if sqlite_db_path is not None:
            self._conn = sqlite3.connect(
                str(sqlite_db_path),
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts_utc TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_security_log_ts ON security_log (ts_utc);
                """
            )
            self._sqlite_ok = True

    def close(self) -> None:
        with self._lock:
            if self._file_handle is not None:
                try:
                    self._file_handle.flush()
                    self._file_handle.close()
                except OSError:
                    pass
                self._file_handle = None
            if self._conn is not None:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.close()
                self._conn = None

    def record(self, event_type: str, fields: Mapping[str, Any]) -> None:
        ts = datetime.now(UTC)
        base: dict[str, Any] = {
            "timestamp": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "hostname": self._hostname,
            "app_name": self._appname,
            "procid": self._procid,
            "msgid": event_type,
            "structured_data": dict(fields),
        }
        line = json.dumps(base, ensure_ascii=False, separators=(",", ":"))
        payload_compact = json.dumps(dict(fields), ensure_ascii=False, separators=(",", ":"))

        with self._lock:
            self._memory.append({"ts": ts, "type": event_type, "raw": base})
            if self._conn is not None:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute(
                        "INSERT INTO security_log (ts_utc, event_type, payload_json) VALUES (?,?,?)",
                        (ts.replace(tzinfo=None).isoformat(timespec="milliseconds") + "Z", event_type, payload_compact),
                    )
            if self._file_handle is not None:
                try:
                    self._file_handle.write(line + "\n")
                    self._file_handle.flush()
                except OSError:
                    pass

    def entries_last_hour(self) -> int:
        cutoff = datetime.now(UTC) - timedelta(hours=1)
        with self._lock:
            if self._conn is not None:
                try:
                    cur = self._conn.execute(
                        "SELECT COUNT(*) FROM security_log WHERE ts_utc >= ?",
                        (cutoff.replace(tzinfo=None).isoformat(timespec="milliseconds") + "Z",),
                    )
                    row = cur.fetchone()
                    return int(row[0]) if row else 0
                except sqlite3.Error:
                    pass
            return sum(1 for e in self._memory if e["ts"] >= cutoff)

    def health_snapshot(self) -> SecurityLogHealth:
        n = self.entries_last_hour()
        if self._sqlite_ok and self._file_path is not None:
            return SecurityLogHealth("ok", n, "sqlite+file")
        if self._sqlite_ok:
            return SecurityLogHealth("ok", n, "sqlite")
        if self._file_path is not None:
            return SecurityLogHealth("ok", n, "file_only")
        return SecurityLogHealth("memory_only", n, "memory")

    def record_service_start(self, extra: Mapping[str, Any] | None = None) -> None:
        payload = {"phase": "startup", "monotonic_ns": time.monotonic_ns()}
        if extra:
            payload.update(extra)
        self.record("service_start", payload)

    def record_service_stop(self, extra: Mapping[str, Any] | None = None) -> None:
        payload = {"phase": "shutdown", "monotonic_ns": time.monotonic_ns()}
        if extra:
            payload.update(extra)
        self.record("service_stop", payload)
