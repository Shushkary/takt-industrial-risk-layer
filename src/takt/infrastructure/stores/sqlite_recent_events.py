from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
    configure_sqlite_connection as _configure_sqlite_connection,
    dt_from_sql as _dt_from_sql,
    dt_to_sql as _dt_to_sql,
)
from takt.infrastructure.stores.sqlite_schema import ensure_recent_events_schema


class SqliteRecentEventStore:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._closed = False
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        _configure_sqlite_connection(self._conn)
        ensure_recent_events_schema(self._conn)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    def add_recent_event(self, event: NormalizedEvent, *, max_events: int) -> None:
        if max_events <= 0:
            return
        with self._lock:
            self._raise_if_closed()
            self._conn.execute(
                """
                INSERT INTO recent_events (
                  event_id, observed_at, source, protocol, operation,
                  payload_size, payload_json, operator_id, inserted_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.event_id,
                    _dt_to_sql(event.observed_at),
                    event.source.value,
                    event.protocol,
                    event.operation,
                    int(event.payload_size),
                    json.dumps(dict(event.payload), ensure_ascii=False, default=str),
                    event.operator_id,
                    _dt_to_sql(datetime.now(timezone.utc)),
                ),
            )
            self._trim(max_events)

    def list_recent_events(self, *, limit: int) -> list[NormalizedEvent]:
        if limit <= 0:
            return []
        with self._lock:
            self._raise_if_closed()
            rows = self._conn.execute(
                """
                SELECT * FROM recent_events
                ORDER BY seq DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [_row_to_event(row) for row in reversed(rows)]

    def _trim(self, max_events: int) -> None:
        self._conn.execute(
            """
            DELETE FROM recent_events
            WHERE seq NOT IN (
              SELECT seq FROM recent_events
              ORDER BY seq DESC
              LIMIT ?
            )
            """,
            (int(max_events),),
        )

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise RuntimeError("SqliteRecentEventStore connection is closed")


def _row_to_event(row: sqlite3.Row) -> NormalizedEvent:
    payload_raw = row["payload_json"] or "{}"
    try:
        payload: dict[str, Any] = dict(json.loads(payload_raw))
    except (TypeError, ValueError):
        payload = {}
    source_raw = str(row["source"] or EventSource.UNKNOWN.value)
    try:
        source = EventSource(source_raw)
    except ValueError:
        source = EventSource.UNKNOWN
    return NormalizedEvent(
        event_id=str(row["event_id"]),
        observed_at=_dt_from_sql(str(row["observed_at"])),
        source=source,
        protocol=str(row["protocol"]),
        operation=str(row["operation"]),
        payload_size=int(row["payload_size"]),
        payload=payload,
        operator_id=str(row["operator_id"] or ""),
    )
