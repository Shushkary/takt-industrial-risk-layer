from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from takt.domain.entities.event import ArtifactType, EventArtifact, EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
)
from takt.infrastructure.stores.sqlite_connection import (
    configure_sqlite_connection as _configure_sqlite_connection,
)
from takt.infrastructure.stores.sqlite_connection import (
    dt_from_sql as _dt_from_sql,
)
from takt.infrastructure.stores.sqlite_connection import (
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
        with self._lock:
            self._raise_if_closed()
            self._persist_event(event)
            if max_events <= 0:
                return
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
                    _dt_to_sql(datetime.now(UTC)),
                ),
            )
            self._trim(max_events)

    def _persist_event(self, event: NormalizedEvent) -> None:
        entities = event.entities or EventEntities()
        artifacts = [{"type": artifact.type.value, "value": artifact.value} for artifact in event.artifacts]
        self._conn.execute(
            """
            INSERT INTO events (
              event_id, observed_at, source, protocol, operation, payload_size,
              payload_json, operator_id, host_id, user_id, process_id,
              parent_process_id, src_address, dst_address, artifacts_json,
              ingest_trust, inserted_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(event_id) DO UPDATE SET
              observed_at=excluded.observed_at, source=excluded.source,
              protocol=excluded.protocol, operation=excluded.operation,
              payload_size=excluded.payload_size, payload_json=excluded.payload_json,
              operator_id=excluded.operator_id, host_id=excluded.host_id,
              user_id=excluded.user_id, process_id=excluded.process_id,
              parent_process_id=excluded.parent_process_id,
              src_address=excluded.src_address, dst_address=excluded.dst_address,
              artifacts_json=excluded.artifacts_json, ingest_trust=excluded.ingest_trust
            """,
            (
                event.event_id, _dt_to_sql(event.observed_at), event.source.value,
                event.protocol, event.operation, int(event.payload_size),
                json.dumps(dict(event.payload), ensure_ascii=False, default=str), event.operator_id,
                entities.host_id, entities.user_id, entities.process_id, entities.parent_process_id,
                entities.src_address, entities.dst_address,
                json.dumps(artifacts, ensure_ascii=False), float(event.ingest_trust),
                _dt_to_sql(datetime.now(UTC)),
            ),
        )
        for entity_type, entity_id, attributes in (
            ("host", entities.host_id, {}),
            ("user", entities.user_id, {}),
            ("process", entities.process_id, {"parent_process_id": entities.parent_process_id}),
        ):
            if entity_id:
                self._upsert_entity(entity_type, entity_id, event, attributes)

    def _upsert_entity(
        self, entity_type: str, entity_id: str, event: NormalizedEvent, attributes: dict[str, Any]
    ) -> None:
        observed = _dt_to_sql(event.observed_at)
        existing = self._conn.execute(
            "SELECT sources_json, attributes_json FROM entity_registry WHERE entity_type=? AND entity_id=?",
            (entity_type, entity_id),
        ).fetchone()
        sources = set(json.loads(existing["sources_json"] or "[]")) if existing else set()
        sources.add(event.source.value)
        previous_attributes = dict(json.loads(existing["attributes_json"] or "{}")) if existing else {}
        previous_attributes.update({key: value for key, value in attributes.items() if value})
        self._conn.execute(
            """
            INSERT INTO entity_registry (
              entity_type, entity_id, first_seen, last_seen, sources_json, event_count, attributes_json
            ) VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(entity_type, entity_id) DO UPDATE SET
              first_seen=MIN(first_seen, excluded.first_seen), last_seen=MAX(last_seen, excluded.last_seen),
              sources_json=excluded.sources_json, event_count=event_count+1,
              attributes_json=excluded.attributes_json
            """,
            (entity_type, entity_id, observed, observed, json.dumps(sorted(sources)), json.dumps(previous_attributes)),
        )
        bucket = event.observed_at.astimezone(UTC).strftime("%Y-%m-%dT%H:00:00Z")
        self._conn.execute(
            """
            INSERT INTO entity_activity (entity_type, entity_id, bucket_hour, event_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(entity_type, entity_id, bucket_hour)
            DO UPDATE SET event_count=event_count+1
            """,
            (entity_type, entity_id, bucket),
        )

    def entity_card(self, entity_type: str, entity_id: str, *, event_limit: int = 100) -> dict[str, Any] | None:
        with self._lock:
            self._raise_if_closed()
            row = self._conn.execute(
                "SELECT * FROM entity_registry WHERE entity_type=? AND entity_id=?",
                (entity_type, entity_id),
            ).fetchone()
            if row is None:
                return None
            activity = self._conn.execute(
                """SELECT bucket_hour, event_count FROM entity_activity
                   WHERE entity_type=? AND entity_id=? ORDER BY bucket_hour DESC LIMIT 168""",
                (entity_type, entity_id),
            ).fetchall()
        filter_name = {"host": "host_id", "user": "user_id", "process": "process_id"}[entity_type]
        # Имя фильтра выбирается по типу сущности, поэтому аргумент собирается словарём.
        entity_filter: dict[str, Any] = {filter_name: entity_id}
        events, total = self.search_events(limit=event_limit, **entity_filter)
        count = int(row["event_count"])
        if count == 1:
            typicality, explanation = "first_seen", "entity has exactly one observed event"
        elif count < 3:
            typicality, explanation = "rare", f"only {count} events are present in history"
        else:
            typicality, explanation = "typical", f"{count} events across {len(activity)} hourly buckets"
        return {
            "type": entity_type, "id": entity_id,
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "sources": json.loads(row["sources_json"] or "[]"), "event_count": count,
            "activity_by_hour": [{"bucket": item["bucket_hour"], "count": item["event_count"]} for item in activity],
            "typicality": {"status": typicality, "explanation": explanation},
            "attributes": json.loads(row["attributes_json"] or "{}"),
            "environment": [_persistent_event_summary(event) for event in events],
            "environment_total": total,
        }

    def search_events(
        self,
        *,
        source: str | None = None,
        observed_from: datetime | None = None,
        observed_to: datetime | None = None,
        host_id: str | None = None,
        user_id: str | None = None,
        process_id: str | None = None,
        address: str | None = None,
        artifact_type: str | None = None,
        artifact_value: str | None = None,
        text: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[NormalizedEvent], int]:
        clauses: list[str] = []
        params: list[Any] = []
        exact = {
            "source": source, "host_id": host_id, "user_id": user_id, "process_id": process_id,
        }
        for column, value in exact.items():
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if observed_from is not None:
            clauses.append("observed_at >= ?")
            params.append(_dt_to_sql(observed_from))
        if observed_to is not None:
            clauses.append("observed_at <= ?")
            params.append(_dt_to_sql(observed_to))
        if address:
            clauses.append("(src_address = ? OR dst_address = ?)")
            params.extend((address, address))
        if artifact_type:
            clauses.append("artifacts_json LIKE ?")
            params.append(f'%"type": "{artifact_type}"%')
        if artifact_value:
            clauses.append("artifacts_json LIKE ?")
            params.append(f"%{artifact_value}%")
        if text:
            clauses.append("payload_json LIKE ?")
            params.append(f"%{text}%")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            self._raise_if_closed()
            count = int(self._conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0])
            rows = self._conn.execute(
                f"SELECT * FROM events{where} ORDER BY observed_at DESC, event_id LIMIT ? OFFSET ?",
                [*params, int(limit), int(offset)],
            ).fetchall()
        return [_persistent_row_to_event(row) for row in rows], count

    def event_counts_by_source(self) -> dict[str, int]:
        with self._lock:
            self._raise_if_closed()
            rows = self._conn.execute("SELECT source, COUNT(*) AS n FROM events GROUP BY source").fetchall()
        return {str(row["source"]): int(row["n"]) for row in rows}

    def events_by_ids(self, event_ids: list[str]) -> list[NormalizedEvent]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            self._raise_if_closed()
            rows = self._conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY observed_at, event_id", event_ids
            ).fetchall()
        return [_persistent_row_to_event(row) for row in rows]

    def list_recent_events(self, *, limit: int) -> list[NormalizedEvent]:
        """Окно контекста для предикатов инвариантов — с сущностями и артефактами.

        Таблица `recent_events` хранит только порядок и «скелет» события: колонок под
        сущности и артефакты в ней нет. Пока окно читалось напрямую из неё, предикаты
        получали события с `entities = None` и пустым списком артефактов, то есть при
        `TAKT_STORAGE=sqlite` работали вслепую, а при хранилище в памяти — нет.
        Полная запись лежит в `events`, поэтому окно берёт порядок из `recent_events`,
        а данные — из `events`.
        """
        if limit <= 0:
            return []
        with self._lock:
            self._raise_if_closed()
            rows = self._conn.execute(
                """
                SELECT events.*, recent_events.seq AS recent_seq
                FROM recent_events
                JOIN events ON events.event_id = recent_events.event_id
                ORDER BY recent_events.seq DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [_persistent_row_to_event(row) for row in reversed(rows)]

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


def _persistent_row_to_event(row: sqlite3.Row) -> NormalizedEvent:
    base = _row_to_event(row)
    artifacts_raw = json.loads(row["artifacts_json"] or "[]")
    artifacts = tuple(EventArtifact(ArtifactType(item["type"]), str(item["value"])) for item in artifacts_raw)
    return NormalizedEvent(
        event_id=base.event_id, observed_at=base.observed_at, source=base.source,
        protocol=base.protocol, operation=base.operation, payload_size=base.payload_size,
        payload=base.payload, operator_id=base.operator_id,
        entities=EventEntities(
            host_id=row["host_id"], user_id=row["user_id"], process_id=row["process_id"],
            parent_process_id=row["parent_process_id"], src_address=row["src_address"],
            dst_address=row["dst_address"],
        ),
        artifacts=artifacts, ingest_trust=float(row["ingest_trust"]),
    )


def _persistent_event_summary(event: NormalizedEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id, "observed_at": event.observed_at.isoformat(),
        "source": event.source.value, "operation": event.operation,
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
    }
