from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.infrastructure.stores.sqlite_store import CURRENT_DB_SCHEMA_VERSION, SqliteCaseStore
from takt.interface_adapters.api.main import create_app


def _event(event_id: str, *, asset_id: str = "shared") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=datetime(2026, 5, 20, 10, 0, tzinfo=UTC),
        source=EventSource.NETWORK,
        protocol="MODBUS",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": asset_id},
    )


def test_sqlite_recent_event_store_roundtrip_and_trim(tmp_path: Path) -> None:
    store = SqliteRecentEventStore(tmp_path / "recent.db")
    try:
        store.add_recent_event(_event("e1"), max_events=2)
        store.add_recent_event(_event("e2"), max_events=2)
        store.add_recent_event(_event("e3"), max_events=2)
        events = store.list_recent_events(limit=10)
    finally:
        store.close()

    assert [event.event_id for event in events] == ["e2", "e3"]
    assert events[-1].payload["asset_id"] == "shared"


def test_sqlite_recent_context_survives_new_app_instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "cases.db"
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(db))

    first = {
        "observed_at": "2026-05-20T10:00:00+00:00",
        "protocol": "MODBUS",
        "operation": "POLL",
        "asset_id": "shared",
        "payload_size": 1,
        "source": "network_events",
    }
    second = {
        "observed_at": "2026-05-20T10:01:00+00:00",
        "protocol": "SMB",
        "operation": "READ",
        "asset_id": "shared",
        "payload_size": 1,
        "source": "network_events",
    }

    with TestClient(create_app()) as client:
        assert client.post("/events", json=first).status_code == 200
    with TestClient(create_app()) as client:
        response = client.post("/events", json=second)

    assert response.status_code == 200
    assert "protocol_escalation" in response.json()["invariant_hits"]


def test_sqlite_case_store_rejects_future_schema_version(tmp_path: Path) -> None:
    db = tmp_path / "future.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
        conn.execute(
            "INSERT INTO app_metadata (key, value) VALUES ('schema_version', ?)",
            (str(CURRENT_DB_SCHEMA_VERSION + 1),),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(RuntimeError, match="newer than supported"):
        SqliteCaseStore(db)
