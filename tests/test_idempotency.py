"""Идемпотентный POST /events и /events/batch (Спринт 4 / план v0.7.0)."""

from pathlib import Path

import json

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def _event_json(i: int = 0) -> dict:
    return {
        "observed_at": "2026-05-03T14:00:00+00:00",
        "protocol": "MODBUS",
        "operation": "READ",
        "asset_id": f"plc-idem-{i}",
        "payload_size": 64,
        "source": "plc_polling",
    }


def test_events_idempotency_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_IDEMPOTENCY_TTL_SEC", "3600")
    body = _event_json()
    headers = {"Idempotency-Key": "idem-events-1"}
    with TestClient(create_app()) as client:
        r1 = client.post("/events", json=body, headers=headers)
        r2 = client.post("/events", json=body, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r2.headers.get("X-Idempotent-Replayed") == "true"
    assert r1.json() == r2.json()


def test_events_idempotency_conflict_different_body() -> None:
    headers = {"Idempotency-Key": "idem-conflict"}
    with TestClient(create_app()) as client:
        r1 = client.post("/events", json=_event_json(0), headers=headers)
        r2 = client.post("/events", json=_event_json(1), headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert "different" in r2.json()["detail"].lower()


def test_batch_idempotency_replay() -> None:
    batch = {"events": [_event_json(0)]}
    headers = {"Idempotency-Key": "idem-batch-a"}
    with TestClient(create_app()) as client:
        r1 = client.post("/events/batch", json=batch, headers=headers)
        r2 = client.post("/events/batch", json=batch, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r2.headers.get("X-Idempotent-Replayed") == "true"
    assert r1.json() == r2.json()


def test_idempotency_key_too_long() -> None:
    long_key = "k" * 300
    with TestClient(create_app()) as client:
        r = client.post("/events", json=_event_json(), headers={"Idempotency-Key": long_key})
    assert r.status_code == 400


def test_idempotency_sqlite_store_has_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "cases.db"
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(db))
    with TestClient(create_app()) as client:
        assert (
            client.post(
                "/events",
                json=_event_json(99),
                headers={"Idempotency-Key": "sqlite-idem"},
            ).status_code
            == 200
        )
    import sqlite3

    conn = sqlite3.connect(str(db))
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='idempotency_keys'",
    )
    assert cur.fetchone() is not None
    conn.close()


def test_idempotency_replay_byte_identical_json() -> None:
    """Повтор с тем же JSON (пробел в батче не сменить через dict — используем raw при необходимости)."""
    raw = json.dumps(_event_json(2), separators=(",", ":"))
    headers = {"Idempotency-Key": "idem-raw", "Content-Type": "application/json"}
    with TestClient(create_app()) as client:
        r1 = client.post("/events", content=raw, headers=headers)
        r2 = client.post("/events", content=raw, headers=headers)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.headers.get("X-Idempotent-Replayed") == "true"
