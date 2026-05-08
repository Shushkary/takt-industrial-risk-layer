from __future__ import annotations

import pytest

from takt.infrastructure.stores.sqlite_store import sqlite_busy_timeout_ms_from_env


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", 5000),
        ("5000", 5000),
        ("10000", 10_000),
        ("300000", 300_000),
        ("99", 5000),
        ("300001", 5000),
        ("not-int", 5000),
    ],
)
def test_sqlite_busy_timeout_ms_from_env_parsing(monkeypatch: pytest.MonkeyPatch, raw: str, expected: int) -> None:
    monkeypatch.delenv("TAKT_SQLITE_BUSY_TIMEOUT_MS", raising=False)
    if raw:
        monkeypatch.setenv("TAKT_SQLITE_BUSY_TIMEOUT_MS", raw)
    assert sqlite_busy_timeout_ms_from_env() == expected


def test_health_takt_sqlite_busy_timeout_env_set_on_memory_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    monkeypatch.setenv("TAKT_SQLITE_BUSY_TIMEOUT_MS", "8000")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["case_storage"] == "memory"
    assert h["takt_sqlite_busy_timeout_ms_env_set"] is True
    assert "sqlite_busy_timeout_ms" not in h


def test_health_sqlite_reports_custom_busy_timeout(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from takt.infrastructure.config.weights_loader import load_risk_weights
    from takt.interface_adapters.api.main import create_app

    db = tmp_path / "busy.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setenv("TAKT_SQLITE_BUSY_TIMEOUT_MS", "15000")
    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["sqlite_busy_timeout_ms"] == 15_000
    assert h["takt_sqlite_busy_timeout_ms_env_set"] is True
