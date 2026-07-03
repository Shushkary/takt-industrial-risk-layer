from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.infrastructure.config.settings_helpers import apply_storage_env_overrides
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.stores.sqlite_store import CURRENT_DB_SCHEMA_VERSION
from takt.interface_adapters.api.main import create_app


def test_apply_storage_env_sqlite_merges_into_existing(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    w: dict = {"storage": {"backend": "memory", "sqlite_path": "data/custom.db"}}
    apply_storage_env_overrides(w)
    assert w["storage"]["backend"] == "sqlite"
    assert w["storage"]["sqlite_path"] == "data/custom.db"


def test_apply_storage_env_sqlite_without_storage_section(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    w: dict = {}
    apply_storage_env_overrides(w)
    assert w["storage"]["backend"] == "sqlite"
    assert w["storage"]["sqlite_path"] == "data/takt_cases.db"


def test_apply_storage_env_memory_overrides_yaml(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_STORAGE", "memory")
    w = {"storage": {"backend": "sqlite", "sqlite_path": "data/x.db"}}
    apply_storage_env_overrides(w)
    assert w["storage"]["backend"] == "memory"


def test_apply_storage_env_invalid_raises(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_STORAGE", "redis")
    with pytest.raises(ValueError, match="TAKT_STORAGE"):
        apply_storage_env_overrides({"storage": {"backend": "memory"}})


def test_create_app_takt_storage_forces_sqlite(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "env.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "memory"}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(db))
    with TestClient(create_app()) as c:
        h = c.get("/health").json()
        assert h["case_storage"] == "sqlite"
        assert h["expected_behavior_storage"] == "sqlite"
        assert h["sqlite_schema_version"] == CURRENT_DB_SCHEMA_VERSION
        assert h["sqlite_busy_timeout_ms"] == 5000
        assert h["takt_storage_env_set"] is True
        assert h["takt_sqlite_path_env_set"] is True


def test_health_storage_env_flags_false_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_STORAGE", raising=False)
    monkeypatch.delenv("TAKT_SQLITE_PATH", raising=False)
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_storage_env_set"] is False
    assert h["takt_sqlite_path_env_set"] is False
