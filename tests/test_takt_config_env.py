from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_create_app_uses_takt_config_env_path(tmp_path, monkeypatch) -> None:
    project_cfg = Path(__file__).resolve().parents[1] / "config" / "risk_weights.yaml"
    alt = tmp_path / "weights_copy.yaml"
    shutil.copyfile(project_cfg, alt)
    monkeypatch.setenv("TAKT_CONFIG", str(alt))
    with TestClient(create_app()) as client:
        h = client.get("/health")
        assert h.status_code == 200
        assert h.json()["takt_config_env_set"] is True


def test_health_takt_config_env_set_false_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_CONFIG", raising=False)
    with TestClient(create_app()) as client:
        assert client.get("/health").json()["takt_config_env_set"] is False


def test_create_app_rejects_takt_config_outside_project(monkeypatch) -> None:
    outside = Path(Path(__file__).anchor) / "risk_weights.yaml"
    monkeypatch.setenv("TAKT_CONFIG", str(outside))
    with pytest.raises(ValueError, match="project root"):
        create_app()
