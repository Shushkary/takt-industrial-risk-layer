from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_create_app_uses_takt_config_env_path(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    project_cfg = repo_root / "config" / "risk_weights.yaml"
    alt = repo_root / "tests" / ".pytest_takt_config_weights.yaml"
    alt.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(project_cfg, alt)
        monkeypatch.setenv("TAKT_CONFIG", str(alt))
        with TestClient(create_app()) as client:
            h = client.get("/health")
            assert h.status_code == 200
            assert h.json()["takt_config_env_set"] is True
    finally:
        alt.unlink(missing_ok=True)


def test_health_takt_config_env_set_false_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_CONFIG", raising=False)
    with TestClient(create_app()) as client:
        assert client.get("/health").json()["takt_config_env_set"] is False


def test_create_app_rejects_takt_config_outside_project(monkeypatch) -> None:
    outside = Path(Path(__file__).anchor) / "risk_weights.yaml"
    monkeypatch.setenv("TAKT_CONFIG", str(outside))
    with pytest.raises(ValueError, match="project root"):
        create_app()
