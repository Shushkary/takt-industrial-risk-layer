from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import build_revision_from_env, create_app


def test_build_revision_from_env_empty() -> None:
    assert build_revision_from_env() is None


def test_build_revision_in_health_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_BUILD_REVISION", " abc123\t")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["build_revision"] == "abc123"
    assert h["takt_build_revision_env_set"] is True


def test_build_revision_truncated_to_256(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_BUILD_REVISION", "x" * 300)
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["build_revision"] == "x" * 256
    assert len(h["build_revision"]) == 256
    assert h["takt_build_revision_env_set"] is True


def test_health_build_revision_env_set_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_BUILD_REVISION", raising=False)
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_build_revision_env_set"] is False


def test_build_revision_in_live_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_BUILD_REVISION", "live-tag")
    with TestClient(create_app()) as client:
        j = client.get("/live").json()
    assert j["build_revision"] == "live-tag"


def test_build_revision_in_ready_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_BUILD_REVISION", "ready-tag")
    with TestClient(create_app()) as client:
        j = client.get("/ready").json()
    assert j["build_revision"] == "ready-tag"
