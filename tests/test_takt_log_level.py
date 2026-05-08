from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import apply_takt_api_log_level_from_env, create_app


def test_apply_takt_log_level_invalid_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_LOG_LEVEL", "not-a-level")
    log = logging.getLogger("takt.api")
    log.setLevel(logging.NOTSET)
    apply_takt_api_log_level_from_env()
    assert log.level == logging.NOTSET
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_log_level_env_set"] is True


def test_health_api_log_level_reflects_takt_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_LOG_LEVEL", "DEBUG")
    log = logging.getLogger("takt.api")
    try:
        with TestClient(create_app()) as client:
            h = client.get("/health").json()
        assert h["api_log_level"] == "DEBUG"
        assert h["takt_log_level_env_set"] is True
    finally:
        log.setLevel(logging.NOTSET)


def test_takt_log_level_warn_alias_maps_to_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_LOG_LEVEL", "warn")
    log = logging.getLogger("takt.api")
    try:
        with TestClient(create_app()) as client:
            h = client.get("/health").json()
        assert h["api_log_level"] == "WARNING"
        assert h["takt_log_level_env_set"] is True
    finally:
        log.setLevel(logging.NOTSET)
