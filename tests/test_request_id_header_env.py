from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_request_id_from_alternate_header_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Correlation-ID")
    with TestClient(create_app()) as client:
        r = client.get(
            "/live",
            headers={"X-Correlation-ID": "corr-1", "X-Request-ID": "req-2"},
        )
        assert r.headers.get("X-Request-ID") == "corr-1"


def test_request_id_falls_back_to_x_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Correlation-ID")
    with TestClient(create_app()) as client:
        r = client.get("/live", headers={"X-Request-ID": "req-only"})
        assert r.headers.get("X-Request-ID") == "req-only"


def test_invalid_takt_request_id_header_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "bad name!")
    with TestClient(create_app()) as client:
        r = client.get("/live", headers={"X-Request-ID": "ok-rid"})
        assert r.headers.get("X-Request-ID") == "ok-rid"
        h = client.get("/health").json()
        assert h["takt_request_id_header_env_set"] is True
        assert "request_id_alternate_header" not in h


def test_health_shows_request_id_alternate_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Correlation-ID")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["request_id_alternate_header"] == "X-Correlation-ID"
    assert h["takt_request_id_header_env_set"] is True


def test_health_omits_alternate_when_env_duplicates_x_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Request-ID")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert "request_id_alternate_header" not in h
    assert h["takt_request_id_header_env_set"] is True
