from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_api_key_disabled_allows_assess(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            json={
                "observed_at": "2026-05-03T12:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-no-key",
            },
        )
        assert r.status_code == 200


def test_api_key_blocks_without_header(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            json={
                "observed_at": "2026-05-03T12:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-need-key",
            },
        )
        assert r.status_code == 401
        j = r.json()
        assert j["detail"] == "missing or invalid API key"
        assert j.get("request_id") == r.headers.get("X-Request-ID")
        assert r.headers.get("x-process-time") is not None
        assert r.headers.get("x-request-id") is not None
        assert r.headers.get("x-request-id") is not None


def test_api_key_public_paths_without_header(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/live").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.head("/health").status_code == 200
        assert client.head("/live").status_code == 200
        assert client.head("/ready").status_code == 200
        assert client.head("/openapi.json").status_code == 200
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        assert client.get("/metrics").status_code in (200, 404)
        assert client.head("/metrics").status_code in (200, 404)


def test_startup_fails_when_auth_required_without_api_key(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_PROFILE", "prod")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    app = create_app()
    with pytest.raises(RuntimeError, match="FATAL: TAKT_API_KEY"):
        with TestClient(app):
            pass


def test_api_key_header_allows_assess(monkeypatch) -> None:
    key = "secret-token-32chars-long!!!!"
    monkeypatch.setenv("TAKT_API_KEY", key)
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            json={
                "observed_at": "2026-05-03T12:01:00+00:00",
                "operation": "READ",
                "asset_id": "plc-with-key",
            },
            headers={"X-TAKT-API-Key": key},
        )
        assert r.status_code == 200


def test_api_key_bearer_allows_assess(monkeypatch) -> None:
    key = "secret-token-32chars-long!!!!"
    monkeypatch.setenv("TAKT_API_KEY", key)
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            json={
                "observed_at": "2026-05-03T12:02:00+00:00",
                "operation": "READ",
                "asset_id": "plc-bearer",
            },
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r.status_code == 200


def test_openapi_includes_takt_api_key_scheme_always(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
    scheme = spec["components"]["securitySchemes"].get("TaktApiKey")
    assert scheme is not None
    assert scheme.get("name") == "X-TAKT-API-Key"
    assert "security" not in spec["paths"]["/cases"]["get"]


def test_openapi_marks_protected_routes_when_api_key_env_set(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
    cases_get = spec["paths"]["/cases"]["get"]
    assert cases_get["security"] == [{"TaktApiKey": []}]
    assert "security" not in spec["paths"]["/health"]["get"]
