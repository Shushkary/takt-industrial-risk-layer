"""Спринт 1: профиль dev, журнал безопасности, mTLS-actor, rate_limit.proxy_mode в /health."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_startup_without_key_fails_prod_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_PROFILE", "prod")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    app = create_app()
    with pytest.raises(RuntimeError, match="FATAL: TAKT_API_KEY"):
        with TestClient(app):
            pass


def test_startup_without_key_succeeds_dev_profile(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_PROFILE", "dev")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    caplog.set_level("WARNING", logger="takt.auth")
    with TestClient(create_app()) as c:
        assert c.get("/health").status_code == 200
    assert any("TAKT_PROFILE=dev" in r.message for r in caplog.records)


def test_health_rate_limit_proxy_mode_direct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("TAKT_TRUSTED_PROXY_CIDRS", raising=False)
    with TestClient(create_app()) as c:
        h = c.get("/health").json()
    assert h["rate_limit"]["proxy_mode"] == "direct"


def test_health_rate_limit_proxy_mode_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    with TestClient(create_app()) as c:
        h = c.get("/health").json()
    assert h["rate_limit"]["proxy_mode"] == "trusted_header"


def test_security_log_auth_failure_on_401(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    monkeypatch.setenv("TAKT_SECURITY_LOG_FILE", str(tmp_path / "sec.log"))
    with TestClient(create_app()) as c:
        r = c.post(
            "/assess",
            json={
                "observed_at": "2026-05-03T12:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-sec",
            },
        )
        assert r.status_code == 401
        h = c.get("/health").json()
    assert h["security_log"]["entries_last_hour"] >= 1
    lines = (tmp_path / "sec.log").read_text(encoding="utf-8").strip().splitlines()
    auth_evts: list[dict] = []
    for line in lines:
        obj = json.loads(line)
        if obj.get("msgid") == "auth_failure":
            auth_evts.append(obj)
    assert len(auth_evts) == 1
    assert auth_evts[0]["structured_data"]["path"] == "/assess"


def test_mtls_dn_actor_when_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAKT_MTLS_DN_HEADER", "X-Test-DN")
    monkeypatch.setenv("TAKT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    from takt.infrastructure.security.request_actor import security_actor_from_request

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "headers": [(b"x-test-dn", b"CN=operator")],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "scheme": "http",
        "http_version": "1.1",
    }

    async def _empty_receive() -> dict:
        return {"type": "http.disconnect"}

    from starlette.requests import Request

    r = Request(scope, _empty_receive)
    assert security_actor_from_request(r) == "CN=operator"


def test_trusted_proxies_merges_cidrs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_TRUSTED_PROXIES", "10.0.0.0/8")
    monkeypatch.setenv("TAKT_TRUSTED_PROXY_CIDRS", "192.168.0.0/16")
    from takt.infrastructure.security.trusted_proxies import trusted_proxy_networks_from_env

    assert len(trusted_proxy_networks_from_env()) == 2
