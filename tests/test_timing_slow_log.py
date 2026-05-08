from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.infrastructure.http.timing_middleware import slow_log_threshold_seconds
from takt.interface_adapters.api.main import create_app


@pytest.mark.parametrize(
    ("env_val", "expected"),
    [
        ("", None),
        ("  ", None),
        ("0", None),
        ("-1", None),
        ("not-a-float", None),
        ("1.5", 1.5),
        ("0.001", 0.001),
    ],
)
def test_slow_log_threshold_seconds(monkeypatch: pytest.MonkeyPatch, env_val: str, expected: float | None) -> None:
    monkeypatch.delenv("TAKT_SLOW_REQUEST_LOG_SEC", raising=False)
    if env_val != "":
        monkeypatch.setenv("TAKT_SLOW_REQUEST_LOG_SEC", env_val)
    assert slow_log_threshold_seconds() == expected


def test_health_includes_slow_request_log_threshold_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SLOW_REQUEST_LOG_SEC", "1.5")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["slow_request_log_threshold_sec"] == 1.5
    assert h["takt_slow_request_log_env_set"] is True


def test_health_slow_request_log_env_set_but_inactive_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SLOW_REQUEST_LOG_SEC", "not-a-float")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_slow_request_log_env_set"] is True
    assert "slow_request_log_threshold_sec" not in h


def test_slow_request_emits_warning_when_over_threshold(caplog, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import logging

    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from takt.infrastructure.http.timing_middleware import ProcessTimeMiddleware

    monkeypatch.setenv("TAKT_SLOW_REQUEST_LOG_SEC", "0.02")

    async def slow(_request):
        await asyncio.sleep(0.06)
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/z", slow)])
    app.add_middleware(ProcessTimeMiddleware)
    caplog.set_level(logging.WARNING)
    with TestClient(app) as c:
        assert c.get("/z").status_code == 200
    assert any("slow request" in rec.message for rec in caplog.records)
