from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.http.cache_control_middleware import catalog_cache_max_age_sec
from takt.infrastructure.http.cors_from_env import (
    add_cors_middleware_if_configured,
    cors_middleware_enabled_from_env,
)


def test_catalog_cache_max_age_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", raising=False)
    assert catalog_cache_max_age_sec() == 60


def test_catalog_cache_max_age_custom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "120")
    assert catalog_cache_max_age_sec() == 120


def test_catalog_cache_max_age_caps_at_one_day(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "999999")
    assert catalog_cache_max_age_sec() == 86400


def test_catalog_cache_max_age_zero_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "0")
    assert catalog_cache_max_age_sec() is None


def test_catalog_cache_max_age_invalid_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "not-int")
    assert catalog_cache_max_age_sec() == 60


def test_cors_middleware_enabled_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_CORS_ORIGINS", raising=False)
    assert cors_middleware_enabled_from_env() is False
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "http://app.example")
    assert cors_middleware_enabled_from_env() is True
    monkeypatch.setenv("TAKT_CORS_ORIGINS", " * ")
    assert cors_middleware_enabled_from_env() is True
    monkeypatch.setenv("TAKT_CORS_ORIGINS", ", , ")
    assert cors_middleware_enabled_from_env() is False


def test_add_cors_middleware_if_configured_registers(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    before = len(app.user_middleware)
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "https://front.example")
    add_cors_middleware_if_configured(app)
    assert len(app.user_middleware) == before + 1


def test_add_cors_middleware_skips_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    before = len(app.user_middleware)
    monkeypatch.delenv("TAKT_CORS_ORIGINS", raising=False)
    add_cors_middleware_if_configured(app)
    assert len(app.user_middleware) == before


def test_webhook_async_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from takt.infrastructure.export.siem_webhook import post_case_to_webhook

    case = Case(
        case_id="c-async",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    n = {"i": 0}

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, *_a: object, **_kw: object) -> MagicMock:
            n["i"] += 1
            if n["i"] == 1:
                raise httpx.ConnectError("fail", request=MagicMock())
            ok = MagicMock()
            ok.status_code = 203
            ok.raise_for_status = MagicMock()
            return ok

    monkeypatch.setattr(
        "takt.infrastructure.export.siem_webhook.httpx.AsyncClient",
        lambda **_kw: FakeClient(),
    )

    async def instant_sleep(_sec: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    async def run() -> int:
        return await post_case_to_webhook(
            case,
            "http://127.0.0.1/ingest",
            retries=3,
            backoff_sec=0.01,
        )

    code = asyncio.run(run())
    assert code == 203
    assert n["i"] == 2


def test_webhook_async_retries_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from takt.infrastructure.export.siem_webhook import post_case_to_webhook

    case = Case(
        case_id="c-async-fail",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    n = {"i": 0}

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, *_a: object, **_kw: object) -> MagicMock:
            n["i"] += 1
            raise httpx.ConnectError("fail", request=MagicMock())

    monkeypatch.setattr(
        "takt.infrastructure.export.siem_webhook.httpx.AsyncClient",
        lambda **_kw: FakeClient(),
    )

    async def instant_sleep(_sec: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    async def run() -> None:
        await post_case_to_webhook(
            case,
            "http://127.0.0.1/ingest",
            retries=2,
            backoff_sec=0.01,
        )

    with pytest.raises(httpx.ConnectError):
        asyncio.run(run())
    assert n["i"] == 2
