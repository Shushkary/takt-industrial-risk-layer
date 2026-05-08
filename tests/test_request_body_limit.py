from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from takt.infrastructure.http.request_body_limit_middleware import (
    max_request_body_bytes_from_env,
    request_has_chunked_transfer_encoding,
)
from takt.interface_adapters.api.main import create_app


def test_chunked_transfer_encoding_detection() -> None:
    def hdrs(te: str) -> Request:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "headers": [(b"transfer-encoding", te.encode("ascii"))],
            "scheme": "http",
            "path": "/x",
            "raw_path": b"/x",
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "server": ("test", 80),
        }
        return Request(scope)

    assert request_has_chunked_transfer_encoding(hdrs("chunked")) is True
    assert request_has_chunked_transfer_encoding(hdrs("gzip, chunked")) is True
    assert request_has_chunked_transfer_encoding(hdrs("GZIP, CHUNKED")) is True
    assert request_has_chunked_transfer_encoding(hdrs("gzip")) is False


@pytest.mark.parametrize(
    ("env_val", "expected"),
    [
        ("", None),
        ("  ", None),
        ("0", None),
        ("-2", None),
        ("bad", None),
        ("1", 1024 * 1024),
        ("0.5", int(0.5 * 1024 * 1024)),
    ],
)
def test_max_request_body_bytes_from_env(monkeypatch: pytest.MonkeyPatch, env_val: str, expected: int | None) -> None:
    monkeypatch.delenv("TAKT_MAX_REQUEST_BODY_MB", raising=False)
    if env_val != "":
        monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", env_val)
    assert max_request_body_bytes_from_env() == expected


def test_health_includes_max_request_body_bytes_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "2")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["max_request_body_bytes"] == 2 * 1024 * 1024
    assert h["takt_max_request_body_mb_env_set"] is True


def test_request_body_limit_413_when_content_length_exceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", str(800 / (1024 * 1024)))
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            content=b"x" * 1200,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 413
    assert "too large" in r.json()["detail"].lower()
    assert r.json().get("request_id") == r.headers.get("X-Request-ID")
    assert r.headers.get("x-process-time")
    assert r.headers.get("x-request-id")


def test_post_invalid_content_length_skips_size_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "1")
    with TestClient(create_app()) as client:
        body = b'{"observed_at":"2026-04-30T20:00:00+00:00","operation":"PING","asset_id":"plc-z"}'
        r = client.post(
            "/assess",
            content=body,
            headers={"Content-Type": "application/json", "Content-Length": "not-int"},
        )
    assert r.status_code == 200


def test_post_blank_content_length_skips_size_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "1")
    with TestClient(create_app()) as client:
        body = b'{"observed_at":"2026-04-30T20:00:00+00:00","operation":"PING","asset_id":"plc-z"}'
        r = client.post(
            "/assess",
            content=body,
            headers={"Content-Type": "application/json", "Content-Length": "   "},
        )
    assert r.status_code == 200


def test_post_numeric_content_length_under_limit_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "1")
    with TestClient(create_app()) as client:
        body = b'{"observed_at":"2026-04-30T20:00:00+00:00","operation":"PING","asset_id":"plc-z"}'
        r = client.post(
            "/assess",
            content=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
    assert r.status_code == 200


def test_health_max_request_body_env_set_but_inactive_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "bad")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
        assert h["takt_max_request_body_mb_env_set"] is True
        assert "max_request_body_bytes" not in h
        r = client.post(
            "/assess",
            content=b"x" * 50_000,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code != 413


def test_request_body_limit_disabled_by_default() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            content=b"x" * 50_000,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code != 413


def test_request_body_limit_skipped_for_get(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", str(10 / (1024 * 1024)))
    with TestClient(create_app()) as client:
        assert client.get("/live").status_code == 200


def test_request_body_chunked_rejected_411_when_limit_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_MAX_REQUEST_BODY_MB", "4")
    with TestClient(create_app()) as client:
        payload = {
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        }
        raw = json.dumps(payload).encode("utf-8")

        def chunks():
            yield raw

        r = client.post("/assess", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 411
    assert "chunked" in r.json()["detail"].lower()
    assert "content-length" in r.json()["detail"].lower()
    assert r.json().get("request_id") == r.headers.get("X-Request-ID")
    assert r.headers.get("x-process-time")
    assert r.headers.get("x-request-id")
