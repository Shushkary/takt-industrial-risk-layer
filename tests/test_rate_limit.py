from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from takt.infrastructure.http.rate_limit_middleware import (
    client_ip_for_rate_limit,
    prune_rate_limit_store,
    rate_limit_ip_header_from_env,
    rate_limit_max_tracked_ips_from_env,
)
from takt.interface_adapters.api.main import create_app


def test_prune_rate_limit_store_removes_stale_window() -> None:
    store: dict[str, tuple[int, int]] = {"a": (10, 1), "b": (11, 2)}
    prune_rate_limit_store(store, current_win=11, max_entries=100)
    assert store == {"b": (11, 2)}


def test_prune_rate_limit_store_trims_oldest_when_over_cap() -> None:
    store = {f"k{i}": (5, 1) for i in range(5)}
    prune_rate_limit_store(store, current_win=5, max_entries=3)
    assert len(store) == 3
    assert all(store[k] == (5, 1) for k in store)


def test_prune_rate_limit_store_stale_removal_fits_before_overflow_trim() -> None:
    """После удаления прошлых окон размер ≤ cap — без отрезания «лишних» ключей текущего окна."""
    store = {"old_a": (9, 1), "old_b": (9, 1), "cur_c": (10, 1), "cur_d": (10, 1)}
    prune_rate_limit_store(store, current_win=10, max_entries=3)
    assert store == {"cur_c": (10, 1), "cur_d": (10, 1)}


def test_rate_limit_max_tracked_ips_from_env_defaults_and_clamps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_RATE_LIMIT_MAX_IPS", raising=False)
    assert rate_limit_max_tracked_ips_from_env() == 8192
    monkeypatch.setenv("TAKT_RATE_LIMIT_MAX_IPS", "128")
    assert rate_limit_max_tracked_ips_from_env() == 256
    monkeypatch.setenv("TAKT_RATE_LIMIT_MAX_IPS", "999999")
    assert rate_limit_max_tracked_ips_from_env() == 500_000
    monkeypatch.setenv("TAKT_RATE_LIMIT_MAX_IPS", "nope")
    assert rate_limit_max_tracked_ips_from_env() == 8192


def test_rate_limit_ip_header_from_env_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_RATE_LIMIT_IP_HEADER", raising=False)
    assert rate_limit_ip_header_from_env() is None
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "CF-Connecting-IP")
    assert rate_limit_ip_header_from_env() == "CF-Connecting-IP"
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "True-Client-IP")
    assert rate_limit_ip_header_from_env() == "True-Client-IP"
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "bad header")
    assert rate_limit_ip_header_from_env() is None
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "x" * 65)
    assert rate_limit_ip_header_from_env() is None
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "")
    assert rate_limit_ip_header_from_env() is None


def test_health_reports_rate_limit_max_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "60")
    monkeypatch.setenv("TAKT_RATE_LIMIT_MAX_IPS", "4096")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["rate_limit_max_tracked_ips"] == 4096
    assert h["rate_limit_tracked_ips"] == 0
    assert h["takt_rate_limit_max_ips_env_set"] is True
    assert h["takt_rate_limit_ip_header_env_set"] is False


def test_rate_limit_separate_buckets_per_custom_header_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "True-Client-IP")
    monkeypatch.setenv("TAKT_TRUSTED_PROXIES", "127.0.0.1/32")
    with TestClient(create_app(), client=("127.0.0.1", 50000)) as client:
        body = {
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        }
        h1 = {"True-Client-IP": "203.0.113.10"}
        h2 = {"True-Client-IP": "203.0.113.20"}
        assert client.post("/assess", json=body, headers=h1).status_code == 200
        assert client.post("/assess", json=body, headers=h2).status_code == 200
        assert client.post("/assess", json=body, headers=h1).status_code == 429


def test_health_reports_rate_limit_ip_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "10")
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "CF-Connecting-IP")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["rate_limit_ip_header"] == "CF-Connecting-IP"
    assert h["takt_rate_limit_ip_header_env_set"] is True
    assert h["takt_rate_limit_max_ips_env_set"] is False


@pytest.fixture
def limited_client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "4")
    with TestClient(create_app()) as client:
        yield client


def test_rate_limit_allows_then_429(limited_client: TestClient) -> None:
    body = {
        "observed_at": "2026-04-30T20:00:00+00:00",
        "operation": "PING",
        "asset_id": "plc-z",
    }
    for i in range(4):
        r = limited_client.post("/assess", json=body)
        assert r.status_code == 200
        assert r.headers.get("X-RateLimit-Limit") == "4"
        assert r.headers.get("X-RateLimit-Remaining") == str(3 - i)
        assert int(r.headers.get("X-RateLimit-Reset", "0")) > 0
    r5 = limited_client.post("/assess", json=body)
    assert r5.status_code == 429
    j = r5.json()
    assert j["detail"] == "rate limit exceeded"
    assert j.get("request_id") == r5.headers.get("X-Request-ID")
    assert "Retry-After" in r5.headers
    assert int(r5.headers["Retry-After"]) >= 1
    assert r5.headers.get("X-RateLimit-Limit") == "4"
    assert r5.headers.get("X-RateLimit-Remaining") == "0"
    assert int(r5.headers.get("X-RateLimit-Reset", "0")) == int(r.headers.get("X-RateLimit-Reset", "0"))


def test_rate_limit_exempt_live(limited_client: TestClient) -> None:
    for _ in range(20):
        assert limited_client.get("/live").status_code == 200


def test_health_rate_limit_tracked_ips_after_requests(limited_client: TestClient) -> None:
    body = {
        "observed_at": "2026-04-30T20:00:00+00:00",
        "operation": "PING",
        "asset_id": "plc-z",
    }
    assert limited_client.post("/assess", json=body).status_code == 200
    h = limited_client.get("/health").json()
    assert h["rate_limit_tracked_ips"] >= 1


def test_health_reports_rate_limit_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "120")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_rate_limit_env_set"] is True
    assert h["takt_rate_limit_max_ips_env_set"] is False
    assert h["takt_rate_limit_ip_header_env_set"] is False
    assert h["rate_limit_per_minute"] == 120
    assert h["rate_limit_max_tracked_ips"] == 8192
    assert h["rate_limit_tracked_ips"] == 0
    assert "rate_limit_ip_header" not in h


def test_health_rate_limit_subordinate_env_set_without_active_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_MAX_IPS", "2048")
    monkeypatch.setenv("TAKT_RATE_LIMIT_IP_HEADER", "bad header")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_rate_limit_max_ips_env_set"] is True
    assert h["takt_rate_limit_ip_header_env_set"] is True
    assert "rate_limit_per_minute" not in h


def test_health_rate_limit_env_set_but_limit_inactive_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "0")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_rate_limit_env_set"] is True
    assert "rate_limit_per_minute" not in h
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "not-int")
    with TestClient(create_app()) as client:
        h2 = client.get("/health").json()
    assert h2["takt_rate_limit_env_set"] is True
    assert "rate_limit_per_minute" not in h2


def _scope(*, headers: list[tuple[bytes, bytes]], client: tuple[str, int] | None) -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": headers,
        "scheme": "http",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "client": client,
        "server": ("test", 80),
    }


def test_client_ip_ignores_xff_when_upstream_not_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_TRUSTED_PROXIES", raising=False)
    hdrs = [(b"x-forwarded-for", b"203.0.113.7, 10.0.0.1")]
    req = Request(_scope(headers=hdrs, client=("127.0.0.1", 50_000)))
    assert client_ip_for_rate_limit(req) == "127.0.0.1"


def test_client_ip_uses_xff_behind_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_TRUSTED_PROXIES", "127.0.0.1/32,10.0.0.0/8")
    hdrs = [(b"x-forwarded-for", b"203.0.113.7, 10.0.0.1")]
    req = Request(_scope(headers=hdrs, client=("127.0.0.1", 50_000)))
    assert client_ip_for_rate_limit(req) == "203.0.113.7"


def test_client_ip_unknown_without_client_or_forwarded_headers() -> None:
    req = Request(_scope(headers=[], client=None))
    assert client_ip_for_rate_limit(req) == "unknown"
