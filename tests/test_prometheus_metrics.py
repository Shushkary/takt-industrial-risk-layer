from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.infrastructure.http.prometheus_metrics import clear_prometheus_build_info, prometheus_client_available
from takt.interface_adapters.api.main import create_app


@pytest.fixture(autouse=True)
def _clear_takt_build_info_between_prometheus_tests() -> None:
    """Иначе **Info** регистрируется один раз на процесс — второй **create_app** не обновляет **revision**."""
    clear_prometheus_build_info()
    yield
    clear_prometheus_build_info()


@pytest.mark.skipif(prometheus_client_available(), reason="exercise TAKT_METRICS without prometheus-client")
def test_health_takt_metrics_env_true_but_endpoint_off_without_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_metrics_env_enabled"] is True
    assert h["prometheus_metrics_enabled"] is False


def test_metrics_route_404_when_disabled() -> None:
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
        assert h["takt_metrics_env_enabled"] is False
        assert h["prometheus_metrics_enabled"] is False
        assert client.get("/metrics").status_code == 404
        assert client.head("/metrics").status_code == 404


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_includes_takt_build_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_BUILD_REVISION", raising=False)
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        body = client.get("/metrics").text
    assert "takt_build_info" in body
    assert "revision" in body
    assert "unset" in body
    assert "version" in body


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_takt_build_info_revision_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_BUILD_REVISION", "prom-{sha}")
    with TestClient(create_app()) as client:
        body = client.get("/metrics").text
    assert "takt_build_info" in body
    assert "prom-{sha}" in body


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_endpoint_and_health_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-biz-metrics",
            },
        )
        h = client.get("/health").json()
        assert h["takt_metrics_env_enabled"] is True
        assert h["prometheus_metrics_enabled"] is True
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "no-store" in (r.headers.get("cache-control") or "").lower()
        body = r.text
    assert "takt_http_requests_total" in body
    assert "takt_http_request_duration_seconds" in body
    assert "takt_http_requests_in_progress" in body
    assert "takt_process_uptime_seconds" in body
    assert "takt_business_risk_score" in body
    assert "takt_business_invariant_hits_total" in body
    assert "takt_business_dq_degraded_ratio" in body
    assert "takt_business_event_to_case_latency_seconds" in body
    assert "takt_business_case_merges_total" in body
    assert "process_cpu_seconds_total" in body or "python_info" in body


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_expose_customer_journey_business_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Разрыв G-4 из `docs/customer_value_map.md`: «стало ли лучше» должно быть измеримо.

    Задержка конвейера (`event_to_case_latency`) на этот вопрос не отвечает — клиент считает
    время от появления дела до решения по нему и долю неопределённых вердиктов.
    """
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        assessed = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-journey-metrics",
            },
        )
        assert assessed.status_code == 200
        case_id = assessed.json()["case_id"]

        decided = client.post(
            f"/cases/{case_id}/decision",
            json={"status": "CONFIRMED", "reason": "подтверждено аналитиком"},
        )
        assert decided.status_code == 200

        body = client.get("/metrics").text

    assert "takt_business_case_to_decision_seconds" in body
    assert "takt_business_verdicts_total" in body
    # Дело без организационного документа не может дать определённый вердикт — метрика обязана
    # показывать именно это, иначе неопределённость снова прячется.
    assert 'verdict="UNDET"' in body


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_case_to_decision_seconds_comes_from_the_case_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Время считается по журналу дела, а не по моменту скрапа.

    Дело заведено в 2026-04-30, решение принято сейчас: если бы показатель мерил разницу
    между HTTP-вызовами, он был бы близок к нулю.
    """
    import re

    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-journey-clock",
            },
        ).json()["case_id"]
        client.post(f"/cases/{case_id}/decision", json={"status": "TRIAGE", "reason": "разбор"})
        text = client.get("/metrics").text

    total = re.search(r"^takt_business_case_to_decision_seconds_sum ([0-9.+-eE]+)\s*$", text, re.MULTILINE)
    count = re.search(r"^takt_business_case_to_decision_seconds_count ([0-9.+-eE]+)\s*$", text, re.MULTILINE)
    assert total is not None and count is not None
    assert float(count.group(1)) >= 1.0
    assert float(total.group(1)) >= 0.0


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_head_ok_empty_body_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        r = client.head("/metrics")
        assert r.status_code == 200
        assert (r.content or b"") == b""
        assert "no-store" in (r.headers.get("cache-control") or "").lower()


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_openapi_lists_head_for_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
    ops = spec["paths"]["/metrics"]
    assert "head" in ops and "get" in ops


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_includes_rate_limit_tracked_ips_when_limit_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "50")
    with TestClient(create_app()) as client:
        text = client.get("/metrics").text
        assert "takt_rate_limit_tracked_ips" in text
        m = re.search(r"^takt_rate_limit_tracked_ips ([0-9.+-eE]+)\s*$", text, re.MULTILINE)
        assert m is not None
        assert float(m.group(1)) == 0.0
        payload = {
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        }
        assert client.post("/assess", json=payload).status_code == 200
        text2 = client.get("/metrics").text
    m2 = re.search(r"^takt_rate_limit_tracked_ips ([0-9.+-eE]+)\s*$", text2, re.MULTILINE)
    assert m2 is not None
    assert float(m2.group(1)) >= 1.0


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_counts_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        client.get("/live")
        body = client.get("/metrics").text
    assert "takt_http_requests_total" in body
    assert "GET" in body
    assert "/live" in body


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_increments_rate_limit_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "1")
    with TestClient(create_app()) as client:
        body = {
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        }
        assert client.post("/assess", json=body).status_code == 200
        assert client.post("/assess", json=body).status_code == 429
        text = client.get("/metrics").text
    assert "takt_rate_limit_rejected_total" in text
    assert "takt_rate_limit_rejected_total 1" in text or "takt_rate_limit_rejected_total 1.0" in text
    assert "takt_rate_limit_tracked_ips" in text


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_process_uptime_near_health_uptime(monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    monkeypatch.setenv("TAKT_METRICS", "1")
    with TestClient(create_app()) as client:
        up_health = client.get("/health").json()["uptime_seconds"]
        body = client.get("/metrics").text
    m = re.search(r"^takt_process_uptime_seconds ([0-9.+-eE]+)\s*$", body, re.MULTILINE)
    assert m is not None
    up_prom = float(m.group(1))
    assert abs(up_prom - up_health) < 0.05


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_metrics_is_public_even_when_api_key_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    with TestClient(create_app()) as client:
        assert client.get("/metrics").status_code == 200
        assert client.head("/metrics").status_code == 200
        r = client.get("/metrics", headers={"X-TAKT-API-Key": "secret-token-32chars-long!!!!"})
        assert r.status_code == 200
        assert client.head("/metrics", headers={"X-TAKT-API-Key": "secret-token-32chars-long!!!!"}).status_code == 200


def test_prometheus_client_available_false_on_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real = builtins.__import__

    def imp(name: str, globals=None, locals=None, fromlist=(), level: int = 0):
        if name == "prometheus_client":
            raise ImportError("blocked")
        return real(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", imp)
    from takt.infrastructure.http.prometheus_metrics import prometheus_client_available

    assert prometheus_client_available() is False


def test_private_rate_limit_per_min_positive_invalid_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from takt.infrastructure.http import prometheus_metrics as pm

    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "not-an-int")
    assert pm._rate_limit_per_min_positive() is False


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_register_build_info_only_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import takt.infrastructure.http.prometheus_metrics as pm

    clear_prometheus_build_info()
    pm.register_prometheus_build_info(version="0.1.0", build_revision="rev-a")
    first = pm._BUILD_INFO
    pm.register_prometheus_build_info(version="9.9.9", build_revision="rev-b")
    assert pm._BUILD_INFO is first
    clear_prometheus_build_info()


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_clear_prometheus_build_info_swallows_registry_keyerror(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    import takt.infrastructure.http.prometheus_metrics as pm
    from prometheus_client import REGISTRY

    clear_prometheus_build_info()
    pm._BUILD_INFO = MagicMock()
    monkeypatch.setattr(REGISTRY, "unregister", lambda _c: (_ for _ in ()).throw(KeyError("missing")))
    pm.clear_prometheus_build_info()
    assert pm._BUILD_INFO is None


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_refresh_rate_limit_tracked_gauge_noop_without_app(monkeypatch: pytest.MonkeyPatch) -> None:
    import takt.infrastructure.http.prometheus_metrics as pm

    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "10")
    pm.register_prometheus_rate_limit_app(None)
    pm._refresh_rate_limit_tracked_gauge()


@pytest.mark.skipif(not prometheus_client_available(), reason="prometheus-client not installed")
def test_refresh_rate_limit_tracked_gauge_swallows_bad_app_state(monkeypatch: pytest.MonkeyPatch) -> None:
    import takt.infrastructure.http.prometheus_metrics as pm

    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "5")

    class BadApp:
        pass

    pm.register_prometheus_rate_limit_app(BadApp())
    pm._refresh_rate_limit_tracked_gauge()


def test_record_rate_limit_rejection_noop_when_counter_import_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    import takt.infrastructure.http.prometheus_metrics as pm

    monkeypatch.setenv("TAKT_METRICS", "1")
    pm._RL_REJECT = None
    real = builtins.__import__

    def imp(name: str, globals=None, locals=None, fromlist=(), level: int = 0):
        if name == "prometheus_client":
            raise ImportError("no counter")
        return real(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", imp)
    pm.record_rate_limit_rejection()


def test_prometheus_metrics_middleware_bypasses_when_gauges_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import takt.infrastructure.http.prometheus_metrics as pm
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    monkeypatch.setattr(pm, "_in_progress_gauge", lambda: (_ for _ in ()).throw(ImportError("no prom")))

    async def ping(_request):
        return PlainTextResponse("pong")

    app = Starlette(routes=[Route("/p", ping)])
    app.add_middleware(pm.PrometheusMetricsMiddleware)
    with TestClient(app) as c:
        assert c.get("/p").status_code == 200
        assert c.get("/p").text == "pong"
