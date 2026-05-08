from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_openapi_middleware_error_schema_exists() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        schema = spec["components"]["schemas"].get("MiddlewareErrorJson")
        assert schema is not None
        props = schema["properties"]
        assert "detail" in props
        assert "request_id" in props
        paths = spec.get("paths", {})
        assert paths, "expected non-empty paths for default error responses"
        sample_ops = 0
        sample_with_mw_errors = 0
        for path_item in paths.values():
            for _, op in path_item.items():
                if not isinstance(op, dict) or "responses" not in op:
                    continue
                sample_ops += 1
                r = op["responses"]
                if all(code in r for code in ("401", "411", "413", "429")):
                    sample_with_mw_errors += 1
        assert sample_ops > 0
        assert sample_with_mw_errors > 0


def test_health_default_cors_hsts_env_flags_false() -> None:
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_cors_origins_env_set"] is False
    assert h["takt_hsts_max_age_env_set"] is False
    assert h["takt_hsts_preload_env_set"] is False


def test_openapi_health_response_schema_exists() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        schema = spec["components"]["schemas"].get("HealthResponse")
        assert schema is not None
        props = schema["properties"]
        for key in (
            "version",
            "python_version",
            "python_implementation",
            "api_log_level",
            "uptime_seconds",
            "booted_at_utc",
            "process_id",
            "hostname",
            "platform",
            "python_executable",
            "working_directory",
            "api_key_enabled",
            "auth",
            "siem",
            "proxy",
            "rate_limit",
            "security_log",
            "cors_enabled",
            "takt_cors_origins_env_set",
            "hsts_enabled",
            "hsts_preload_enabled",
            "takt_hsts_max_age_env_set",
            "takt_hsts_preload_env_set",
            "gzip_minimum_size_bytes",
            "openapi_servers_count",
            "request_id_alternate_header",
            "full_json_max_cases",
            "export_pdf_unicode_font_configured",
            "siem_webhook_retries",
            "sqlite_schema_version",
            "sqlite_busy_timeout_ms",
            "max_request_body_bytes",
            "catalog_cache_max_age_sec",
            "prometheus_metrics_enabled",
            "forensic_crypto_mode",
            "forensic_strict_ready",
            "forensic_strict_missing",
            "rate_limit_per_minute",
            "rate_limit_max_tracked_ips",
            "rate_limit_tracked_ips",
            "rate_limit_ip_header",
            "build_revision",
        ):
            assert key in props


def test_openapi_servers_from_env_single_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_OPENAPI_SERVER_URL", "https://takt.example/v1/")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
    assert spec.get("servers") == [
        {"url": "https://takt.example/v1", "description": "From TAKT_OPENAPI_SERVER_URL"},
    ]


def test_openapi_servers_from_env_multiple_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_OPENAPI_SERVER_URL", "https://a.example, https://b.example/api/")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
    assert spec["servers"] == [
        {"url": "https://a.example", "description": "From TAKT_OPENAPI_SERVER_URL"},
        {"url": "https://b.example/api", "description": "From TAKT_OPENAPI_SERVER_URL"},
    ]


def test_openapi_servers_empty_when_env_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_OPENAPI_SERVER_URL", "ftp://bad, not-a-url")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        assert "servers" not in spec
        h = client.get("/health").json()
    assert h["openapi_servers_count"] == 0
    assert h["takt_openapi_server_url_env_set"] is True


def test_openapi_servers_mixed_valid_invalid_uses_only_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_OPENAPI_SERVER_URL", "ftp://bad.example, https://good.example/path/")
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        assert spec["servers"] == [
            {"url": "https://good.example/path", "description": "From TAKT_OPENAPI_SERVER_URL"},
        ]
        assert client.get("/health").json()["openapi_servers_count"] == 1


def test_health_openapi_servers_count_matches_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_OPENAPI_SERVER_URL", "https://one.example, https://two.example")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["openapi_servers_count"] == 2
    assert h["takt_openapi_server_url_env_set"] is True


def test_openapi_live_and_ready_response_schemas_exist() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        schemas = spec["components"]["schemas"]
        live = schemas.get("LiveResponse")
        assert live is not None
        assert "live" in live["properties"]
        assert "version" in live["properties"]
        assert "build_revision" in live["properties"]
        ready = schemas.get("ReadyResponse")
        assert ready is not None
        for key in (
            "ready",
            "case_storage",
            "expected_behavior_storage",
            "forensic_crypto_mode",
            "forensic_strict_ready",
            "forensic_strict_missing",
            "build_revision",
        ):
            assert key in ready["properties"]


def test_openapi_case_decision_siem_backtest_schemas_exist() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        schemas = spec["components"]["schemas"]
        for name in (
            "CaseDecisionResponse",
            "SiemForwardResponse",
            "SiemForwardAsyncResponse",
            "BacktestFixtureResponse",
            "AuditEngagementOut",
            "AuditEngagementReportOut",
        ):
            assert name in schemas, f"missing {name}"
        assert "http_status" in schemas["SiemForwardResponse"]["properties"]
        async_props = schemas["SiemForwardAsyncResponse"]["properties"]
        assert "async" in async_props
        assert "risk_class_histogram" in schemas["BacktestFixtureResponse"]["properties"]
        assert "engagement" in schemas["AuditEngagementReportOut"]["properties"]
        assert "findings_count" in schemas["AuditEngagementReportOut"]["properties"]


def test_openapi_siem_case_export_schema_exists() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        schema = spec["components"]["schemas"].get("SiemCaseExportPayload")
        assert schema is not None
        props = schema["properties"]
        for key in ("product", "case_id", "data_quality", "invariant_details", "audit_tail"):
            assert key in props


def test_openapi_forensic_export_endpoints_document_503() -> None:
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        manifest_responses = spec["paths"]["/cases/{case_id}/forensic-bundle/manifest"]["get"]["responses"]
        zip_responses = spec["paths"]["/cases/{case_id}/forensic-bundle.zip"]["get"]["responses"]
        assert "503" in manifest_responses
        assert "503" in zip_responses
        assert "signing unavailable" in manifest_responses["503"]["description"].lower()
        assert "signing unavailable" in zip_responses["503"]["description"].lower()


def test_catalog_get_endpoints_have_short_public_cache_control() -> None:
    with TestClient(create_app()) as client:
        for path in ("/invariants", "/catalog/event-sources", "/topology/demo-graph"):
            r = client.get(path)
            assert r.status_code == 200
            cc = (r.headers.get("cache-control") or "").lower()
            assert "public" in cc
            assert "max-age=60" in cc


def test_catalog_cache_disabled_when_env_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "0")
    with TestClient(create_app()) as client:
        r = client.get("/invariants")
        assert r.status_code == 200
        assert r.headers.get("cache-control") is None


def test_cases_get_endpoints_have_private_no_store_cache_control() -> None:
    with TestClient(create_app()) as client:
        for path in ("/cases", "/cases/stats", "/cases/export/full.json"):
            r = client.get(path)
            assert r.status_code == 200
            cc = (r.headers.get("cache-control") or "").lower()
            assert "private" in cc
            assert "no-store" in cc


def test_cases_cache_does_not_apply_to_catalog_routes() -> None:
    with TestClient(create_app()) as client:
        r = client.get("/invariants")
        assert r.status_code == 200
        cc = (r.headers.get("cache-control") or "").lower()
        assert "public" in cc
        assert "no-store" not in cc


def test_health_includes_catalog_cache_max_age_by_default() -> None:
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["catalog_cache_max_age_sec"] == 60
    assert h["takt_catalog_cache_max_age_sec_env_set"] is False


def test_health_omits_catalog_cache_max_age_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "0")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert "catalog_cache_max_age_sec" not in h
    assert h["takt_catalog_cache_max_age_sec_env_set"] is True


def test_health_reports_cors_and_hsts_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "http://app.example")
    monkeypatch.setenv("TAKT_HSTS_MAX_AGE", "86400")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["cors_enabled"] is True
    assert h["hsts_enabled"] is True
    assert h["hsts_preload_enabled"] is False
    assert h["takt_metrics_env_enabled"] is False
    assert h["takt_openapi_server_url_env_set"] is False
    assert h["takt_rate_limit_env_set"] is False
    assert h["takt_log_level_env_set"] is False
    assert h["takt_max_request_body_mb_env_set"] is False
    assert h["takt_slow_request_log_env_set"] is False
    assert h["takt_sqlite_busy_timeout_ms_env_set"] is False
    assert h["takt_catalog_cache_max_age_sec_env_set"] is False
    assert h["takt_build_revision_env_set"] is False
    assert h["takt_request_id_header_env_set"] is False
    assert h["takt_rate_limit_max_ips_env_set"] is False
    assert h["takt_rate_limit_ip_header_env_set"] is False
    assert h["takt_cors_origins_env_set"] is True
    assert h["takt_hsts_max_age_env_set"] is True
    assert h["takt_hsts_preload_env_set"] is False


def test_cors_expose_headers_include_retry_after_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "http://app.example")
    monkeypatch.setenv("TAKT_RATE_LIMIT_PER_MIN", "1")
    with TestClient(create_app()) as client:
        body = {
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        }
        hdrs = {"Origin": "http://app.example"}
        assert client.post("/assess", json=body, headers=hdrs).status_code == 200
        r = client.post("/assess", json=body, headers=hdrs)
    assert r.status_code == 429
    exposed = (r.headers.get("access-control-expose-headers") or "").lower()
    assert "retry-after" in exposed
    assert "x-ratelimit-limit" in exposed
    assert "x-ratelimit-remaining" in exposed
    assert "x-ratelimit-reset" in exposed


def test_cors_enabled_from_env_false_when_only_commas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_CORS_ORIGINS", ", , ")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["cors_enabled"] is False
    assert h["takt_cors_origins_env_set"] is True


def test_response_includes_x_process_time():
    with TestClient(create_app()) as client:
        r = client.get("/live")
        assert r.status_code == 200
        raw = r.headers.get("x-process-time") or r.headers.get("X-Process-Time")
        assert raw is not None
        sec = float(raw)
        assert sec >= 0.0


def test_response_includes_x_request_id():
    with TestClient(create_app()) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert "x-request-id" in {k.lower() for k in r.headers}
        rid = r.headers.get("x-request-id") or r.headers.get("X-Request-ID")
        assert rid and len(rid) >= 8


def test_x_request_id_passthrough():
    with TestClient(create_app()) as client:
        r = client.get("/health", headers={"X-Request-ID": "trace-from-gateway"})
        assert r.headers.get("x-request-id") == "trace-from-gateway"


def test_security_headers_on_response():
    with TestClient(create_app()) as client:
        r = client.get("/live")
        assert r.status_code == 200
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"
        assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert "geolocation=()" in (r.headers.get("permissions-policy") or "")


def test_hsts_header_when_takt_hsts_max_age_set(monkeypatch):
    monkeypatch.setenv("TAKT_HSTS_MAX_AGE", "31536000")
    with TestClient(create_app()) as client:
        r = client.get("/live")
        h = r.headers.get("strict-transport-security") or ""
    assert "max-age=31536000" in h
    assert "includeSubDomains" in h


def test_hsts_preload_when_env_set(monkeypatch):
    monkeypatch.setenv("TAKT_HSTS_MAX_AGE", "63072000")
    monkeypatch.setenv("TAKT_HSTS_PRELOAD", "1")
    with TestClient(create_app()) as client:
        h = client.get("/live").headers.get("strict-transport-security") or ""
        assert "preload" in h
        assert client.get("/health").json()["hsts_preload_enabled"] is True


def test_health_hsts_preload_env_set_without_max_age(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_HSTS_MAX_AGE", raising=False)
    monkeypatch.setenv("TAKT_HSTS_PRELOAD", "1")
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
    assert h["takt_hsts_preload_env_set"] is True
    assert h["takt_hsts_max_age_env_set"] is False
    assert h["hsts_enabled"] is False
    assert h["hsts_preload_enabled"] is False


def test_head_probes_ok_and_empty_body():
    with TestClient(create_app()) as client:
        for path in ("/live", "/health", "/ready", "/openapi.json"):
            r = client.head(path)
            assert r.status_code == 200
            assert (r.content or b"") == b""
            assert r.headers.get("x-request-id")
            assert r.headers.get("x-process-time")


def test_openapi_lists_head_for_system_probes():
    with TestClient(create_app()) as client:
        spec = client.get("/openapi.json").json()
        for path in ("/live", "/health", "/ready"):
            ops = spec["paths"][path]
            assert "head" in ops and "get" in ops


def test_slow_request_invalid_threshold_env_does_not_break(monkeypatch):
    monkeypatch.setenv("TAKT_SLOW_REQUEST_LOG_SEC", "not-a-float")
    with TestClient(create_app()) as client:
        assert client.get("/live").status_code == 200


def test_cors_actual_response_exposes_custom_headers(monkeypatch):
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "http://test.front")
    with TestClient(create_app()) as client:
        r = client.get("/health", headers={"Origin": "http://test.front"})
        assert r.status_code == 200
        expose = (r.headers.get("access-control-expose-headers") or "").lower()
        for name in ("x-request-id", "x-process-time", "x-total-count", "link", "cache-control"):
            assert name in expose


def test_cors_allows_configured_origin(monkeypatch):
    monkeypatch.setenv("TAKT_CORS_ORIGINS", "http://test.front")
    with TestClient(create_app()) as client:
        r = client.options(
            "/health",
            headers={
                "Origin": "http://test.front",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code == 200
        allow = r.headers.get("access-control-allow-origin") or r.headers.get("Access-Control-Allow-Origin")
        assert allow == "http://test.front"


def test_health_reports_api_key_enabled(monkeypatch):
    monkeypatch.setenv("TAKT_API_KEY", "k" * 32)
    with TestClient(create_app()) as client:
        assert client.get("/health").json()["api_key_enabled"] is True
