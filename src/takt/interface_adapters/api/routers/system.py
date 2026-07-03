from __future__ import annotations

import logging
import os
import socket
import sys
import time
from datetime import timezone
from typing import Any

from fastapi import HTTPException, Response

from takt.domain.entities.case import CaseStatus
from takt.infrastructure.http.cache_control_middleware import catalog_cache_max_age_sec
from takt.infrastructure.http.cors_from_env import cors_middleware_enabled_from_env
from takt.infrastructure.http.prometheus_metrics import metrics_enabled_from_env
from takt.infrastructure.http.rate_limit_middleware import (
    rate_limit_ip_header_from_env,
    rate_limit_max_tracked_ips_from_env,
    rate_limit_per_minute_from_env,
    rate_limit_proxy_mode_for_health,
)
from takt.infrastructure.http.request_body_limit_middleware import max_request_body_bytes_from_env
from takt.infrastructure.http.request_id_middleware import request_id_alternate_header_from_env
from takt.infrastructure.http.security_headers import hsts_enabled_from_env, hsts_preload_enabled_from_env
from takt.infrastructure.http.timing_middleware import slow_log_threshold_seconds
from takt.infrastructure.security.auth_env import auth_mode_for_health
from takt.infrastructure.security.trusted_proxies import trusted_proxy_networks_from_env
from takt.infrastructure.security.webhook_allowlist import (
    siem_allowlist_mode_label,
    takt_security_profile_from_env,
)
from takt.infrastructure.stores.sqlite_store import sqlite_busy_timeout_ms_from_env
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.system import DataQualityResponse, HealthResponse, LiveResponse, ReadyResponse

_LOGGER = logging.getLogger("takt.api")


def register_system_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/live", response_model=LiveResponse, response_model_exclude_none=True, tags=["System"])
    def live():
        br = ctx.build_revision_from_env()
        return LiveResponse(product="TAKT-MVP", version=ctx.package_version, build_revision=br)

    @app.head("/live", tags=["System"])
    def live_probe():
        return Response()

    def _health_payload() -> dict[str, Any]:
        all_cases = ctx.repo.list_all()
        open_n = sum(1 for c in all_cases if c.status in (CaseStatus.NEW, CaseStatus.TRIAGE))
        tbs = dict(app.state.trust_by_source) if app.state.trust_by_source else {}
        slog = getattr(app.state, "security_log", None)
        if slog is not None:
            sst = slog.health_snapshot()
            sec_health = {"status": sst.status, "entries_last_hour": sst.entries_last_hour}
        else:
            sec_health = {"status": "disabled", "entries_last_hour": 0}
        out: dict[str, Any] = {
            "status": "ok",
            "product": "TAKT-MVP",
            "version": ctx.package_version,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "python_implementation": sys.implementation.name,
            "api_log_level": logging.getLevelName(_LOGGER.getEffectiveLevel()),
            "uptime_seconds": round(time.monotonic() - float(app.state.boot_monotonic), 3),
            "booted_at_utc": app.state.booted_at_utc.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "process_id": os.getpid(),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "python_executable": sys.executable,
            "working_directory": os.getcwd(),
            "api_key_enabled": bool(os.environ.get("TAKT_API_KEY", "").strip()),
            "auth": {"mode": auth_mode_for_health()},
            "siem": {
                "allowlist_mode": siem_allowlist_mode_label(),
                "profile": takt_security_profile_from_env(),
            },
            "proxy": {"trusted_count": len(trusted_proxy_networks_from_env())},
            "rate_limit": {"proxy_mode": rate_limit_proxy_mode_for_health()},
            "security_log": sec_health,
            "takt_config_env_set": bool(os.environ.get("TAKT_CONFIG", "").strip()),
            "takt_storage_env_set": bool(os.environ.get("TAKT_STORAGE", "").strip()),
            "takt_sqlite_path_env_set": bool(os.environ.get("TAKT_SQLITE_PATH", "").strip()),
            "takt_sqlite_busy_timeout_ms_env_set": bool(os.environ.get("TAKT_SQLITE_BUSY_TIMEOUT_MS", "").strip()),
            "takt_log_level_env_set": bool(os.environ.get("TAKT_LOG_LEVEL", "").strip()),
            "takt_max_request_body_mb_env_set": bool(os.environ.get("TAKT_MAX_REQUEST_BODY_MB", "").strip()),
            "takt_slow_request_log_env_set": bool(os.environ.get("TAKT_SLOW_REQUEST_LOG_SEC", "").strip()),
            "takt_cors_origins_env_set": bool(os.environ.get("TAKT_CORS_ORIGINS", "").strip()),
            "takt_hsts_max_age_env_set": bool(os.environ.get("TAKT_HSTS_MAX_AGE", "").strip()),
            "takt_hsts_preload_env_set": bool(os.environ.get("TAKT_HSTS_PRELOAD", "").strip()),
            "cors_enabled": cors_middleware_enabled_from_env(),
            "hsts_enabled": hsts_enabled_from_env(),
            "hsts_preload_enabled": hsts_preload_enabled_from_env(),
            "gzip_minimum_size_bytes": ctx.gzip_minimum_size_bytes,
            "openapi_servers_count": len(ctx.openapi_server_entries_from_env()),
            "takt_openapi_server_url_env_set": bool(os.environ.get("TAKT_OPENAPI_SERVER_URL", "").strip()),
            "takt_request_id_header_env_set": bool(os.environ.get("TAKT_REQUEST_ID_HEADER", "").strip()),
            "case_storage": app.state.case_storage_backend,
            "expected_behavior_storage": app.state.expected_behavior_backend,
            "cases_total": len(all_cases),
            "cases_open": open_n,
            "event_window_len": len(app.state.event_window),
            "ingest_trust_sources": len(tbs),
            "ingest_trust_by_source": tbs,
            "full_json_max_cases": ctx.export_full_max,
            "ingest_event_window_max": ctx.event_window_max,
            "ingest_recent_for_context": getattr(app.state, "ingest_recent_for_context", 5),
            "ingest_batch_max_events": ctx.ingest_batch_max,
            "cases_list_max_limit": ctx.case_list_max_limit,
            "cases_list_default_sort": ctx.case_list_default_sort,
            "siem_webhook_retries": app.state.webhook_retries,
            "siem_webhook_backoff_sec": app.state.webhook_backoff_sec,
            "siem_webhook_allowlist_prefixes_count": len(app.state.siem_webhook_prefixes),
            "export_pdf_unicode_font_configured": bool(getattr(app.state, "pdf_unicode_font", None)),
            "gossopka_profile": os.environ.get("TAKT_GOSSOPKA_PROFILE", "mvp").strip() or "mvp",
            "gossopka_official_exchange_enabled": (
                (os.environ.get("TAKT_GOSSOPKA_PROFILE", "").strip().lower() == "official")
                or bool(os.environ.get("TAKT_GOSSOPKA_OFFICIAL_CONTRACT_ID", "").strip())
            ),
            "ingest_syslog_rfc5424_enabled": bool(os.environ.get("TAKT_INGEST_SYSLOG_RFC5424", "").strip()),
            "ingest_snmp_enabled": bool(os.environ.get("TAKT_INGEST_SNMP", "").strip()),
            "ingest_netflow_enabled": bool(os.environ.get("TAKT_INGEST_NETFLOW", "").strip()),
            "ingest_ipfix_enabled": bool(os.environ.get("TAKT_INGEST_IPFIX", "").strip()),
            "ldap_integration_configured": bool(os.environ.get("TAKT_LDAP_URL", "").strip()),
            "ad_integration_configured": bool(os.environ.get("TAKT_AD_DOMAIN", "").strip()),
            "timeseries_backend": os.environ.get("TAKT_TIMESERIES_BACKEND", "sqlite").strip() or "sqlite",
            "timeseries_configured": bool(os.environ.get("TAKT_TIMESERIES_DSN", "").strip()),
            "object_storage_backend": os.environ.get("TAKT_OBJECT_STORAGE_BACKEND", "none").strip() or "none",
            "object_storage_configured": bool(os.environ.get("TAKT_OBJECT_STORAGE_BUCKET", "").strip()),
            "forensic_crypto_mode": ctx.forensic_crypto_mode(),
            "forensic_strict_ready": not ctx.forensic_strict_missing(),
            "forensic_strict_missing": ctx.forensic_strict_missing(),
        }
        rid_alt = request_id_alternate_header_from_env()
        if rid_alt is not None:
            out["request_id_alternate_header"] = rid_alt
        ver_fn = getattr(ctx.repo, "db_schema_version", None)
        if callable(ver_fn):
            out["sqlite_schema_version"] = ver_fn()
            out["sqlite_busy_timeout_ms"] = sqlite_busy_timeout_ms_from_env()
        max_body = max_request_body_bytes_from_env()
        if max_body is not None:
            out["max_request_body_bytes"] = max_body
        slow_log_sec = slow_log_threshold_seconds()
        if slow_log_sec is not None:
            out["slow_request_log_threshold_sec"] = slow_log_sec
        cat_age = catalog_cache_max_age_sec()
        if cat_age is not None:
            out["catalog_cache_max_age_sec"] = cat_age
        out["takt_catalog_cache_max_age_sec_env_set"] = bool(os.environ.get("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "").strip())
        out["takt_metrics_env_enabled"] = metrics_enabled_from_env()
        out["prometheus_metrics_enabled"] = bool(getattr(app.state, "prometheus_metrics_active", False))
        out["takt_rate_limit_env_set"] = bool(os.environ.get("TAKT_RATE_LIMIT_PER_MIN", "").strip())
        out["takt_rate_limit_max_ips_env_set"] = bool(os.environ.get("TAKT_RATE_LIMIT_MAX_IPS", "").strip())
        out["takt_rate_limit_ip_header_env_set"] = bool(os.environ.get("TAKT_RATE_LIMIT_IP_HEADER", "").strip())
        rl = rate_limit_per_minute_from_env()
        if rl is not None:
            out["rate_limit_per_minute"] = rl
            out["rate_limit_max_tracked_ips"] = rate_limit_max_tracked_ips_from_env()
            rlh = rate_limit_ip_header_from_env()
            if rlh is not None:
                out["rate_limit_ip_header"] = rlh
            lock = app.state.rate_limit_lock
            with lock:
                out["rate_limit_tracked_ips"] = len(app.state.rate_limit_buckets)
        br = ctx.build_revision_from_env()
        out["takt_build_revision_env_set"] = bool(os.environ.get("TAKT_BUILD_REVISION", "").strip())
        if br is not None:
            out["build_revision"] = br
        return out

    @app.get("/health", response_model=HealthResponse, response_model_exclude_none=True, tags=["System"])
    def health():
        return HealthResponse.model_validate(_health_payload())

    @app.head("/health", tags=["System"])
    def health_probe():
        _health_payload()
        return Response()

    def _ready_or_fail() -> None:
        try:
            _ = ctx.repo.list_all()
            _ = ctx.baseline.is_expected("__ready_probe__", "PING")
            missing = ctx.forensic_strict_missing()
            if missing:
                raise RuntimeError(f"forensic_strict_misconfigured: missing={','.join(missing)}")
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"not_ready: {e!s}") from e

    @app.get("/ready", response_model=ReadyResponse, response_model_exclude_none=True, tags=["System"])
    def ready():
        _ready_or_fail()
        br = ctx.build_revision_from_env()
        return ReadyResponse(
            case_storage=app.state.case_storage_backend,
            expected_behavior_storage=app.state.expected_behavior_backend,
            forensic_crypto_mode=ctx.forensic_crypto_mode(),
            forensic_strict_ready=not ctx.forensic_strict_missing(),
            forensic_strict_missing=ctx.forensic_strict_missing(),
            build_revision=br,
        )

    @app.head("/ready", tags=["System"])
    def ready_probe():
        _ready_or_fail()
        return Response()

    @app.get("/data-quality", response_model=DataQualityResponse, tags=["System"])
    def data_quality():
        dq = app.state.last_dq
        if dq is None:
            raise HTTPException(status_code=404, detail="run POST /assess or POST /events first")
        return DataQualityResponse(
            dq_score=dq.dq_score,
            partial_observability=dq.partial_observability,
            reasons=list(dq.reasons),
        )
