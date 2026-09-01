from __future__ import annotations

import logging
import os
import socket
import sys
import time
from datetime import UTC
from typing import Any

from fastapi import HTTPException, Request, Response

from takt.domain.entities.case import CaseStatus
from takt.infrastructure.config.effective_environment import (
    auth_mode_for_health,
    environment_health_snapshot,
    sqlite_busy_timeout_ms_from_env,
)
from takt.infrastructure.security.rbac import role_satisfies
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.system import (
    DataQualityResponse,
    HealthResponse,
    LiveResponse,
    ReadyResponse,
    SessionPermissions,
    SessionResponse,
)

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
        tbs = dict(ctx.trust_by_source)
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
            "booted_at_utc": app.state.booted_at_utc.astimezone(UTC).isoformat(timespec="seconds"),
            "process_id": os.getpid(),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "python_executable": sys.executable,
            "working_directory": os.getcwd(),
            "security_log": sec_health,
            "gzip_minimum_size_bytes": ctx.gzip_minimum_size_bytes,
            "openapi_servers_count": len(ctx.openapi_server_entries_from_env()),
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
            "siem_webhook_allowlist_prefixes_count": len(ctx.siem_webhook_prefixes),
            "export_pdf_unicode_font_configured": bool(getattr(app.state, "pdf_unicode_font", None)),
            "prometheus_metrics_enabled": bool(getattr(app.state, "prometheus_metrics_active", False)),
            "forensic_crypto_mode": ctx.forensic_crypto_mode(),
            "forensic_strict_ready": not ctx.forensic_strict_missing(),
            "forensic_strict_missing": ctx.forensic_strict_missing(),
        }
        # Всё, что выводится только из переменных окружения, собирает инфраструктура.
        out.update(environment_health_snapshot())

        # Ниже — то, что зависит и от окружения, и от состояния процесса, поэтому в снимок
        # окружения не помещается.
        ver_fn = getattr(ctx.repo, "db_schema_version", None)
        if callable(ver_fn):
            out["sqlite_schema_version"] = ver_fn()
            out["sqlite_busy_timeout_ms"] = sqlite_busy_timeout_ms_from_env()
        if "rate_limit_per_minute" in out:
            lock = app.state.rate_limit_lock
            with lock:
                out["rate_limit_tracked_ips"] = len(app.state.rate_limit_buckets)
        br = ctx.build_revision_from_env()
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

    @app.get("/session", response_model=SessionResponse, tags=["System"])
    def session(request: Request):
        """Кто предъявил ключ доступа: `actor_id` и роль.

        Маршрут не публичный намеренно: без ключа он отвечает **401**, и рабочее место
        отличает «требуется ключ доступа» от «нет связи с продуктом».
        """
        role = str(getattr(request.state, "takt_role", "") or "")
        return SessionResponse(
            actor_id=str(getattr(request.state, "takt_actor_id", "") or ""),
            role=role,
            auth_mode=auth_mode_for_health(),
            permissions=SessionPermissions(
                case_write=role_satisfies(role, "analyst_l1"),
                case_relink=role_satisfies(role, "analyst_l2"),
                administration=role_satisfies(role, "admin"),
            ),
        )

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
