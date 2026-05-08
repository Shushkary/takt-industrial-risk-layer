from __future__ import annotations

import logging
import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.middleware.gzip import GZipMiddleware

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.audit_engagement import (
    CreateAuditEngagementCommand,
    FinalizeAuditReportCommand,
    ManageAuditEngagementUseCase,
)
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.build_forensic_bundle import BuildForensicBundleUseCase
from takt.application.use_cases.case_decision import SubmitCaseDecisionUseCase
from takt.application.use_cases.compliance_report import (
    BuildCaseEvidenceChecklistUseCase,
    BuildComplianceDataQualityReportUseCase,
    BuildForensicReadinessReportUseCase,
    FORENSIC_READINESS_MISSING_CODES,
    REMEDIATION_KIND_DESCRIPTIONS,
)
from takt.application.use_cases.manual_permit import AttachManualPermitCommand, AttachManualPermitUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.application.use_cases.remediation import (
    ListRemediationAttemptsQuery,
    ListRemediationAttemptsUseCase,
    RecordRemediationAttemptCommand,
    RecordRemediationAttemptUseCase,
)
from takt.application.use_cases.verify_forensic_bundle import VerifyForensicBundleUseCase
from takt.application.system_defaults import default_clock, default_id_provider
from takt.domain.entities.case import (
    Case,
    CaseDecisionRecord,
    CaseStatus,
    InvariantHitRecord,
    ManualPermit,
    Observation,
    RawEvidenceRef,
    RemediationAttempt,
)
from takt.domain.engines.causal_mesh import GraphEdge, detect_jump_server_bypass
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.entities.audit_engagement import AuditEngagement
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.invariants.catalog import invariant_titles_by_id
from takt.domain.invariants.evaluator import invariant_context_from_config
from takt.infrastructure.config.invariant_catalog_yaml import (
    catalog_experimental_invariant_ids,
    catalog_rule_overrides,
    catalog_rule_specs,
    load_invariant_catalog_from_dir,
)
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.config.settings_helpers import (
    apply_storage_env_overrides,
    case_repository_from_weights,
    enrichment_from_weights,
    expected_behavior_from_weights,
    graph_edges_from_weights,
    siem_webhook_retries,
    topology_from_weights,
    trust_by_source_from_weights,
)
from takt.infrastructure.stores.memory import InMemoryAuditEngagementStore, InMemoryIdempotencyStore
from takt.infrastructure.stores.sqlite_store import (
    SqliteAuditEngagementStore,
    SqliteCaseStore,
    sqlite_busy_timeout_ms_from_env,
)
from takt.infrastructure.export.case_pdf import render_case_pdf
from takt.infrastructure.export.forensic_bundle import ZipForensicBundleBuilder, ZipForensicBundleVerifier
from takt.infrastructure.export.gossopka import (
    case_to_gossopka_card,
    case_to_gossopka_official_card,
    case_to_gossopka_official_transport_payload,
    case_to_gossopka_transport_payload,
)
from takt.infrastructure.export.siem_webhook import (
    SiemCaseExportPayload,
    case_to_siem_payload,
    post_case_to_webhook,
    post_case_to_webhook_sync,
)
from takt.infrastructure.http.cors_from_env import add_cors_middleware_if_configured, cors_middleware_enabled_from_env
from takt.infrastructure.http.rate_limit_middleware import (
    InMemoryRateLimitMiddleware,
    rate_limit_ip_header_from_env,
    rate_limit_max_tracked_ips_from_env,
    rate_limit_per_minute_from_env,
    rate_limit_proxy_mode_for_health,
)
from takt.infrastructure.http.idempotency import idempotency_record_success, idempotent_json_response_or_none
from takt.infrastructure.http.request_body_limit_middleware import (
    RequestBodySizeLimitMiddleware,
    max_request_body_bytes_from_env,
)
from takt.infrastructure.http.request_id_middleware import RequestIdMiddleware, request_id_alternate_header_from_env
from takt.infrastructure.http.security_log_middleware import SecurityLogMiddleware
from takt.infrastructure.http.cache_control_middleware import (
    CasesPrivateNoStoreMiddleware,
    CatalogCacheControlMiddleware,
    catalog_cache_max_age_sec,
)
from takt.infrastructure.http.prometheus_metrics import metrics_enabled_from_env
from takt.infrastructure.http.prometheus_metrics import record_business_assessment
from takt.infrastructure.http.security_headers import (
    SecurityHeadersMiddleware,
    hsts_enabled_from_env,
    hsts_preload_enabled_from_env,
)
from takt.infrastructure.http.timing_middleware import ProcessTimeMiddleware, slow_log_threshold_seconds
from takt.infrastructure.importers.csv_events import load_normalized_from_csv, raw_row_to_normalized
from takt.infrastructure.security.api_key_middleware import OptionalApiKeyMiddleware
from takt.infrastructure.security.auth_env import (
    auth_mode_for_health,
    validate_startup_auth_or_raise,
)
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.infrastructure.security.security_log_service import SecurityLogService, security_log_file_path_from_env
from takt.infrastructure.security.startup_audit import security_startup_config_snapshot
from takt.infrastructure.security.webhook_allowlist import (
    require_allowed_siem_url,
    siem_allowlist_mode_label,
    takt_security_profile_from_env,
)
from takt.infrastructure.security.trusted_proxies import trusted_proxy_networks_from_env

_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_CFG = _ROOT / "config" / "risk_weights.yaml"


def _read_installed_package_version(default: str = "0.6.23") -> str:
    """Версия дистрибутива; при ошибке **`importlib.metadata`** (editable/битый venv) — **`default`**."""

    try:
        from importlib.metadata import version as _distribution_version

        return _distribution_version("takt-industrial-risk-layer")
    except Exception:
        return default


_PACKAGE_VERSION = _read_installed_package_version()
_EVENT_WINDOW_MAX = 64
_INGEST_BATCH_MAX = 100
_EXPORT_FULL_MAX = 10_000
_CASE_LIST_MAX_LIMIT = 1000
_CASE_LIST_DEFAULT_SORT = "risk_score_desc"
_GZIP_MINIMUM_SIZE_BYTES = 512
_LOGGER = logging.getLogger("takt.api")
_TAKT_LOG_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
_TAKT_BUILD_REVISION_MAX_LEN = 256


def build_revision_from_env() -> str | None:
    """Необязательная метка сборки из **`TAKT_BUILD_REVISION`** для **`GET /health`**: **`build_revision`** (до **256** символов); пустая — **`None`**."""
    raw = os.environ.get("TAKT_BUILD_REVISION", "").strip()
    if not raw:
        return None
    return raw[:_TAKT_BUILD_REVISION_MAX_LEN]


def _python_runtime_tag() -> str:
    """**`python_implementation`/`python_version`** в одном теге (строки **`TAKT API ready`** / **`shutdown`**)."""
    return f"{sys.implementation.name}/{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def apply_takt_api_log_level_from_env() -> None:
    """Уровень логгера **`takt.api`** из **`TAKT_LOG_LEVEL`** (`DEBUG`, `INFO`, `WARNING`/`WARN`, `ERROR`, `CRITICAL`); неверное значение игнорируется."""
    raw = os.environ.get("TAKT_LOG_LEVEL", "").strip().upper()
    if not raw:
        return
    level = _TAKT_LOG_LEVEL_MAP.get(raw)
    if level is None:
        return
    _LOGGER.setLevel(level)


_VALID_RISK_CLASSES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_OPENAPI_PUBLIC_PATHS: frozenset[str] = frozenset({"/health", "/live", "/ready", "/openapi.json", "/metrics"})
_OPENAPI_PUBLIC_PREFIXES: tuple[str, ...] = ("/docs", "/redoc")


def _is_openapi_public_path(path: str) -> bool:
    if path in _OPENAPI_PUBLIC_PATHS:
        return True
    return any(path == p or path.startswith(f"{p}/") for p in _OPENAPI_PUBLIC_PREFIXES)


def _openapi_api_key_configured() -> bool:
    return bool(os.environ.get("TAKT_API_KEY", "").strip())


def openapi_server_entries_from_env() -> list[dict[str, str]]:
    """Валидные элементы **`servers`** из **TAKT_OPENAPI_SERVER_URL** (OpenAPI и **GET /health**)."""
    raw = os.environ.get("TAKT_OPENAPI_SERVER_URL", "").strip()
    if not raw:
        return []
    entries: list[dict[str, str]] = []
    for part in (p.strip() for p in raw.split(",") if p.strip()):
        url = part.rstrip("/")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            _LOGGER.warning("TAKT_OPENAPI_SERVER_URL entry %r ignored (scheme must be http or https)", part)
            continue
        if not parsed.netloc:
            _LOGGER.warning("TAKT_OPENAPI_SERVER_URL entry %r ignored (missing host)", part)
            continue
        entries.append({"url": url, "description": "From TAKT_OPENAPI_SERVER_URL"})
    return entries


def _patch_openapi_servers(schema: dict[str, Any]) -> None:
    """Если задан **TAKT_OPENAPI_SERVER_URL**, добавляет **`servers`** для Swagger за прокси."""
    entries = openapi_server_entries_from_env()
    if entries:
        schema["servers"] = entries


def _patch_openapi_with_takt_api_key(schema: dict[str, Any]) -> None:
    """**components.securitySchemes.TaktApiKey**; при **TAKT_API_KEY** — **security** на непубличных операциях."""
    components = schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["TaktApiKey"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-TAKT-API-Key",
        "description": (
            "Тот же ключ можно передать как Authorization: Bearer. "
            "Нужен для путей, не относящихся к /health, /live, /ready, /metrics, /openapi.json и UI /docs, /redoc, "
            "если задана переменная окружения TAKT_API_KEY."
        ),
    }
    if not _openapi_api_key_configured():
        return
    http_methods = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
    req = {"TaktApiKey": []}
    for path_key, path_item in schema.get("paths", {}).items():
        if _is_openapi_public_path(path_key):
            continue
        for method, operation in path_item.items():
            if method.lower() not in http_methods or not isinstance(operation, dict):
                continue
            sec = operation.setdefault("security", [])
            if req not in sec:
                sec.append(req)


def _attach_custom_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            routes=app.routes,
        )
        _patch_openapi_servers(openapi_schema)
        _patch_openapi_with_takt_api_key(openapi_schema)
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi


def _register_prometheus_if_enabled(application: FastAPI) -> None:
    from takt.infrastructure.http.prometheus_metrics import (
        PrometheusMetricsMiddleware,
        metrics_enabled_from_env,
        prometheus_client_available,
        prometheus_metrics_response,
        register_process_boot_monotonic,
        register_prometheus_build_info,
        register_prometheus_rate_limit_app,
    )

    application.state.prometheus_metrics_active = False
    if not metrics_enabled_from_env():
        return
    if not prometheus_client_available():
        _LOGGER.warning(
            "TAKT_METRICS is set but prometheus-client is not installed; /metrics is disabled"
        )
        return
    register_process_boot_monotonic(float(application.state.boot_monotonic))
    register_prometheus_build_info(
        version=_PACKAGE_VERSION,
        build_revision=build_revision_from_env(),
    )
    register_prometheus_rate_limit_app(application)
    application.add_middleware(PrometheusMetricsMiddleware)
    application.state.prometheus_metrics_active = True

    @application.get(
        "/metrics",
        tags=["System"],
        summary="Метрики Prometheus",
        response_class=Response,
    )
    def prometheus_metrics_endpoint():
        """Формат **OpenMetrics** / Prometheus (**takt_build_info**, **takt_http_requests_total**, **takt_http_request_duration_seconds**, **takt_http_requests_in_progress**, **takt_rate_limit_rejected_total**, **takt_rate_limit_tracked_ips** при **`TAKT_RATE_LIMIT_PER_MIN`**, **takt_process_uptime_seconds**, **process_***)."""
        return prometheus_metrics_response()

    @application.head(
        "/metrics",
        tags=["System"],
        summary="HEAD /metrics",
    )
    def prometheus_metrics_head():
        """Тот же контроль доступа, что **GET /metrics**, без тела и без генерации текста метрик (**`Cache-Control: no-store`**)."""
        r = Response()
        r.headers["Cache-Control"] = "no-store, private"
        return r


_CASE_LIST_SORT = frozenset(
    {
        "risk_score_desc",
        "risk_score_asc",
        "created_at_desc",
        "created_at_asc",
        "dq_score_desc",
        "dq_score_asc",
        "invariant_hits_desc",
        "invariant_hits_asc",
        "event_count_desc",
        "event_count_asc",
        "title_desc",
        "title_asc",
        "case_id_desc",
        "case_id_asc",
        "primary_asset_id_desc",
        "primary_asset_id_asc",
    },
)


def _offset_limit_link_header(
    request: Request,
    *,
    offset: int,
    limit: int | None,
    total_before_slice: int,
) -> str | None:
    """При заданном `limit` — `Link` с `rel=next` / `rel=prev` (остальные query-параметры сохраняются)."""
    if limit is None or total_before_slice == 0:
        return None
    raw_pairs = list(request.query_params.multi_items())
    path = request.url.path
    chunks: list[str] = []

    def _href(new_offset: int) -> str:
        pairs = [(k, v) for k, v in raw_pairs if k not in ("offset", "limit")]
        pairs.append(("offset", str(new_offset)))
        pairs.append(("limit", str(limit)))
        return f"{path}?{urlencode(pairs)}"

    if offset + limit < total_before_slice:
        chunks.append(f'<{_href(offset + limit)}>; rel="next"')
    if offset > 0:
        chunks.append(f'<{_href(max(0, offset - limit))}>; rel="prev"')
    return ", ".join(chunks) if chunks else None


def _resolve_config_path() -> Path:
    """Путь к YAML: `TAKT_CONFIG` или `config/risk_weights.yaml` в корне проекта."""
    raw = os.environ.get("TAKT_CONFIG", "").strip()
    if not raw:
        return _DEFAULT_CFG
    return Path(raw).expanduser().resolve()


def _invariant_catalog_dir_for_config(cfg_path: Path) -> Path:
    """Каталог `invariants`: рядом с активным YAML или из коробки (`config/invariants` проекта)."""
    sibling = cfg_path.parent / "invariants"
    if sibling.is_dir():
        return sibling
    return _DEFAULT_CFG.parent / "invariants"


@asynccontextmanager
async def _app_lifespan(app: FastAPI):
    validate_startup_auth_or_raise()
    slog = getattr(app.state, "security_log", None)
    if slog is not None:
        slog.record_service_start({"config": security_startup_config_snapshot()})
    yield
    if slog is not None:
        slog.record_service_stop()
        slog.close()
    for attr in ("repo", "baseline", "audit_engagement_store"):
        obj = getattr(app.state, attr, None)
        closer = getattr(obj, "close", None)
        if callable(closer):
            closer()
    _LOGGER.info(
        "TAKT API shutdown version=%s python=%s pid=%s hostname=%s platform=%s python_executable=%s cwd=%s",
        _PACKAGE_VERSION,
        _python_runtime_tag(),
        os.getpid(),
        socket.gethostname(),
        sys.platform,
        sys.executable,
        os.getcwd(),
    )


def _trim_event_window(window: list, *, max_events: int = _EVENT_WINDOW_MAX) -> None:
    overflow = len(window) - max_events
    if overflow > 0:
        del window[0:overflow]


def _take_recent(window: list, n: int) -> list:
    return list(window[-n:]) if window else []


def _coerce_event_source(raw: str | None) -> EventSource:
    if raw is None or raw == "":
        return EventSource.PLC_POLLING
    try:
        return EventSource(raw)
    except ValueError:
        allowed = ", ".join(s.value for s in EventSource)
        raise HTTPException(status_code=400, detail=f"invalid source; use one of: {allowed}")


def _coerce_case_status(raw: str) -> CaseStatus:
    try:
        return CaseStatus(raw.strip().upper())
    except ValueError:
        allowed = ", ".join(s.value for s in CaseStatus)
        raise HTTPException(status_code=400, detail=f"invalid status; use one of: {allowed}") from None


def _as_utc_boundary(dt: datetime) -> datetime:
    """Граница сравнения для created_at: naive → UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_import_created_at(raw: str) -> datetime:
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def _sort_cases_copy(items: list[Case], sort_key: str) -> list[Case]:
    sk = sort_key.strip().lower()
    if sk == "risk_score_desc":
        return sorted(items, key=lambda c: c.risk_score, reverse=True)
    if sk == "risk_score_asc":
        return sorted(items, key=lambda c: c.risk_score)
    if sk == "created_at_desc":
        return sorted(items, key=lambda c: _as_utc_boundary(c.created_at), reverse=True)
    if sk == "created_at_asc":
        return sorted(items, key=lambda c: _as_utc_boundary(c.created_at))
    if sk == "dq_score_desc":
        return sorted(items, key=lambda c: c.dq_score, reverse=True)
    if sk == "dq_score_asc":
        return sorted(items, key=lambda c: c.dq_score)
    if sk == "invariant_hits_desc":
        return sorted(items, key=lambda c: len(c.invariant_hits), reverse=True)
    if sk == "invariant_hits_asc":
        return sorted(items, key=lambda c: len(c.invariant_hits))
    if sk == "event_count_desc":
        return sorted(items, key=lambda c: len(c.normalized_event_ids), reverse=True)
    if sk == "event_count_asc":
        return sorted(items, key=lambda c: len(c.normalized_event_ids))
    if sk == "title_desc":
        return sorted(items, key=lambda c: c.title.lower(), reverse=True)
    if sk == "title_asc":
        return sorted(items, key=lambda c: c.title.lower())
    if sk == "case_id_desc":
        return sorted(items, key=lambda c: c.case_id.lower(), reverse=True)
    if sk == "case_id_asc":
        return sorted(items, key=lambda c: c.case_id.lower())
    if sk == "primary_asset_id_desc":
        return sorted(items, key=lambda c: c.primary_asset_id.lower(), reverse=True)
    if sk == "primary_asset_id_asc":
        return sorted(items, key=lambda c: c.primary_asset_id.lower())
    raise RuntimeError(f"unsupported sort: {sort_key!r}")


class InvariantHitDetail(BaseModel):
    id: str
    title_ru: str


class ObservationDetail(BaseModel):
    source: str
    ingest_trust: float
    event_ids: list[str]


class InvariantHitRecordDetail(BaseModel):
    invariant_id: str
    event_ref: str
    ts: str
    score_contribution: float
    dq_score: float
    dq_partial: bool
    dq_reasons: list[str]


class ManualPermitDetail(BaseModel):
    permit_id: str
    case_id: str
    work_order_number: str
    actor: str
    created_at: str
    asset_id: str = ""
    operation: str = ""
    verdict: str = "undetermined"
    confidence: float = 0.5
    rationale: str = ""
    counterfactual: str = ""
    note: str = ""


class CaseDecisionRecordDetail(BaseModel):
    ts: str
    actor: str
    prev_status: str
    next_status: str
    reason: str = ""
    request_id: str = ""


class RemediationAttemptDetail(BaseModel):
    attempt_id: str
    case_id: str
    kind: str
    status: str
    actor: str
    created_at: str
    action: str = ""
    result: str = ""
    readiness_before: bool | None = None
    readiness_after: bool | None = None
    note: str = ""
    request_id: str = ""


def _invariant_details_for_hits(hits: list[str]) -> list[InvariantHitDetail]:
    titles = invariant_titles_by_id()
    return [InvariantHitDetail(id=h, title_ru=titles.get(h) or h) for h in hits]


def _manual_permit_to_detail(p: ManualPermit) -> ManualPermitDetail:
    return ManualPermitDetail(
        permit_id=p.permit_id,
        case_id=p.case_id,
        work_order_number=p.work_order_number,
        actor=p.actor,
        created_at=p.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        asset_id=p.asset_id,
        operation=p.operation,
        verdict=p.verdict,
        confidence=p.confidence,
        rationale=p.rationale,
        counterfactual=p.counterfactual,
        note=p.note,
    )


def _decision_record_to_detail(r: CaseDecisionRecord) -> CaseDecisionRecordDetail:
    return CaseDecisionRecordDetail(
        ts=r.ts.astimezone(timezone.utc).isoformat(timespec="seconds"),
        actor=r.actor,
        prev_status=r.prev_status,
        next_status=r.next_status,
        reason=r.reason,
        request_id=r.request_id,
    )


def _remediation_attempt_to_detail(a: RemediationAttempt) -> RemediationAttemptDetail:
    return RemediationAttemptDetail(
        attempt_id=a.attempt_id,
        case_id=a.case_id,
        kind=a.kind,
        status=a.status,
        actor=a.actor,
        created_at=a.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        action=a.action,
        result=a.result,
        readiness_before=a.readiness_before,
        readiness_after=a.readiness_after,
        note=a.note,
        request_id=a.request_id,
    )


class AssessRequest(BaseModel):
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    payload_size: int = 128
    observed_at: str = "2026-04-30T22:15:00+00:00"
    persist_case: bool = Field(
        default=True,
        description="Сохранять ли кейс в хранилище и добавлять событие в общее окно контекста.",
    )


class AssessResponse(BaseModel):
    risk_score: float
    risk_class: str
    invariant_hits: list[str]
    invariant_details: list[InvariantHitDetail]
    xai_what: str
    xai_why: str
    case_id: str
    dq_score: float
    dq_partial: bool
    merged_into_existing: bool


class CaseSummary(BaseModel):
    case_id: str
    status: str
    title: str
    risk_class: str
    risk_score: float
    fingerprint: str
    primary_asset_id: str
    trigger_operation: str
    last_event_source: str
    invariant_hits_count: int
    event_count: int
    created_at: str
    dq_score: float
    dq_partial: bool


class CaseDetail(BaseModel):
    case_id: str
    status: str
    title: str
    risk_class: str
    risk_score: float
    event_ids: list[str]
    invariant_hits: list[str]
    invariant_details: list[InvariantHitDetail]
    observations: list[ObservationDetail] = Field(default_factory=list)
    manual_permits: list[ManualPermitDetail] = Field(default_factory=list)
    decision_records: list[CaseDecisionRecordDetail] = Field(default_factory=list)
    remediation_attempts: list[RemediationAttemptDetail] = Field(default_factory=list)
    invariant_hit_records: list[InvariantHitRecordDetail] = Field(default_factory=list)
    xai_summary: str
    audit_log: list[str]
    fingerprint: str
    primary_asset_id: str
    trigger_operation: str
    last_event_source: str
    created_at: str
    dq_score: float
    dq_partial: bool
    dq_reasons: list[str]
    pdf_last_sha256: str = ""
    pdf_last_generated_at: str = ""


class CasesFullExportResponse(BaseModel):
    exported_at: str
    count: int
    total_in_repo: int
    offset: int = 0
    limit: int | None = None
    cases: list[CaseDetail]


class CasesImportBody(BaseModel):
    cases: list[CaseDetail] = Field(
        max_length=_EXPORT_FULL_MAX,
        description=f"Карточки в формате выгрузки (не более {_EXPORT_FULL_MAX}).",
    )
    mode: Literal["upsert", "skip_existing"] = Field(
        default="upsert",
        description="upsert — запись/перезапись по case_id; skip_existing — пропуск уже существующих.",
    )


class CasesImportResponse(BaseModel):
    imported: int
    skipped: int
    mode: str


class CasesStatsResponse(BaseModel):
    total: int
    open: int
    by_status: dict[str, int]
    by_risk_class: dict[str, int]
    avg_risk_score: float
    avg_dq_score: float
    dq_partial_count: int
    normalized_events_total: int
    distinct_invariant_hits: int
    invariant_hits_occurrences_total: int
    by_last_event_source: dict[str, int]


class MiddlewareErrorJson(BaseModel):
    """Тело **JSON** для ответов ошибок HTTP middleware (**401**, **411**, **413**, **429** — см. README)."""

    detail: str = Field(..., description="Краткое описание причины отказа.")
    request_id: str | None = Field(
        None,
        description="Идентификатор запроса; совпадает с **X-Request-ID**, если заголовок был передан или сгенерирован.",
    )


_MIDDLEWARE_ERROR_OPENAPI: dict[int | str, dict[str, Any]] = {
    401: {
        "description": (
            "Unauthorized: при активной аутентификации (**TAKT_AUTH_REQUIRED** и ключ) отсутствует или неверен "
            "**X-TAKT-API-Key** / **Authorization: Bearer**. **X-Request-ID**, **X-Process-Time**."
        ),
        "model": MiddlewareErrorJson,
    },
    411: {
        "description": (
            "**Length Required**: для **POST**/**PUT**/**PATCH** при **Transfer-Encoding: chunked** нужен **Content-Length** "
            "(см. **TAKT_MAX_REQUEST_BODY_MB**). **X-Request-ID**, **X-Process-Time**."
        ),
        "model": MiddlewareErrorJson,
    },
    413: {
        "description": (
            "**Payload Too Large**: тело запроса превышает лимит (**TAKT_MAX_REQUEST_BODY_MB**). "
            "**X-Request-ID**, **X-Process-Time**."
        ),
        "model": MiddlewareErrorJson,
    },
    429: {
        "description": (
            "**Too Many Requests**: превышен in-memory лимит (**TAKT_RATE_LIMIT_PER_MIN**). "
            "Заголовок **Retry-After** (секунды до сброса окна), **X-RateLimit-***, **X-Request-ID**, **X-Process-Time**."
        ),
        "model": MiddlewareErrorJson,
    },
}


class HealthAuthBlock(BaseModel):
    mode: Literal["required", "optional", "disabled"]


class HealthSiemBlock(BaseModel):
    allowlist_mode: str = Field(description="Режим allowlist SIEM webhook (напр. **structural**).")
    profile: str = Field(description="**TAKT_SECURITY_PROFILE**: **dev** или **prod**.")


class HealthProxyBlock(BaseModel):
    trusted_count: int = Field(
        ge=0,
        description="Число уникальных CIDR (**TAKT_TRUSTED_PROXIES** и **TAKT_TRUSTED_PROXY_CIDRS**).",
    )


class HealthRateLimitGate(BaseModel):
    """Режим извлечения IP для rate limit (Спринт 1)."""

    proxy_mode: Literal["direct", "trusted_header"]


class HealthSecurityLogGate(BaseModel):
    """Журнал безопасности (Спринт 1)."""

    status: str = Field(description="**ok**, **memory_only**, **sqlite**, …")
    entries_last_hour: int = Field(ge=0)


class HealthResponse(BaseModel):
    """Сводка состояния API и лимитов (см. **`GET /health`** в README)."""

    model_config = ConfigDict(extra="ignore")
    status: Literal["ok"] = "ok"
    product: str
    version: str
    python_version: str
    python_implementation: str = Field(
        description="**`sys.implementation.name`** интерпретатора (напр. **`cpython`**, **`graalpy`**).",
    )
    api_log_level: str
    uptime_seconds: float
    booted_at_utc: str
    process_id: int = Field(description="PID процесса (**`os.getpid()`**).")
    hostname: str = Field(description="Имя узла ОС (**`socket.gethostname()`**).")
    platform: str = Field(
        description="**`sys.platform`** (напр. **`linux`**, **`win32`**, **`darwin`**).",
    )
    python_executable: str = Field(description="Путь к двоичному файлу интерпретатора (**`sys.executable`**).")
    working_directory: str = Field(description="Текущий рабочий каталог процесса (**`os.getcwd()`**).")
    api_key_enabled: bool
    auth: HealthAuthBlock
    siem: HealthSiemBlock
    proxy: HealthProxyBlock
    rate_limit: HealthRateLimitGate
    security_log: HealthSecurityLogGate
    takt_config_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_CONFIG`** (путь к YAML в ответе не возвращается).",
    )
    takt_storage_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_STORAGE`** (`memory` / `sqlite`; значение в ответе не дублируется).",
    )
    takt_sqlite_path_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_SQLITE_PATH`** (путь к файлу БД в ответе не возвращается).",
    )
    takt_sqlite_busy_timeout_ms_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_SQLITE_BUSY_TIMEOUT_MS`** (**PRAGMA busy_timeout**; для **`sqlite_busy_timeout_ms`** см. эффективное значение).",
    )
    takt_log_level_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_LOG_LEVEL`**; неверное значение не меняет **`api_log_level`**.",
    )
    takt_max_request_body_mb_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_MAX_REQUEST_BODY_MB`**; при **`max_request_body_bytes`: null** лимит не активен.",
    )
    takt_slow_request_log_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_SLOW_REQUEST_LOG_SEC`**; при отсутствии **`slow_request_log_threshold_sec`** порог не активен.",
    )
    takt_cors_origins_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_CORS_ORIGINS`**; список может не дать **`cors_enabled`** (напр. только запятые).",
    )
    takt_hsts_max_age_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_HSTS_MAX_AGE`**; при неверном или **≤ 0** **`hsts_enabled`** будет **false**.",
    )
    takt_hsts_preload_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_HSTS_PRELOAD`**; **`hsts_preload_enabled`** только при активном HSTS.",
    )
    cors_enabled: bool
    hsts_enabled: bool
    hsts_preload_enabled: bool = Field(
        description="**True**, если HSTS включён и **`TAKT_HSTS_PRELOAD`** — **1**/**true**/**yes**.",
    )
    gzip_minimum_size_bytes: int
    openapi_servers_count: int = 0
    takt_openapi_server_url_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_OPENAPI_SERVER_URL`** (валидные URL — только в **`openapi_servers_count`**).",
    )
    takt_request_id_header_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_REQUEST_ID_HEADER`** (имя может быть отклонено; тогда нет **`request_id_alternate_header`**).",
    )
    request_id_alternate_header: str | None = Field(
        default=None,
        description="Дополнительный входящий заголовок для ID запроса (**TAKT_REQUEST_ID_HEADER**), если задан.",
    )
    case_storage: str
    expected_behavior_storage: str
    cases_total: int
    cases_open: int
    event_window_len: int
    ingest_trust_sources: int
    ingest_trust_by_source: dict[str, float]
    full_json_max_cases: int
    ingest_event_window_max: int
    ingest_recent_for_context: int
    ingest_batch_max_events: int
    cases_list_max_limit: int
    cases_list_default_sort: str
    siem_webhook_retries: int
    siem_webhook_backoff_sec: float
    siem_webhook_allowlist_prefixes_count: int
    export_pdf_unicode_font_configured: bool
    gossopka_profile: str = "mvp"
    gossopka_official_exchange_enabled: bool = False
    ingest_syslog_rfc5424_enabled: bool = False
    ingest_snmp_enabled: bool = False
    ingest_netflow_enabled: bool = False
    ingest_ipfix_enabled: bool = False
    ldap_integration_configured: bool = False
    ad_integration_configured: bool = False
    timeseries_backend: str = "sqlite"
    timeseries_configured: bool = False
    object_storage_backend: str = "none"
    object_storage_configured: bool = False
    forensic_crypto_mode: str = "mvp"
    forensic_strict_ready: bool = False
    forensic_strict_missing: list[str] = Field(default_factory=list)
    sqlite_schema_version: int | None = None
    sqlite_busy_timeout_ms: int | None = Field(
        default=None,
        description="**PRAGMA busy_timeout** (мс) при **storage.backend: sqlite**; см. **TAKT_SQLITE_BUSY_TIMEOUT_MS**.",
    )
    max_request_body_bytes: int | None = None
    slow_request_log_threshold_sec: float | None = None
    takt_catalog_cache_max_age_sec_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_CATALOG_CACHE_MAX_AGE_SEC`** (эффективный **`catalog_cache_max_age_sec`** может отличаться).",
    )
    catalog_cache_max_age_sec: int | None = None
    takt_metrics_env_enabled: bool = Field(
        default=False,
        description="**True**, если **`TAKT_METRICS`** запрашивает **`/metrics`** (**1**/**true**/**yes**); без **prometheus-client** **`prometheus_metrics_enabled`** остаётся **false**.",
    )
    prometheus_metrics_enabled: bool = False
    takt_rate_limit_env_set: bool = Field(
        description="**True**, если **`TAKT_RATE_LIMIT_PER_MIN`** непуста в окружении; при **`rate_limit_per_minute`: null** лимит не активен (неверное или **≤ 0**).",
    )
    takt_rate_limit_max_ips_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_RATE_LIMIT_MAX_IPS`** (учитывается только при активном лимите).",
    )
    takt_rate_limit_ip_header_env_set: bool = Field(
        description="**True**, если задана непустая **`TAKT_RATE_LIMIT_IP_HEADER`** (имя может быть отклонено; тогда нет **`rate_limit_ip_header`**).",
    )
    rate_limit_per_minute: int | None = None
    rate_limit_max_tracked_ips: int | None = None
    rate_limit_tracked_ips: int | None = None
    rate_limit_ip_header: str | None = None
    takt_build_revision_env_set: bool = Field(
        description="**True**, если **`TAKT_BUILD_REVISION`** непуста в окружении (см. **`build_revision`**).",
    )
    build_revision: str | None = Field(
        default=None,
        max_length=_TAKT_BUILD_REVISION_MAX_LEN,
        description="Метка ревизии/сборки из **TAKT_BUILD_REVISION** (CI, образ), если переменная непуста.",
    )


class LiveResponse(BaseModel):
    """Liveness без обращения к хранилищу (**`GET /live`**)."""

    live: Literal[True] = True
    product: str
    version: str
    build_revision: str | None = Field(
        default=None,
        max_length=_TAKT_BUILD_REVISION_MAX_LEN,
        description="Как **`GET /health`**: из **TAKT_BUILD_REVISION**, если непусто.",
    )


class ReadyResponse(BaseModel):
    """Readiness при успешной проверке хранилища (**`GET /ready`**)."""

    ready: Literal[True] = True
    case_storage: str
    expected_behavior_storage: str
    forensic_crypto_mode: str = "mvp"
    forensic_strict_ready: bool = False
    forensic_strict_missing: list[str] = Field(default_factory=list)
    build_revision: str | None = Field(
        default=None,
        max_length=_TAKT_BUILD_REVISION_MAX_LEN,
        description="Как **`GET /health`**: из **TAKT_BUILD_REVISION**, если непусто.",
    )


class CaseDecisionResponse(BaseModel):
    ok: Literal[True] = True
    case_id: str
    status: str


class SiemForwardResponse(BaseModel):
    ok: Literal[True] = True
    http_status: int


class SiemForwardAsyncResponse(BaseModel):
    ok: Literal[True] = True
    http_status: int
    async_handled: Literal[True] = Field(serialization_alias="async")


class BacktestFixtureResponse(BaseModel):
    events_processed: int
    cases_created: int
    merges: int
    risk_class_histogram: dict[str, int]


class DecisionBody(BaseModel):
    status: CaseStatus
    reason: str = ""


class DataQualityResponse(BaseModel):
    dq_score: float
    partial_observability: bool
    reasons: list[str]


class SiemForwardBody(BaseModel):
    case_id: str
    target_url: str


class ManualPermitBody(BaseModel):
    work_order_number: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(default="", max_length=256)
    operation: str = Field(default="", max_length=256)
    note: str = Field(default="", max_length=2000)


class RemediationAttemptBody(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    status: str = Field(default="recorded", max_length=64)
    action: str = Field(default="", max_length=512)
    result: str = Field(default="", max_length=2000)
    note: str = Field(default="", max_length=2000)


class AuditEngagementCreateBody(BaseModel):
    customer: str = Field(min_length=1, max_length=256)
    scope: str = Field(min_length=1, max_length=5000)
    case_ids: list[str] = Field(default_factory=list, max_length=200)
    nda_signed: bool = False
    evidence_intake_checklist: list[str] = Field(default_factory=list, max_length=200)


class AuditStageOut(BaseModel):
    code: str
    title: str
    day_range: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    note: str = ""


class AuditFinalReportOut(BaseModel):
    title: str
    uri: str
    summary: str
    generated_at: str


class AuditEngagementOut(BaseModel):
    engagement_id: str
    created_at: str
    status: str
    customer: str
    scope: str
    case_ids: list[str]
    nda_signed: bool
    evidence_intake_checklist: list[str]
    stages: list[AuditStageOut]
    findings: list[str]
    final_report: AuditFinalReportOut | None = None


class AuditStageAdvanceBody(BaseModel):
    note: str = Field(default="", max_length=2000)


class AuditFindingBody(BaseModel):
    finding: str = Field(min_length=1, max_length=4000)


class AuditFinalizeReportBody(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    uri: str = Field(min_length=1, max_length=2000)
    summary: str = Field(default="", max_length=8000)


class AuditEngagementReportOut(BaseModel):
    format: str
    generated_at: str
    engagement: AuditEngagementOut
    findings_count: int
    stages_completed: int
    stages_total: int
    nda_signed: bool
    has_final_report: bool


class DemoGraphEdgeOut(BaseModel):
    src: str
    dst: str
    kind: str


class DemoTopologyResponse(BaseModel):
    """Эталон из `topology` + рёбра, которые используют **`POST /assess`**, `/events`, `/backtest/fixture`."""

    jump_host: str
    plc_hosts: list[str]
    edges: list[DemoGraphEdgeOut]
    has_jump_bypass_pattern: bool


class EventIngestBody(BaseModel):
    """Полноценный ingest в L1 + ProcessEvent (обогащение, IEC-подсказки, assess)."""

    observed_at: str
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    payload_size: int = 128
    source: str | None = Field(
        default=None,
        description="auth_logs | network_events | plc_polling | service_desk | unknown",
    )
    event_id: str | None = None
    payload: dict[str, Any] | None = None


class IntegrationIngestBody(BaseModel):
    observed_at: str
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    payload_size: int = 128
    event_id: str | None = None
    payload: dict[str, Any] | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)


class SyslogRfc5424IngestBody(BaseModel):
    observed_at: str
    protocol: str = "SYSLOG_RFC5424"
    operation: str = "SYSLOG_EVENT"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    message: str = Field(default="", max_length=8192)
    hostname: str = Field(default="", max_length=255)
    app_name: str = Field(default="", max_length=128)
    procid: str = Field(default="", max_length=64)
    msgid: str = Field(default="", max_length=64)
    severity: int | None = Field(default=None, ge=0, le=7)
    facility: int | None = Field(default=None, ge=0, le=23)
    structured_data: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None


class SnmpTrapIngestBody(BaseModel):
    observed_at: str
    protocol: str = "SNMP_TRAP"
    operation: str = "SNMP_TRAP"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    trap_oid: str = Field(default="", max_length=255)
    version: str = Field(default="v2c", max_length=16)
    community: str = Field(default="", max_length=128)
    agent_addr: str = Field(default="", max_length=64)
    varbinds: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None


class NetflowIngestBody(BaseModel):
    observed_at: str
    protocol: str = "NETFLOW"
    operation: str = "NETFLOW_FLOW"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    exporter_ip: str = Field(default="", max_length=64)
    src_ip: str = Field(default="", max_length=64)
    dst_ip: str = Field(default="", max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    flow_start: str = ""
    flow_end: str = ""
    payload: dict[str, Any] | None = None


class IpfixIngestBody(BaseModel):
    observed_at: str
    protocol: str = "IPFIX"
    operation: str = "IPFIX_FLOW"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    exporter_ip: str = Field(default="", max_length=64)
    src_ip: str = Field(default="", max_length=64)
    dst_ip: str = Field(default="", max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    template_id: int | None = Field(default=None, ge=0)
    observation_domain_id: int | None = Field(default=None, ge=0)
    payload: dict[str, Any] | None = None


class EventBatchBody(BaseModel):
    events: list[EventIngestBody] = Field(min_length=1, max_length=_INGEST_BATCH_MAX)


class BatchAssessResponse(BaseModel):
    results: list[AssessResponse]
    count: int


class InvariantCatalogItem(BaseModel):
    id: str
    block_key: str
    block_label_ru: str
    title_ru: str
    experimental: bool = False


class EventSourceCatalogItem(BaseModel):
    id: str
    ingest_trust: float | None = Field(
        default=None,
        description="Значение из ingest_trust.by_source; null — ключ не задан (в оценке для источника используется 1.0).",
    )


def _domain_case_from_detail(d: CaseDetail) -> Case:
    try:
        status = CaseStatus(d.status.strip().upper())
    except ValueError as e:
        raise ValueError(f"case {d.case_id}: invalid status {d.status!r}") from e
    obs_dom = [
        Observation(source=o.source, ingest_trust=o.ingest_trust, event_ids=list(o.event_ids))
        for o in d.observations
    ]
    rec_dom = [
        InvariantHitRecord(
            invariant_id=r.invariant_id,
            event_ref=r.event_ref,
            ts=_parse_import_created_at(r.ts),
            score_contribution=r.score_contribution,
            dq_score=r.dq_score,
            dq_partial=r.dq_partial,
            dq_reasons=list(r.dq_reasons),
        )
        for r in d.invariant_hit_records
    ]
    permit_dom = [
        ManualPermit(
            permit_id=p.permit_id,
            case_id=p.case_id,
            work_order_number=p.work_order_number,
            actor=p.actor,
            created_at=_parse_import_created_at(p.created_at),
            asset_id=p.asset_id,
            operation=p.operation,
            verdict=p.verdict,
            confidence=p.confidence,
            rationale=p.rationale,
            counterfactual=p.counterfactual,
            note=p.note,
        )
        for p in d.manual_permits
    ]
    remediation_dom = [
        RemediationAttempt(
            attempt_id=a.attempt_id,
            case_id=a.case_id,
            kind=a.kind,
            status=a.status,
            actor=a.actor,
            created_at=_parse_import_created_at(a.created_at),
            action=a.action,
            result=a.result,
            readiness_before=a.readiness_before,
            readiness_after=a.readiness_after,
            note=a.note,
            request_id=a.request_id,
        )
        for a in d.remediation_attempts
    ]
    decision_dom = [
        CaseDecisionRecord(
            ts=_parse_import_created_at(r.ts),
            actor=r.actor,
            prev_status=r.prev_status,
            next_status=r.next_status,
            reason=r.reason,
            request_id=r.request_id,
        )
        for r in d.decision_records
    ]
    return Case(
        case_id=d.case_id,
        status=status,
        title=d.title,
        risk_class=d.risk_class,
        risk_score=d.risk_score,
        created_at=_parse_import_created_at(d.created_at),
        normalized_event_ids=list(d.event_ids),
        xai_summary=d.xai_summary,
        audit_log=list(d.audit_log),
        burst_fingerprint=d.fingerprint,
        primary_asset_id=d.primary_asset_id,
        trigger_operation=d.trigger_operation,
        invariant_hits=list(d.invariant_hits),
        observations=obs_dom,
        manual_permits=permit_dom,
        decision_records=decision_dom,
        remediation_attempts=remediation_dom,
        invariant_hit_records=rec_dom,
        dq_score=d.dq_score,
        dq_partial=d.dq_partial,
        dq_reasons=list(d.dq_reasons),
        last_event_source=d.last_event_source,
        pdf_last_sha256=d.pdf_last_sha256,
        pdf_last_generated_at=d.pdf_last_generated_at,
    )


def create_app() -> FastAPI:
    apply_takt_api_log_level_from_env()
    app = FastAPI(
        title="ТАКТ Industrial Risk Layer",
        version=_PACKAGE_VERSION,
        lifespan=_app_lifespan,
        responses=_MIDDLEWARE_ERROR_OPENAPI,
    )
    app.state.prometheus_metrics_active = False
    app.state.booted_at_utc = datetime.now(timezone.utc)
    app.state.boot_monotonic = time.monotonic()
    app.state.rate_limit_lock = threading.Lock()
    app.state.rate_limit_buckets = {}
    cfg_path = _resolve_config_path()
    weights = load_risk_weights(cfg_path)
    apply_storage_env_overrides(weights)
    stor = weights.get("storage") if isinstance(weights.get("storage"), dict) else {}
    case_backend = str(stor.get("backend", "memory")).strip().lower()
    app.state.case_storage_backend = "sqlite" if case_backend == "sqlite" else "memory"
    app.state.expected_behavior_backend = app.state.case_storage_backend
    repo = case_repository_from_weights(weights, project_root=_ROOT)
    baseline = expected_behavior_from_weights(weights, project_root=_ROOT)
    jump_host, plc_hosts = topology_from_weights(weights)
    inv_catalog = load_invariant_catalog_from_dir(_invariant_catalog_dir_for_config(cfg_path))
    app.state.invariant_catalog = inv_catalog
    inv_rule_overrides = catalog_rule_overrides(inv_catalog)
    inv_profile = invariant_context_from_config(weights)
    assess = AssessRiskUseCase(
        weights,
        jump_host=jump_host,
        plc_hosts=plc_hosts,
        expected_behavior=baseline,
        invariant_profile=inv_profile,
        rule_overrides=inv_rule_overrides,
        experimental_invariant_ids=catalog_experimental_invariant_ids(inv_catalog),
        rule_specs=catalog_rule_specs(inv_catalog),
    )
    enr = enrichment_from_weights(weights)
    process = ProcessEventUseCase(assess, repo, enrichment=enr)
    compliance_report_uc = BuildComplianceDataQualityReportUseCase(repo, default_clock)
    forensic_readiness_uc = BuildForensicReadinessReportUseCase(repo, default_clock)
    evidence_checklist_uc = BuildCaseEvidenceChecklistUseCase(repo, default_clock)
    decision_uc = SubmitCaseDecisionUseCase(repo, baseline)
    forensic_uc = BuildForensicBundleUseCase(
        repo,
        ZipForensicBundleBuilder(),
        default_clock,
        compliance_report_uc,
        forensic_readiness_uc,
        evidence_checklist_uc,
    )
    forensic_verify_uc = VerifyForensicBundleUseCase(ZipForensicBundleVerifier())
    manual_permit_uc = AttachManualPermitUseCase(repo, default_clock, default_id_provider)
    remediation_uc = RecordRemediationAttemptUseCase(repo, default_clock, default_id_provider)
    remediation_list_uc = ListRemediationAttemptsUseCase(repo)
    if isinstance(repo, SqliteCaseStore):
        audit_engagement_store = SqliteAuditEngagementStore(repo.database_path)
    else:
        audit_engagement_store = InMemoryAuditEngagementStore()
    audit_engagement_uc = ManageAuditEngagementUseCase(
        audit_engagement_store,
        default_clock,
        default_id_provider,
    )
    backtest_uc = RunBacktestUseCase(process)
    app.state.ingest_recent_for_context = process.recent_context_event_count
    demo_edges = graph_edges_from_weights(weights, plc_hosts=plc_hosts)

    app.state.repo = repo
    app.state.idempotency_store = repo if isinstance(repo, SqliteCaseStore) else InMemoryIdempotencyStore()
    app.state.baseline = baseline
    app.state.audit_engagement_store = audit_engagement_store
    app.state.last_dq = None
    app.state.event_window = []
    sw = weights.get("siem_webhook") if isinstance(weights.get("siem_webhook"), dict) else {}
    raw_prefixes = sw.get("allowed_url_prefixes")
    app.state.siem_webhook_prefixes = list(raw_prefixes) if isinstance(raw_prefixes, list) else []
    exp = weights.get("export") if isinstance(weights.get("export"), dict) else {}
    wh_retries, wh_backoff = siem_webhook_retries(weights)
    app.state.webhook_retries = wh_retries
    app.state.webhook_backoff_sec = wh_backoff
    raw_font = exp.get("pdf_unicode_font")
    app.state.pdf_unicode_font = str(raw_font).strip() if raw_font else None
    app.state.trust_by_source = trust_by_source_from_weights(weights)

    sqlite_security_path: Path | None = None
    if isinstance(repo, SqliteCaseStore):
        sqlite_security_path = repo.database_path
    app.state.security_log = SecurityLogService(
        sqlite_db_path=sqlite_security_path,
        file_path=security_log_file_path_from_env(),
    )

    app.add_middleware(GZipMiddleware, minimum_size=_GZIP_MINIMUM_SIZE_BYTES)
    app.add_middleware(OptionalApiKeyMiddleware)
    app.add_middleware(SecurityLogMiddleware)
    app.add_middleware(RequestBodySizeLimitMiddleware)
    app.add_middleware(InMemoryRateLimitMiddleware)
    app.add_middleware(RequestIdMiddleware)
    add_cors_middleware_if_configured(app)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CasesPrivateNoStoreMiddleware)
    app.add_middleware(CatalogCacheControlMiddleware)
    app.add_middleware(ProcessTimeMiddleware)

    _demo_intervals = [1000.0, 1000.0, 4670.0, 21_800.0]

    def _forensic_crypto_mode() -> str:
        return os.environ.get("TAKT_FORENSIC_CRYPTO_MODE", "").strip().lower() or "mvp"

    def _forensic_strict_missing() -> list[str]:
        if _forensic_crypto_mode() != "gost_strict":
            return []
        missing: list[str] = []
        if not os.environ.get("TAKT_FORENSIC_SIGN_URL", "").strip():
            missing.append("TAKT_FORENSIC_SIGN_URL")
        if not os.environ.get("TAKT_FORENSIC_VERIFY_URL", "").strip():
            missing.append("TAKT_FORENSIC_VERIFY_URL")
        return missing

    def _build_raw_evidence_ref(
        *,
        raw_payload: bytes,
        source: str,
        event_id: str,
        captured_at: datetime,
        media_type: str = "application/json",
        note: str = "",
    ) -> RawEvidenceRef:
        sha = hashlib.sha256(raw_payload).hexdigest()
        return RawEvidenceRef(
            evidence_id=f"{event_id or 'event'}-{sha[:16]}",
            source=source,
            media_type=media_type,
            captured_at=captured_at,
            payload_b64=base64.b64encode(raw_payload).decode("ascii"),
            sha256=sha,
            size_bytes=len(raw_payload),
            event_id=event_id,
            note=note,
        )

    def _attach_raw_evidence(case: Case, ref: RawEvidenceRef, *, persist_case: bool) -> None:
        for existing in case.raw_evidence_refs:
            if (
                existing.sha256 == ref.sha256
                and existing.event_id == ref.event_id
                and existing.source == ref.source
            ):
                return
        case.raw_evidence_refs.append(ref)
        case.append_audit(f"raw evidence captured evidence_id={ref.evidence_id} sha256={ref.sha256}", ref.captured_at)
        if persist_case:
            repo.save(case)

    def _assess_normalized_event(
        ev: NormalizedEvent,
        *,
        persist_case: bool = True,
        raw_evidence_ref: RawEvidenceRef | None = None,
    ) -> AssessResponse:
        tickets: list[ServiceTicket] = []
        edges = list(demo_edges)
        recent = _take_recent(app.state.event_window, process.recent_context_event_count)
        out = process.execute(
            ev,
            persist=persist_case,
            recent_events=recent,
            tickets=tickets,
            graph_edges=edges,
            polling_intervals_us=_demo_intervals,
            clock=ev.observed_at,
            trust_by_source=app.state.trust_by_source,
        )
        if raw_evidence_ref is not None:
            _attach_raw_evidence(out.case, raw_evidence_ref, persist_case=persist_case)
        if persist_case:
            app.state.event_window.append(ev)
            _trim_event_window(app.state.event_window)
        app.state.last_dq = out.assessment.data_quality
        dq = out.assessment.data_quality
        hits = list(out.case.invariant_hits)
        latency_seconds: float | None = None
        try:
            latency_seconds = max(
                0.0,
                (datetime.now(timezone.utc) - ev.observed_at.astimezone(timezone.utc)).total_seconds(),
            )
        except Exception:
            latency_seconds = None
        record_business_assessment(
            risk_class=out.case.risk_class,
            risk_score=out.case.risk_score,
            invariant_hits=hits,
            dq_partial=bool(dq.partial_observability),
            merged_into_existing=out.merged_into_existing,
            event_to_case_latency_seconds=latency_seconds,
        )
        return AssessResponse(
            risk_score=out.case.risk_score,
            risk_class=out.case.risk_class,
            invariant_hits=hits,
            invariant_details=_invariant_details_for_hits(hits),
            xai_what=out.assessment.xai.what,
            xai_why=out.assessment.xai.why_unusual,
            case_id=out.case.case_id,
            dq_score=dq.dq_score,
            dq_partial=dq.partial_observability,
            merged_into_existing=out.merged_into_existing,
        )

    def _audit_engagement_out(item: AuditEngagement) -> AuditEngagementOut:
        return AuditEngagementOut(
            engagement_id=item.engagement_id,
            created_at=item.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            status=item.status,
            customer=item.customer,
            scope=item.scope,
            case_ids=list(item.case_ids),
            nda_signed=item.nda_signed,
            evidence_intake_checklist=list(item.evidence_intake_checklist),
            stages=[
                AuditStageOut(
                    code=s.code,
                    title=s.title,
                    day_range=s.day_range,
                    status=s.status,
                    started_at=(s.started_at.astimezone(timezone.utc).isoformat(timespec="seconds") if s.started_at else None),
                    completed_at=(
                        s.completed_at.astimezone(timezone.utc).isoformat(timespec="seconds") if s.completed_at else None
                    ),
                    note=s.note,
                )
                for s in item.stages
            ],
            findings=list(item.findings),
            final_report=(
                AuditFinalReportOut(
                    title=item.final_report.title,
                    uri=item.final_report.uri,
                    summary=item.final_report.summary,
                    generated_at=item.final_report.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
                )
                if item.final_report is not None
                else None
            ),
        )

    def _audit_engagement_bundle_files(case_id: str, engagement_id: str) -> list[tuple[str, str, bytes]]:
        eid = engagement_id.strip()
        if not eid:
            return []
        engagement = audit_engagement_uc.get(eid)
        if engagement is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        if case_id not in engagement.case_ids:
            raise HTTPException(status_code=400, detail="engagement is not linked to case")
        payload = _audit_engagement_out(engagement).model_dump()
        files: list[tuple[str, str, bytes]] = [
            ("engagement.json", "application/json", _json_bytes(payload)),
        ]
        if payload.get("final_report") is not None:
            files.append(("engagement-report.json", "application/json", _json_bytes(payload["final_report"])))
        return files

    def _audit_engagement_summary() -> dict[str, int]:
        items = audit_engagement_uc.list_all()
        return {
            "total": len(items),
            "active": sum(1 for i in items if i.status == "active"),
            "completed": sum(1 for i in items if i.status == "completed"),
            "with_final_report": sum(1 for i in items if i.final_report is not None),
        }

    @app.get("/live", response_model=LiveResponse, response_model_exclude_none=True, tags=["System"])
    def live():
        """Liveness: процесс отвечает, без обращения к БД (Kubernetes **livenessProbe**)."""
        br = build_revision_from_env()
        return LiveResponse(
            product="TAKT-MVP",
            version=_PACKAGE_VERSION,
            build_revision=br,
        )

    @app.head("/live", tags=["System"])
    def live_probe():
        """Тот же **200**, что **GET /live**, без тела ответа (**HEAD** для проб)."""
        return Response()

    def _health_payload() -> dict[str, Any]:
        all_cases = repo.list_all()
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
            "version": _PACKAGE_VERSION,
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
            "gzip_minimum_size_bytes": _GZIP_MINIMUM_SIZE_BYTES,
            "openapi_servers_count": len(openapi_server_entries_from_env()),
            "takt_openapi_server_url_env_set": bool(os.environ.get("TAKT_OPENAPI_SERVER_URL", "").strip()),
            "takt_request_id_header_env_set": bool(os.environ.get("TAKT_REQUEST_ID_HEADER", "").strip()),
            "case_storage": app.state.case_storage_backend,
            "expected_behavior_storage": app.state.expected_behavior_backend,
            "cases_total": len(all_cases),
            "cases_open": open_n,
            "event_window_len": len(app.state.event_window),
            "ingest_trust_sources": len(tbs),
            "ingest_trust_by_source": tbs,
            "full_json_max_cases": _EXPORT_FULL_MAX,
            "ingest_event_window_max": _EVENT_WINDOW_MAX,
            "ingest_recent_for_context": getattr(app.state, "ingest_recent_for_context", 5),
            "ingest_batch_max_events": _INGEST_BATCH_MAX,
            "cases_list_max_limit": _CASE_LIST_MAX_LIMIT,
            "cases_list_default_sort": _CASE_LIST_DEFAULT_SORT,
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
            "forensic_crypto_mode": _forensic_crypto_mode(),
            "forensic_strict_ready": not _forensic_strict_missing(),
            "forensic_strict_missing": _forensic_strict_missing(),
        }
        rid_alt = request_id_alternate_header_from_env()
        if rid_alt is not None:
            out["request_id_alternate_header"] = rid_alt
        ver_fn = getattr(repo, "db_schema_version", None)
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
        br = build_revision_from_env()
        out["takt_build_revision_env_set"] = bool(os.environ.get("TAKT_BUILD_REVISION", "").strip())
        if br is not None:
            out["build_revision"] = br
        return out

    @app.get("/health", response_model=HealthResponse, response_model_exclude_none=True, tags=["System"])
    def health():
        return HealthResponse.model_validate(_health_payload())

    @app.head("/health", tags=["System"])
    def health_probe():
        """Как **GET /health** по побочным эффектам (запрос к хранилищу), без JSON-тела."""
        _health_payload()
        return Response()

    def _ready_or_fail() -> None:
        try:
            _ = repo.list_all()
            _ = baseline.is_expected("__ready_probe__", "PING")
            missing = _forensic_strict_missing()
            if missing:
                raise RuntimeError(f"forensic_strict_misconfigured: missing={','.join(missing)}")
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"not_ready: {e!s}") from e

    @app.get("/ready", response_model=ReadyResponse, response_model_exclude_none=True, tags=["System"])
    def ready():
        """Проверка готовности (хранилище кейсов и baseline отвечают). HTTP 503 при сбое."""
        _ready_or_fail()
        br = build_revision_from_env()
        return ReadyResponse(
            case_storage=app.state.case_storage_backend,
            expected_behavior_storage=app.state.expected_behavior_backend,
            forensic_crypto_mode=_forensic_crypto_mode(),
            forensic_strict_ready=not _forensic_strict_missing(),
            forensic_strict_missing=_forensic_strict_missing(),
            build_revision=br,
        )

    @app.head("/ready", tags=["System"])
    def ready_probe():
        """Как **GET /ready** по проверкам; **503** при недоступности хранилища; без тела при **200**."""
        _ready_or_fail()
        return Response()

    @app.get("/invariants", response_model=list[InvariantCatalogItem], tags=["Catalog"])
    def invariants_catalog(block_key: str | None = Query(default=None, description="Фильтр: rhythm, topology, …")):
        rows = tuple(app.state.invariant_catalog.records)
        if block_key is not None and block_key.strip() != "":
            bk = block_key.strip().lower()
            known = frozenset(r.block_key for r in rows)
            if bk not in known:
                raise HTTPException(
                    status_code=400,
                    detail=f"unknown block_key; use one of: {', '.join(sorted(known))}",
                )
            rows = tuple(r for r in rows if r.block_key == bk)
        return [
            InvariantCatalogItem(
                id=r.id,
                block_key=r.block_key,
                block_label_ru=r.block_label_ru,
                title_ru=r.title_ru,
                experimental=r.experimental,
            )
            for r in rows
        ]

    @app.get("/catalog/event-sources", response_model=list[EventSourceCatalogItem], tags=["Catalog"])
    def event_sources_catalog():
        tbs = app.state.trust_by_source or {}
        return [
            EventSourceCatalogItem(
                id=s.value,
                ingest_trust=(float(tbs[s.value]) if s.value in tbs else None),
            )
            for s in EventSource
        ]

    @app.get("/topology/demo-graph", response_model=DemoTopologyResponse, tags=["Catalog"])
    def demo_topology():
        bypass = detect_jump_server_bypass(list(demo_edges), jump_host, plc_hosts)
        return DemoTopologyResponse(
            jump_host=jump_host,
            plc_hosts=sorted(plc_hosts),
            edges=[DemoGraphEdgeOut(src=e.src, dst=e.dst, kind=e.kind) for e in demo_edges],
            has_jump_bypass_pattern=bypass,
        )

    def _assess_from_plc_demo_body(body: AssessRequest) -> AssessResponse:
        try:
            ev = raw_row_to_normalized(
                {
                    "timestamp": body.observed_at,
                    "protocol": body.protocol,
                    "operation": body.operation,
                    "asset_id": body.asset_id,
                    "payload_size": str(body.payload_size),
                },
                source=EventSource.PLC_POLLING,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_normalized_event(ev, persist_case=body.persist_case)

    def _assess_from_integration_ingest(body: IntegrationIngestBody, *, source: EventSource) -> AssessResponse:
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.payload:
            row.update(body.payload)
        try:
            ev = raw_row_to_normalized(row, source=source, event_id=body.event_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        payload_raw = body.model_dump_json(exclude_none=True).encode("utf-8")
        raw_ref = _build_raw_evidence_ref(
            raw_payload=payload_raw,
            source=source.value,
            event_id=ev.event_id,
            captured_at=ev.observed_at,
            note=f"integration_ingest:{source.value}",
        )
        return _assess_normalized_event(ev, raw_evidence_ref=raw_ref)

    def _assess_from_integration_row(
        *,
        row: dict[str, Any],
        source: EventSource,
        event_id: str | None,
        raw_payload: bytes,
        note: str,
    ) -> AssessResponse:
        try:
            ev = raw_row_to_normalized(row, source=source, event_id=event_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        raw_ref = _build_raw_evidence_ref(
            raw_payload=raw_payload,
            source=source.value,
            event_id=ev.event_id,
            captured_at=ev.observed_at,
            note=note,
        )
        return _assess_normalized_event(ev, raw_evidence_ref=raw_ref)

    def _parse_syslog_priority(message: str) -> tuple[int | None, int | None]:
        if not message.startswith("<"):
            return None, None
        end = message.find(">")
        if end <= 1:
            return None, None
        token = message[1:end]
        if not token.isdigit():
            return None, None
        pri = int(token, 10)
        return pri // 8, pri % 8

    @app.post("/assess", response_model=AssessResponse, tags=["Ingest"])
    def assess(body: AssessRequest):
        """Оценка риска по демо-телу (PLC_POLLING): сохранение кейса опционально через **persist_case**."""
        return _assess_from_plc_demo_body(body)

    @app.post("/assess/demo", response_model=AssessResponse, tags=["Ingest"], deprecated=True)
    def assess_demo(body: AssessRequest):
        """Устаревший путь; используйте **POST /assess**."""
        return _assess_from_plc_demo_body(body)

    @app.post("/events", response_model=AssessResponse, tags=["Ingest"])
    async def ingest_event(request: Request):
        raw = await request.body()
        idem = getattr(app.state, "idempotency_store", None)
        replay = idempotent_json_response_or_none(request=request, raw_body=raw, store=idem)
        if replay is not None:
            payload, _ = replay
            return JSONResponse(content=payload, headers={"X-Idempotent-Replayed": "true"})
        try:
            body = EventIngestBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        src = _coerce_event_source(body.source)
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
        }
        if body.payload:
            row.update(body.payload)
        try:
            ev = raw_row_to_normalized(row, source=src, event_id=body.event_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        raw_ref = _build_raw_evidence_ref(
            raw_payload=raw,
            source=src.value,
            event_id=ev.event_id,
            captured_at=ev.observed_at,
            note="events_ingest",
        )
        out = _assess_normalized_event(ev, raw_evidence_ref=raw_ref)
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out

    @app.post("/integrations/ingest/syslog/rfc5424", response_model=AssessResponse, tags=["Ingest"])
    def ingest_syslog_rfc5424(body: SyslogRfc5424IngestBody):
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        facility, severity = _parse_syslog_priority(body.message)
        row["syslog_severity"] = body.severity if body.severity is not None else severity
        row["syslog_facility"] = body.facility if body.facility is not None else facility
        if body.hostname:
            row["syslog_hostname"] = body.hostname
        if body.app_name:
            row["syslog_app_name"] = body.app_name
        if body.procid:
            row["syslog_procid"] = body.procid
        if body.msgid:
            row["syslog_msgid"] = body.msgid
        if body.structured_data:
            row["syslog_structured_data"] = body.structured_data
        if body.message:
            row["syslog_message"] = body.message
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.payload:
            row.update(body.payload)
        return _assess_from_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:syslog_rfc5424",
        )

    @app.post("/integrations/ingest/snmp/trap", response_model=AssessResponse, tags=["Ingest"])
    def ingest_snmp_trap(body: SnmpTrapIngestBody):
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.trap_oid:
            row["snmp_trap_oid"] = body.trap_oid
        if body.version:
            row["snmp_version"] = body.version
        if body.community:
            row["snmp_community"] = body.community
        if body.agent_addr:
            row["snmp_agent_addr"] = body.agent_addr
        if body.varbinds:
            row["snmp_varbinds"] = body.varbinds
        if body.payload:
            row.update(body.payload)
        return _assess_from_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:snmp_trap",
        )

    @app.post("/integrations/ingest/netflow", response_model=AssessResponse, tags=["Ingest"])
    def ingest_netflow(body: NetflowIngestBody):
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.exporter_ip:
            row["flow_exporter_ip"] = body.exporter_ip
        if body.src_ip:
            row["flow_src_ip"] = body.src_ip
        if body.dst_ip:
            row["flow_dst_ip"] = body.dst_ip
        if body.src_port is not None:
            row["flow_src_port"] = body.src_port
        if body.dst_port is not None:
            row["flow_dst_port"] = body.dst_port
        if body.bytes is not None:
            row["flow_bytes"] = body.bytes
        if body.packets is not None:
            row["flow_packets"] = body.packets
        if body.protocol_number is not None:
            row["flow_protocol_number"] = body.protocol_number
        if body.flow_start:
            row["flow_start"] = body.flow_start
        if body.flow_end:
            row["flow_end"] = body.flow_end
        if body.payload:
            row.update(body.payload)
        return _assess_from_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:netflow",
        )

    @app.post("/integrations/ingest/ipfix", response_model=AssessResponse, tags=["Ingest"])
    def ingest_ipfix(body: IpfixIngestBody):
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.exporter_ip:
            row["flow_exporter_ip"] = body.exporter_ip
        if body.src_ip:
            row["flow_src_ip"] = body.src_ip
        if body.dst_ip:
            row["flow_dst_ip"] = body.dst_ip
        if body.src_port is not None:
            row["flow_src_port"] = body.src_port
        if body.dst_port is not None:
            row["flow_dst_port"] = body.dst_port
        if body.bytes is not None:
            row["flow_bytes"] = body.bytes
        if body.packets is not None:
            row["flow_packets"] = body.packets
        if body.protocol_number is not None:
            row["flow_protocol_number"] = body.protocol_number
        if body.template_id is not None:
            row["ipfix_template_id"] = body.template_id
        if body.observation_domain_id is not None:
            row["ipfix_observation_domain_id"] = body.observation_domain_id
        if body.payload:
            row.update(body.payload)
        return _assess_from_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:ipfix",
        )

    @app.post("/events/batch", response_model=BatchAssessResponse, tags=["Ingest"])
    async def ingest_batch(request: Request):
        raw = await request.body()
        idem = getattr(app.state, "idempotency_store", None)
        replay = idempotent_json_response_or_none(request=request, raw_body=raw, store=idem)
        if replay is not None:
            payload, _ = replay
            return JSONResponse(content=payload, headers={"X-Idempotent-Replayed": "true"})
        try:
            body = EventBatchBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        results: list[AssessResponse] = []
        for i, item in enumerate(body.events):
            src = _coerce_event_source(item.source)
            row = {
                "timestamp": item.observed_at,
                "protocol": item.protocol,
                "operation": item.operation,
                "asset_id": item.asset_id,
                "payload_size": str(item.payload_size),
            }
            if item.payload:
                row.update(item.payload)
            try:
                ev = raw_row_to_normalized(row, source=src, event_id=item.event_id)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"events[{i}]: {e}") from e
            item_raw = json.dumps(item.model_dump(exclude_none=True), ensure_ascii=False, sort_keys=True).encode("utf-8")
            raw_ref = _build_raw_evidence_ref(
                raw_payload=item_raw,
                source=src.value,
                event_id=ev.event_id,
                captured_at=ev.observed_at,
                note="events_batch_ingest",
            )
            results.append(_assess_normalized_event(ev, raw_evidence_ref=raw_ref))
        out = BatchAssessResponse(results=results, count=len(results))
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out

    @app.get(
        "/cases",
        response_model=list[CaseSummary],
        tags=["Cases"],
        responses={
            200: {
                "description": "Список кейсов (после фильтров и сортировки, срез по offset/limit)",
                "headers": {
                    "X-Total-Count": {
                        "description": (
                            "Число записей после всех фильтров и сортировки, до применения offset/limit"
                        ),
                        "schema": {"type": "string", "example": "42"},
                    },
                    "Link": {
                        "description": (
                            "Пагинация (RFC 8288): при переданном query-параметре `limit` — "
                            "`rel=\"next\"` и/или `rel=\"prev\"` с теми же фильтрами, что в запросе"
                        ),
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    )
    def list_cases(
        request: Request,
        response: Response,
        status: str | None = Query(default=None, description="NEW, TRIAGE, …"),
        risk_class: str | None = Query(default=None, description="LOW, MEDIUM, HIGH, CRITICAL"),
        risk_classes: str | None = Query(
            default=None,
            description="Несколько классов через запятую, напр. HIGH,CRITICAL (пересекается с фильтром risk_class)",
        ),
        created_after: datetime | None = Query(
            default=None,
            description="ISO-8601: created_at >= момента (без часового пояса — UTC)",
        ),
        created_before: datetime | None = Query(
            default=None,
            description="ISO-8601: created_at <= момента (без часового пояса — UTC)",
        ),
        min_risk_score: float | None = Query(default=None, ge=0.0, le=1.0),
        max_risk_score: float | None = Query(
            default=None,
            ge=0.0,
            le=1.0,
            description="Кейсы с risk_score <= порога",
        ),
        min_dq_score: float | None = Query(
            default=None,
            ge=0.0,
            le=1.0,
            description="Кейсы с dq_score >= порога",
        ),
        max_dq_score: float | None = Query(
            default=None,
            ge=0.0,
            le=1.0,
            description="Кейсы с dq_score <= порога",
        ),
        dq_partial: bool | None = Query(
            default=None,
            description="true — только partial_observability; false — только полная наблюдаемость",
        ),
        has_invariant: str | None = Query(default=None, description="Подстрока id инварианта"),
        has_dq_reason: str | None = Query(
            default=None,
            description="Подстрока причины DQ (напр. source_reputation_drift, stale_data)",
        ),
        primary_asset_id: str | None = Query(
            default=None,
            description="Точное совпадение primary_asset_id (без учёта регистра)",
        ),
        fingerprint: str | None = Query(default=None, description="Точное совпадение burst_fingerprint"),
        fingerprint_prefix: str | None = Query(
            default=None,
            description="Префикс burst_fingerprint (без учёта регистра)",
        ),
        title_contains: str | None = Query(
            default=None,
            description="Подстрока в title кейса (без учёта регистра)",
        ),
        case_id_prefix: str | None = Query(
            default=None,
            description="Префикс case_id (без учёта регистра)",
        ),
        trigger_operation_contains: str | None = Query(
            default=None,
            description="Подстрока в trigger_operation последнего события (без учёта регистра)",
        ),
        min_invariant_hits: int | None = Query(
            default=None,
            ge=0,
            le=10_000,
            description="Минимум записей в invariant_hits",
        ),
        max_invariant_hits: int | None = Query(
            default=None,
            ge=0,
            le=10_000,
            description="Максимум записей в invariant_hits",
        ),
        xai_contains: str | None = Query(
            default=None,
            description="Подстрока в xai_summary (без учёта регистра)",
        ),
        min_event_count: int | None = Query(
            default=None,
            ge=1,
            le=100_000,
            description="Минимум нормализованных событий в кейсе (после merge — union event_ids)",
        ),
        max_event_count: int | None = Query(
            default=None,
            ge=0,
            le=100_000,
            description="Максимум нормализованных событий в кейсе",
        ),
        audit_contains: str | None = Query(
            default=None,
            description="Подстрока в любой строке audit_log (без учёта регистра)",
        ),
        event_source: str | None = Query(
            default=None,
            description="Точное совпадение last_event_source (EventSource последнего события в потоке)",
        ),
        sort: str = Query(
            default=_CASE_LIST_DEFAULT_SORT,
            description="risk_score|created_at|dq_score|invariant_hits|event_count|title|case_id|primary_asset_id — _desc или _asc",
        ),
        limit: int | None = Query(default=None, ge=1, le=_CASE_LIST_MAX_LIMIT, description="Ограничить число записей"),
        offset: int = Query(default=0, ge=0, description="Смещение после сортировки"),
    ):
        items: list[Case] = list(repo.list_all())
        if status is not None and status.strip() != "":
            st = _coerce_case_status(status)
            items = [c for c in items if c.status == st]
        if risk_class is not None and risk_class.strip() != "":
            rc = risk_class.strip().upper()
            if rc not in _VALID_RISK_CLASSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"invalid risk_class; use one of: {', '.join(sorted(_VALID_RISK_CLASSES))}",
                )
            items = [c for c in items if c.risk_class.upper() == rc]
        if risk_classes is not None and risk_classes.strip() != "":
            parts = {p.strip().upper() for p in risk_classes.split(",") if p.strip()}
            unknown = parts - _VALID_RISK_CLASSES
            if unknown:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"invalid risk_classes token(s): {', '.join(sorted(unknown))}; "
                        f"use: {', '.join(sorted(_VALID_RISK_CLASSES))}"
                    ),
                )
            items = [c for c in items if c.risk_class.upper() in parts]
        if created_after is not None:
            t0 = _as_utc_boundary(created_after)
            items = [c for c in items if c.created_at >= t0]
        if created_before is not None:
            t1 = _as_utc_boundary(created_before)
            items = [c for c in items if c.created_at <= t1]
        if min_risk_score is not None:
            items = [c for c in items if c.risk_score >= min_risk_score]
        if max_risk_score is not None:
            items = [c for c in items if c.risk_score <= max_risk_score]
        if min_dq_score is not None:
            items = [c for c in items if c.dq_score >= min_dq_score]
        if max_dq_score is not None:
            items = [c for c in items if c.dq_score <= max_dq_score]
        if dq_partial is not None:
            items = [c for c in items if c.dq_partial == dq_partial]
        if has_invariant is not None and has_invariant.strip() != "":
            needle = has_invariant.strip().lower()
            items = [c for c in items if any(needle in h.lower() for h in c.invariant_hits)]
        if has_dq_reason is not None and has_dq_reason.strip() != "":
            needle = has_dq_reason.strip().lower()
            items = [c for c in items if any(needle in r.lower() for r in c.dq_reasons)]
        if primary_asset_id is not None and primary_asset_id.strip() != "":
            aid = primary_asset_id.strip().lower()
            items = [c for c in items if c.primary_asset_id.lower() == aid]
        if fingerprint is not None and fingerprint.strip() != "":
            fpq = fingerprint.strip()
            items = [c for c in items if c.burst_fingerprint == fpq]
        if fingerprint_prefix is not None and fingerprint_prefix.strip() != "":
            fpfx = fingerprint_prefix.strip().lower()
            items = [c for c in items if c.burst_fingerprint.lower().startswith(fpfx)]
        if title_contains is not None and title_contains.strip() != "":
            needle = title_contains.strip().lower()
            items = [c for c in items if needle in c.title.lower()]
        if case_id_prefix is not None and case_id_prefix.strip() != "":
            pfx = case_id_prefix.strip().lower()
            items = [c for c in items if c.case_id.lower().startswith(pfx)]
        if trigger_operation_contains is not None and trigger_operation_contains.strip() != "":
            needle = trigger_operation_contains.strip().lower()
            items = [c for c in items if needle in c.trigger_operation.lower()]
        if min_invariant_hits is not None:
            items = [c for c in items if len(c.invariant_hits) >= min_invariant_hits]
        if max_invariant_hits is not None:
            items = [c for c in items if len(c.invariant_hits) <= max_invariant_hits]
        if xai_contains is not None and xai_contains.strip() != "":
            needle = xai_contains.strip().lower()
            items = [c for c in items if needle in c.xai_summary.lower()]
        if min_event_count is not None:
            items = [c for c in items if len(c.normalized_event_ids) >= min_event_count]
        if max_event_count is not None:
            items = [c for c in items if len(c.normalized_event_ids) <= max_event_count]
        if audit_contains is not None and audit_contains.strip() != "":
            needle = audit_contains.strip().lower()
            items = [c for c in items if any(needle in line.lower() for line in c.audit_log)]
        if event_source is not None and event_source.strip() != "":
            es = _coerce_event_source(event_source.strip())
            items = [c for c in items if c.last_event_source == es.value]
        if sort.strip().lower() not in _CASE_LIST_SORT:
            raise HTTPException(
                status_code=400,
                detail=f"invalid sort; use one of: {', '.join(sorted(_CASE_LIST_SORT))}",
            )
        items = _sort_cases_copy(items, sort)
        total_after_sort = len(items)
        response.headers["X-Total-Count"] = str(total_after_sort)
        link = _offset_limit_link_header(
            request, offset=offset, limit=limit, total_before_slice=total_after_sort
        )
        if link:
            response.headers["Link"] = link
        items = items[offset:]
        if limit is not None:
            items = items[:limit]
        return [
            CaseSummary(
                case_id=c.case_id,
                status=c.status.value,
                title=c.title,
                risk_class=c.risk_class,
                risk_score=c.risk_score,
                fingerprint=c.burst_fingerprint,
                primary_asset_id=c.primary_asset_id,
                trigger_operation=c.trigger_operation,
                last_event_source=c.last_event_source,
                invariant_hits_count=len(c.invariant_hits),
                event_count=len(c.normalized_event_ids),
                created_at=c.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
                dq_score=c.dq_score,
                dq_partial=c.dq_partial,
            )
            for c in items
        ]

    @app.get("/cases/stats", response_model=CasesStatsResponse, tags=["Cases"])
    def cases_stats():
        all_c = list(repo.list_all())
        n = len(all_c)
        by_status = Counter(c.status.value for c in all_c)
        by_rc = Counter(c.risk_class.upper() for c in all_c)
        open_n = sum(1 for c in all_c if c.status in (CaseStatus.NEW, CaseStatus.TRIAGE))
        avg_r = sum(c.risk_score for c in all_c) / n if n else 0.0
        avg_dq = sum(c.dq_score for c in all_c) / n if n else 0.0
        dq_part = sum(1 for c in all_c if c.dq_partial)
        ev_total = sum(len(c.normalized_event_ids) for c in all_c)
        inv_seen: set[str] = set()
        inv_occ = 0
        for c in all_c:
            inv_seen.update(c.invariant_hits)
            inv_occ += len(c.invariant_hits)
        by_es = Counter((c.last_event_source or "unknown") for c in all_c)
        return CasesStatsResponse(
            total=n,
            open=open_n,
            by_status=dict(sorted(by_status.items())),
            by_risk_class=dict(sorted(by_rc.items())),
            avg_risk_score=avg_r,
            avg_dq_score=avg_dq,
            dq_partial_count=dq_part,
            normalized_events_total=ev_total,
            distinct_invariant_hits=len(inv_seen),
            invariant_hits_occurrences_total=inv_occ,
            by_last_event_source=dict(sorted(by_es.items())),
        )

    @app.get(
        "/cases/export/full.json",
        response_model=CasesFullExportResponse,
        tags=["Export"],
        responses={
            200: {
                "description": "Пакет карточек (срез по offset/limit после сортировки)",
                "headers": {
                    "X-Total-Count": {
                        "description": (
                            "Число кейсов в репозитории, подпадающих под выгрузку "
                            "(до среза по offset/limit; совпадает с total_in_repo в теле)"
                        ),
                        "schema": {"type": "string", "example": "42"},
                    },
                    "Link": {
                        "description": (
                            "Пагинация (RFC 8288): при переданном query-параметре `limit` — "
                            "`rel=\"next\"` и/или `rel=\"prev\"` с тем же путём и параметрами выгрузки"
                        ),
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    )
    def export_all_cases_full_json(
        request: Request,
        response: Response,
        offset: int = Query(default=0, ge=0, description="Смещение в отсортированном списке (created_at desc)"),
        limit: int | None = Query(
            default=None,
            ge=1,
            le=_EXPORT_FULL_MAX,
            description=f"Макс. число кейсов в ответе (по умолчанию — все от offset; не больше {_EXPORT_FULL_MAX})",
        ),
    ):
        """Полная выгрузка кейсов в формате карточки (как `GET /cases/{id}`), сортировка по `created_at` убыв."""
        all_sorted = _sort_cases_copy(list(repo.list_all()), "created_at_desc")
        total = len(all_sorted)
        response.headers["X-Total-Count"] = str(total)
        exp_link = _offset_limit_link_header(
            request, offset=offset, limit=limit, total_before_slice=total
        )
        if exp_link:
            response.headers["Link"] = exp_link
        slice_start = min(offset, total)
        rest = all_sorted[slice_start:]
        if limit is None:
            batch = rest
        else:
            batch = rest[:limit]
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return CasesFullExportResponse(
            exported_at=now,
            count=len(batch),
            total_in_repo=total,
            offset=offset,
            limit=limit,
            cases=[_case_to_detail(c) for c in batch],
        )

    @app.post("/cases/import/full.json", response_model=CasesImportResponse, tags=["Export"])
    async def import_cases_full_json(request: Request):
        """Импорт карточек (как в **`GET /cases/export/full.json`**): восстановление/миграция."""
        raw = await request.body()
        try:
            body = CasesImportBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        import_secret = os.environ.get("TAKT_IMPORT_HMAC_SECRET", "").strip()
        if import_secret:
            got = request.headers.get("X-TAKT-Import-Signature", "").strip()
            if got.startswith("sha256="):
                got = got.split("=", 1)[1].strip()
            expected = hmac.new(import_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
            if not got or not hmac.compare_digest(got, expected):
                raise HTTPException(status_code=401, detail="invalid import signature")
        parsed: list[Case] = []
        for d in body.cases:
            try:
                parsed.append(_domain_case_from_detail(d))
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e

        imported = 0
        skipped = 0

        def _apply() -> None:
            nonlocal imported, skipped
            op_rec = getattr(repo, "record_operation_event", None)
            for case in parsed:
                if body.mode == "skip_existing" and repo.get(case.case_id) is not None:
                    skipped += 1
                    continue
                repo.save(case)
                imported += 1
                if callable(op_rec):
                    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    op_rec(
                        operation_type="import",
                        entity_id=case.case_id,
                        actor="import_api",
                        payload_json=json.dumps(
                            {
                                "case_id": case.case_id,
                                "mode": body.mode,
                                "event_ids_count": len(case.normalized_event_ids),
                                "risk_class": case.risk_class,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        created_at=now_iso,
                    )

        tx_cm = getattr(repo, "transaction", None)
        if callable(tx_cm):
            with tx_cm():
                _apply()
        else:
            _apply()
        return CasesImportResponse(imported=imported, skipped=skipped, mode=body.mode)

    @app.get("/cases/{case_id}", response_model=CaseDetail, tags=["Cases"])
    def get_case(case_id: str):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return _case_to_detail(c)

    @app.get("/compliance/data-quality-report", tags=["Analytics"])
    def compliance_data_quality_report():
        report = compliance_report_uc.execute()
        engagement_summary = _audit_engagement_summary()
        return {
            "generated_at": report.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "total_cases": report.total_cases,
            "open_cases": report.open_cases,
            "by_status": report.by_status,
            "by_risk_class": report.by_risk_class,
            "avg_dq_score": report.avg_dq_score,
            "dq_partial_count": report.dq_partial_count,
            "dq_reasons": report.dq_reasons,
            "cases_without_manual_permit": report.cases_without_manual_permit,
            "cases_with_forensic_bundle_audit": report.cases_with_forensic_bundle_audit,
            "high_risk_without_decision": report.high_risk_without_decision,
            "false_positive_count": report.false_positive_count,
            "expected_behavior_count": report.expected_behavior_count,
            "invariant_hits": report.invariant_hits,
            "remediation_attempts_by_kind": report.remediation_attempts_by_kind,
            "remediation_attempts_by_status": report.remediation_attempts_by_status,
            "readiness_flags": [
                {
                    "code": f.code,
                    "ok": f.ok,
                    "value": f.value,
                    "threshold": f.threshold,
                }
                for f in report.readiness_flags
            ],
            "audit_engagements": engagement_summary,
        }

    @app.get("/compliance/forensic-readiness", tags=["Analytics"])
    def compliance_forensic_readiness(only_not_ready: bool = False, missing_code: str = ""):
        try:
            report = forensic_readiness_uc.execute(only_not_ready=only_not_ready, missing_code=missing_code)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {
            "generated_at": report.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "total_cases": report.total_cases,
            "ready_cases": report.ready_cases,
            "not_ready_cases": report.not_ready_cases,
            "missing_by_code": report.missing_by_code,
            "allowed_missing_codes": sorted(FORENSIC_READINESS_MISSING_CODES),
            "cases": [
                {
                    "case_id": c.case_id,
                    "status": c.status,
                    "risk_class": c.risk_class,
                    "risk_score": c.risk_score,
                    "ready": c.ready,
                    "missing": list(c.missing),
                }
                for c in report.cases
            ],
        }

    @app.get("/compliance/remediation-kinds", tags=["Analytics"])
    def remediation_kinds_catalog():
        return {
            "kinds": [
                {"kind": kind, "description": description}
                for kind, description in sorted(REMEDIATION_KIND_DESCRIPTIONS.items())
            ]
        }

    @app.get("/compliance/remediations", tags=["Analytics"])
    def compliance_remediations(
        case_id: str = "",
        kind: str = "",
        status: str = "",
        limit: int = Query(default=100, ge=1, le=500),
    ):
        try:
            attempts = remediation_list_uc.execute(
                ListRemediationAttemptsQuery(case_id=case_id, kind=kind, status=status, limit=limit)
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {"attempts": [_remediation_attempt_to_detail(a).model_dump() for a in attempts]}

    @app.post("/audit-engagements", response_model=AuditEngagementOut, tags=["Analytics"])
    def create_audit_engagement(body: AuditEngagementCreateBody):
        item = audit_engagement_uc.create(
            CreateAuditEngagementCommand(
                customer=body.customer,
                scope=body.scope,
                case_ids=list(body.case_ids),
                nda_signed=body.nda_signed,
                evidence_intake_checklist=list(body.evidence_intake_checklist),
            )
        )
        return _audit_engagement_out(item)

    @app.get("/audit-engagements", response_model=list[AuditEngagementOut], tags=["Analytics"])
    def list_audit_engagements():
        return [_audit_engagement_out(item) for item in audit_engagement_uc.list_all()]

    @app.get("/audit-engagements/{engagement_id}", response_model=AuditEngagementOut, tags=["Analytics"])
    def get_audit_engagement(engagement_id: str):
        item = audit_engagement_uc.get(engagement_id)
        if item is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/advance-stage", response_model=AuditEngagementOut, tags=["Analytics"])
    def advance_audit_engagement_stage(engagement_id: str, body: AuditStageAdvanceBody):
        try:
            item = audit_engagement_uc.advance_stage(engagement_id, note=body.note)
        except ValueError as e:
            message = str(e)
            code = 404 if "unknown engagement" in message else 400
            raise HTTPException(status_code=code, detail=message) from e
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/findings", response_model=AuditEngagementOut, tags=["Analytics"])
    def add_audit_engagement_finding(engagement_id: str, body: AuditFindingBody):
        try:
            item = audit_engagement_uc.add_finding(engagement_id, body.finding)
        except ValueError as e:
            message = str(e)
            code = 404 if "unknown engagement" in message else 400
            raise HTTPException(status_code=code, detail=message) from e
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/final-report", response_model=AuditEngagementOut, tags=["Analytics"])
    def finalize_audit_engagement_report(engagement_id: str, body: AuditFinalizeReportBody):
        try:
            item = audit_engagement_uc.finalize_report(
                engagement_id,
                FinalizeAuditReportCommand(
                    title=body.title,
                    uri=body.uri,
                    summary=body.summary,
                ),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return _audit_engagement_out(item)

    @app.get("/audit-engagements/{engagement_id}/export/report.json", response_model=AuditEngagementReportOut, tags=["Analytics"])
    def export_audit_engagement_report(engagement_id: str):
        item = audit_engagement_uc.get(engagement_id)
        if item is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        out = _audit_engagement_out(item)
        stages_total = len(out.stages)
        stages_completed = sum(1 for s in out.stages if s.status == "completed")
        return AuditEngagementReportOut(
            format="TAKT Audit Engagement Report",
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            engagement=out,
            findings_count=len(out.findings),
            stages_completed=stages_completed,
            stages_total=stages_total,
            nda_signed=out.nda_signed,
            has_final_report=out.final_report is not None,
        )

    @app.get("/cases/{case_id}/compliance/evidence-checklist", tags=["Analytics"])
    def case_evidence_checklist(case_id: str):
        try:
            checklist = evidence_checklist_uc.execute(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e
        return {
            "generated_at": checklist.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "case_id": checklist.case_id,
            "ready": checklist.ready,
            "remediation_summary": checklist.remediation_summary,
            "items": [
                {
                    "code": item.code,
                    "ok": item.ok,
                    "detail": item.detail,
                    "remediation_kind": item.remediation_kind,
                    "remediation_action": item.remediation_action,
                    "remediation_attempted": item.remediation_attempted,
                    "latest_remediation_status": item.latest_remediation_status,
                }
                for item in checklist.items
            ],
        }

    @app.post("/cases/{case_id}/compliance/remediations", tags=["Analytics"])
    def post_remediation_attempt(case_id: str, body: RemediationAttemptBody, request: Request):
        try:
            attempt = remediation_uc.execute(
                RecordRemediationAttemptCommand(
                    case_id=case_id,
                    kind=body.kind,
                    status=body.status,
                    action=body.action,
                    result=body.result,
                    note=body.note,
                    actor=security_actor_from_request(request),
                    request_id=str(getattr(request.state, "request_id", "")),
                )
            )
        except ValueError as e:
            detail = str(e)
            code = 400 if "invalid remediation" in detail else 404
            raise HTTPException(status_code=code, detail=detail) from e
        return {"attempt": _remediation_attempt_to_detail(attempt).model_dump()}

    def _recheck_entry_from_audit_line(line: str) -> dict[str, Any] | None:
        parts = [chunk.strip() for chunk in line.split(" | ")]
        if len(parts) < 2:
            return None
        msg = parts[1]
        pref = "remediation readiness recheck "
        if not msg.startswith(pref):
            return None
        fields: dict[str, str] = {}
        for token in msg[len(pref) :].split():
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            fields[k] = v
        ready_raw = fields.get("ready", "").lower()
        if ready_raw not in {"true", "false"}:
            return None
        missing_raw = fields.get("missing_codes", "-")
        actor = ""
        for p in parts[2:]:
            if p.startswith("actor="):
                actor = p.split("=", 1)[1]
                break
        return {
            "ts": parts[0],
            "ready": ready_raw == "true",
            "missing_codes": [] if missing_raw in {"", "-"} else [x for x in missing_raw.split(",") if x],
            "attempt_id": "" if fields.get("attempt_id", "-") == "-" else fields.get("attempt_id", ""),
            "actor": actor,
        }

    @app.post("/cases/{case_id}/compliance/remediations/recheck-readiness", tags=["Analytics"])
    def post_remediation_readiness_recheck(case_id: str, body: dict[str, Any], request: Request):
        case = repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        checklist = evidence_checklist_uc.execute(case_id)
        ready = checklist.ready
        missing_codes = [item.code for item in checklist.items if not item.ok]
        attempt_id = str(body.get("attempt_id", "")).strip()
        note = str(body.get("note", "")).strip()
        updated_attempt: RemediationAttempt | None = None
        if attempt_id:
            for item in case.remediation_attempts:
                if item.attempt_id == attempt_id:
                    updated_attempt = item
                    break
            if updated_attempt is None:
                raise HTTPException(status_code=404, detail="remediation attempt not found")
            updated_attempt.readiness_after = ready
            if updated_attempt.status in {"recorded", "started"}:
                updated_attempt.status = "completed" if ready else "failed"
            if not updated_attempt.result:
                updated_attempt.result = "readiness_recheck:ready" if ready else "readiness_recheck:not_ready"
            if note:
                updated_attempt.note = f"{updated_attempt.note} | recheck_note={note}" if updated_attempt.note else note
        case.append_audit(
            (
                "remediation readiness recheck "
                f"ready={ready} missing_codes={','.join(missing_codes) or '-'} "
                f"attempt_id={attempt_id or '-'}"
            ),
            datetime.now(timezone.utc),
            actor=security_actor_from_request(request),
        )
        repo.save(case)
        return {
            "case_id": case_id,
            "ready": ready,
            "missing_codes": missing_codes,
            "attempt": _remediation_attempt_to_detail(updated_attempt).model_dump() if updated_attempt else None,
        }

    @app.get("/cases/{case_id}/compliance/remediations/recheck-readiness/history", tags=["Analytics"])
    def get_remediation_readiness_recheck_history(
        request: Request,
        response: Response,
        case_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        attempt_id: str = "",
        ready: bool | None = None,
    ):
        case = repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        out: list[dict[str, Any]] = []
        total_matched = 0
        attempt_id_filter = attempt_id.strip()
        for line in reversed(case.audit_log):
            entry = _recheck_entry_from_audit_line(line)
            if entry is None:
                continue
            if attempt_id_filter and entry["attempt_id"] != attempt_id_filter:
                continue
            if ready is not None and bool(entry["ready"]) != ready:
                continue
            total_matched += 1
            if total_matched <= offset:
                continue
            if len(out) < limit:
                out.append(entry)
        response.headers["X-Total-Count"] = str(total_matched)
        link = _offset_limit_link_header(request, offset=offset, limit=limit, total_before_slice=total_matched)
        if link:
            response.headers["Link"] = link
        return {"case_id": case_id, "total_matched": total_matched, "entries": out}

    @app.post("/cases/{case_id}/manual-permits", tags=["Cases"])
    def post_manual_permit(case_id: str, body: ManualPermitBody, request: Request):
        try:
            permit = manual_permit_uc.execute(
                AttachManualPermitCommand(
                    case_id=case_id,
                    work_order_number=body.work_order_number,
                    actor=security_actor_from_request(request),
                    asset_id=body.asset_id,
                    operation=body.operation,
                    note=body.note,
                )
            )
        except ValueError as e:
            detail = str(e)
            code = 400 if "work_order_number" in detail else 404
            raise HTTPException(status_code=code, detail=detail) from e
        return {"permit": _manual_permit_to_detail(permit).model_dump()}

    @app.post("/cases/{case_id}/decision", response_model=CaseDecisionResponse, tags=["Cases"])
    def post_decision(case_id: str, body: DecisionBody, request: Request):
        try:
            decision_uc.execute(
                case_id,
                body.status,
                datetime.now(timezone.utc),
                actor=security_actor_from_request(request),
                reason=body.reason,
                request_id=str(getattr(request.state, "request_id", "")),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return CaseDecisionResponse(case_id=case_id, status=body.status.value)

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

    @app.get("/cases/{case_id}/audit-ledger/verify", tags=["Analytics"])
    def verify_case_audit_ledger(case_id: str):
        verifier = getattr(repo, "verify_audit_ledger", None)
        if not callable(verifier):
            raise HTTPException(status_code=501, detail="audit ledger verification is unavailable for this storage")
        case = repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        return verifier(case_id)

    @app.get("/audit-ledger/operations/verify", tags=["Analytics"])
    def verify_operation_audit_ledger(stream_key: str = ""):
        verifier = getattr(repo, "verify_operation_ledger", None)
        if not callable(verifier):
            raise HTTPException(status_code=501, detail="operation audit ledger verification is unavailable for this storage")
        return verifier(stream_key.strip())

    @app.get("/cases/{case_id}/export.pdf", tags=["Export"])
    def export_case_pdf(case_id: str):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        try:
            pdf_bytes = render_case_pdf(
                c,
                generated_at=datetime.now(timezone.utc),
                unicode_font_path=getattr(app.state, "pdf_unicode_font", None),
            )
        except RuntimeError as e:
            raise HTTPException(status_code=501, detail=str(e)) from e
        sha = __import__("hashlib").sha256(pdf_bytes).hexdigest()
        c.pdf_last_sha256 = sha
        c.pdf_last_generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        c.append_audit(f"pdf exported sha256={sha}", datetime.now(timezone.utc))
        repo.save(c)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="takt-case-{case_id}.pdf"',
                "X-TAKT-PDF-SHA256": sha,
            },
        )

    @app.get("/cases/{case_id}/export/siem.json", response_model=SiemCaseExportPayload, tags=["Export"])
    def export_case_siem_json(case_id: str):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case_to_siem_payload(c)

    @app.get("/cases/{case_id}/export/gossopka.json", tags=["Export"])
    def export_case_gossopka_json(case_id: str):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case_to_gossopka_card(c, generated_at=datetime.now(timezone.utc))

    @app.get("/cases/{case_id}/export/gossopka-transport.json", tags=["Export"])
    def export_case_gossopka_transport(case_id: str, exchange_mode: str = "pull_http_json"):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        try:
            return case_to_gossopka_transport_payload(
                c,
                generated_at=datetime.now(timezone.utc),
                exchange_mode=exchange_mode.strip() or "pull_http_json",
            )
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/cases/{case_id}/export/gossopka-official.json", tags=["Export"])
    def export_case_gossopka_official_json(case_id: str):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case_to_gossopka_official_card(c, generated_at=datetime.now(timezone.utc))

    @app.get("/cases/{case_id}/export/gossopka-official-transport.json", tags=["Export"])
    def export_case_gossopka_official_transport(case_id: str, exchange_mode: str = "pull_http_json"):
        c = repo.get(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        try:
            return case_to_gossopka_official_transport_payload(
                c,
                generated_at=datetime.now(timezone.utc),
                exchange_mode=exchange_mode.strip() or "pull_http_json",
            )
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    def _forensic_manifest_response(case_id: str, engagement_id: str = "") -> dict[str, Any]:
        try:
            bundle = forensic_uc.execute(
                case_id,
                record_audit=False,
                supplemental_files=_audit_engagement_bundle_files(case_id, engagement_id),
            ).metadata
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=f"forensic_signing_unavailable: {e}") from e
        return {
            "case_id": bundle.case_id,
            "generated_at": bundle.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "root_hash_sha256": bundle.root_hash_sha256,
            "signature_status": bundle.signature_status,
            "signature_ref": bundle.signature_ref,
            "process_suitability": bundle.process_suitability,
            "items": [
                {
                    "path": item.path,
                    "media_type": item.media_type,
                    "sha256": item.sha256,
                    "chain_sha256": item.chain_sha256,
                    "size_bytes": item.size_bytes,
                }
                for item in bundle.items
            ],
        }

    @app.get(
        "/cases/{case_id}/forensic-bundle/manifest",
        tags=["Export"],
        responses={
            404: {"description": "Case not found"},
            503: {"description": "Forensic signing unavailable in strict mode"},
        },
    )
    def export_case_forensic_manifest(case_id: str, engagement_id: str = Query(default="")):
        return _forensic_manifest_response(case_id, engagement_id=engagement_id)

    @app.get(
        "/cases/{case_id}/forensic-bundle.zip",
        tags=["Export"],
        responses={
            404: {"description": "Case not found"},
            503: {"description": "Forensic signing unavailable in strict mode"},
        },
    )
    def export_case_forensic_bundle(case_id: str, request: Request, engagement_id: str = Query(default="")):
        try:
            out = forensic_uc.execute(
                case_id,
                actor=security_actor_from_request(request),
                record_audit=True,
                supplemental_files=_audit_engagement_bundle_files(case_id, engagement_id),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=f"forensic_signing_unavailable: {e}") from e
        root_hash = out.metadata.root_hash_sha256
        signature_status = out.metadata.signature_status
        return Response(
            content=out.archive_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="takt-forensic-{case_id}.zip"',
                "X-TAKT-Forensic-Root-Hash": root_hash,
                "X-TAKT-Forensic-Signature-Status": signature_status,
            },
        )

    @app.post("/forensic-bundle/verify", tags=["Export"])
    async def verify_forensic_bundle_endpoint(request: Request):
        raw = await request.body()
        if not raw:
            raise HTTPException(status_code=400, detail="empty archive body")
        result = forensic_verify_uc.execute(raw)
        return {
            "ok": result.ok,
            "case_id": result.case_id,
            "root_hash_sha256": result.root_hash_sha256,
            "signature_status": result.signature_status,
            "checked_items": result.checked_items,
            "issues": [{"code": issue.code, "detail": issue.detail} for issue in result.issues],
        }

    @app.post("/integrations/siem/forward", response_model=SiemForwardResponse, tags=["Integrations"])
    def forward_to_siem(body: SiemForwardBody):
        c = repo.get(body.case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        try:
            require_allowed_siem_url(body.target_url, app.state.siem_webhook_prefixes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        try:
            code = post_case_to_webhook_sync(
                c,
                body.target_url.strip(),
                retries=int(getattr(app.state, "webhook_retries", 3)),
                backoff_sec=float(getattr(app.state, "webhook_backoff_sec", 0.35)),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"webhook failed: {e!s}") from e
        return SiemForwardResponse(http_status=code)

    @app.post("/integrations/siem/forward/async", response_model=SiemForwardAsyncResponse, tags=["Integrations"])
    async def forward_to_siem_async(body: SiemForwardBody):
        c = repo.get(body.case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        try:
            require_allowed_siem_url(body.target_url, app.state.siem_webhook_prefixes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        try:
            code = await post_case_to_webhook(
                c,
                body.target_url.strip(),
                retries=int(getattr(app.state, "webhook_retries", 3)),
                backoff_sec=float(getattr(app.state, "webhook_backoff_sec", 0.35)),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"webhook failed: {e!s}") from e
        return SiemForwardAsyncResponse(http_status=code, async_handled=True)

    @app.post("/backtest/fixture", response_model=BacktestFixtureResponse, tags=["Analytics"])
    def backtest_fixture():
        fx = _ROOT / "tests" / "fixtures" / "plc_polling_demo.csv"
        if not fx.is_file():
            raise HTTPException(status_code=500, detail="fixture missing")
        events = load_normalized_from_csv(fx, source=EventSource.PLC_POLLING)
        report = backtest_uc.execute(
            events,
            graph_edges=list(demo_edges),
            polling_intervals_us=[1000.0, 1000.0, 4670.0, 21_800.0],
            trust_by_source=app.state.trust_by_source,
        )
        return BacktestFixtureResponse(
            events_processed=report.events_processed,
            cases_created=report.cases_created,
            merges=report.merges,
            risk_class_histogram=report.risk_class_histogram,
        )

    _register_prometheus_if_enabled(app)
    _attach_custom_openapi(app)
    br = build_revision_from_env()
    py_tag = _python_runtime_tag()
    pid, host, pl, py_exe, cwd = os.getpid(), socket.gethostname(), sys.platform, sys.executable, os.getcwd()
    if br is not None:
        _LOGGER.info(
            "TAKT API ready storage=%s config=%s version=%s python=%s pid=%s hostname=%s platform=%s python_executable=%s cwd=%s build_revision=%s",
            app.state.case_storage_backend,
            _resolve_config_path(),
            _PACKAGE_VERSION,
            py_tag,
            pid,
            host,
            pl,
            py_exe,
            cwd,
            br,
        )
    else:
        _LOGGER.info(
            "TAKT API ready storage=%s config=%s version=%s python=%s pid=%s hostname=%s platform=%s python_executable=%s cwd=%s",
            app.state.case_storage_backend,
            _resolve_config_path(),
            _PACKAGE_VERSION,
            py_tag,
            pid,
            host,
            pl,
            py_exe,
            cwd,
        )
    return app


def _case_to_detail(c: Case) -> CaseDetail:
    hits = list(c.invariant_hits)
    obs_out = [
        ObservationDetail(source=o.source, ingest_trust=o.ingest_trust, event_ids=list(o.event_ids))
        for o in c.observations
    ]
    rec_out = [
        InvariantHitRecordDetail(
            invariant_id=r.invariant_id,
            event_ref=r.event_ref,
            ts=r.ts.astimezone(timezone.utc).isoformat(timespec="seconds"),
            score_contribution=r.score_contribution,
            dq_score=r.dq_score,
            dq_partial=r.dq_partial,
            dq_reasons=list(r.dq_reasons),
        )
        for r in c.invariant_hit_records
    ]
    return CaseDetail(
        case_id=c.case_id,
        status=c.status.value,
        title=c.title,
        risk_class=c.risk_class,
        risk_score=c.risk_score,
        event_ids=list(c.normalized_event_ids),
        invariant_hits=hits,
        invariant_details=_invariant_details_for_hits(hits),
        observations=obs_out,
        manual_permits=[_manual_permit_to_detail(p) for p in c.manual_permits],
        decision_records=[_decision_record_to_detail(r) for r in c.decision_records],
        remediation_attempts=[_remediation_attempt_to_detail(a) for a in c.remediation_attempts],
        invariant_hit_records=rec_out,
        xai_summary=c.xai_summary,
        audit_log=list(c.audit_log),
        fingerprint=c.burst_fingerprint,
        primary_asset_id=c.primary_asset_id,
        trigger_operation=c.trigger_operation,
        last_event_source=c.last_event_source,
        created_at=c.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        dq_score=c.dq_score,
        dq_partial=c.dq_partial,
        dq_reasons=list(c.dq_reasons),
        pdf_last_sha256=c.pdf_last_sha256,
        pdf_last_generated_at=c.pdf_last_generated_at,
    )


app = create_app()
