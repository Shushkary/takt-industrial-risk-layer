from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.gzip import GZipMiddleware

from takt.application.system_defaults import default_clock, default_id_provider
from takt.application.use_cases.audit_engagement import ManageAuditEngagementUseCase
from takt.application.use_cases.audit_ledger_facade import AuditLedgerFacade
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.build_forensic_bundle import BuildForensicBundleUseCase
from takt.application.use_cases.case_actions_facade import CaseActionsFacade
from takt.application.use_cases.case_decision import SubmitCaseDecisionUseCase
from takt.application.use_cases.case_findings import CaseFindingsUseCase
from takt.application.use_cases.cases_query_service import CASE_LIST_SORT_KEYS, CasesQueryService
from takt.application.use_cases.compliance_facade import ComplianceFacade
from takt.application.use_cases.compliance_report import (
    BuildCaseEvidenceChecklistUseCase,
    BuildComplianceDataQualityReportUseCase,
    BuildForensicReadinessReportUseCase,
)
from takt.application.use_cases.enrichment import LocalDecoderService
from takt.application.use_cases.export_facade import ExportFacade
from takt.application.use_cases.forensic_export_facade import ForensicExportFacade
from takt.application.use_cases.formal_verdict_confirmation import ConfirmFormalVerdictUseCase
from takt.application.use_cases.ingest_facade import IngestAssessmentFacade
from takt.application.use_cases.manual_correlation import ManualCorrelationUseCase
from takt.application.use_cases.manual_permit import AttachManualPermitUseCase
from takt.application.use_cases.remediation import (
    ListRemediationAttemptsUseCase,
    RecordRemediationAttemptUseCase,
)
from takt.application.use_cases.verify_forensic_bundle import VerifyForensicBundleUseCase
from takt.domain.entities.case import Case
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.ports.audit_engagement_repository import AuditEngagementRepositoryPort
from takt.infrastructure.config.pipeline import build_assessment_pipeline
from takt.infrastructure.config.settings_helpers import (
    apply_storage_env_overrides,
    case_repository_from_weights,
    expected_behavior_from_weights,
    siem_webhook_retries,
)
from takt.infrastructure.config.weights_loader import load_risk_weights

# Ниже — импорты ради позднего связывания, а не для прямого вызова. `_main_module_callable`
# берёт эти имена с модуля в момент вызова (`getattr(sys.modules[__name__], name)`), а модуль
# подменяет собой `api.main` — благодаря чему тесты и подменяют `api.main.render_case_pdf`
# и `api.main.post_case_to_webhook*`. Уберёшь импорт — подмена перестанет находить атрибут,
# а рабочий путь упадёт с AttributeError. Ruff видит их неиспользуемыми (F401) справедливо:
# по тексту модуля обращений нет, связь возникает только во время выполнения.
from takt.infrastructure.export.case_pdf import (  # noqa: F401
    render_case_pdf,
    render_decision_brief_pdf,
)
from takt.infrastructure.export.forensic_bundle import ZipForensicBundleBuilder, ZipForensicBundleVerifier
from takt.infrastructure.export.gossopka import (
    case_to_gossopka_card,
    case_to_gossopka_official_card,
    case_to_gossopka_official_transport_payload,
    case_to_gossopka_transport_payload,
)
from takt.infrastructure.export.siem_webhook import (  # noqa: F401
    case_to_siem_payload,
    post_case_to_webhook,
    post_case_to_webhook_sync,
)
from takt.infrastructure.http.cache_control_middleware import (
    CasesPrivateNoStoreMiddleware,
    CatalogCacheControlMiddleware,
)
from takt.infrastructure.http.cors_from_env import add_cors_middleware_if_configured
from takt.infrastructure.http.prometheus_metrics import record_business_assessment
from takt.infrastructure.http.rate_limit_middleware import (
    InMemoryRateLimitMiddleware,
)
from takt.infrastructure.http.request_body_limit_middleware import (
    RequestBodySizeLimitMiddleware,
)
from takt.infrastructure.http.request_id_middleware import RequestIdMiddleware
from takt.infrastructure.http.security_headers import (
    SecurityHeadersMiddleware,
)
from takt.infrastructure.http.security_log_middleware import SecurityLogMiddleware
from takt.infrastructure.http.timing_middleware import ProcessTimeMiddleware
from takt.infrastructure.importers.csv_events import raw_row_to_normalized
from takt.infrastructure.security.api_key_middleware import OptionalApiKeyMiddleware
from takt.infrastructure.security.auth_env import (
    validate_startup_auth_or_raise,
)
from takt.infrastructure.security.security_log_service import SecurityLogService, security_log_file_path_from_env
from takt.infrastructure.security.startup_audit import security_startup_config_snapshot
from takt.infrastructure.security.webhook_allowlist import (
    require_allowed_siem_url,
)
from takt.infrastructure.stores.memory import InMemoryAuditEngagementStore, InMemoryIdempotencyStore
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.infrastructure.stores.sqlite_store import (
    SqliteAuditEngagementStore,
    SqliteCaseStore,
)
from takt.interface_adapters.api.config_paths import (
    ensure_explicit_takt_config_under_project,
    invariant_catalog_dir_for_config,
    resolve_config_path,
)
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.event_sources import coerce_event_source
from takt.interface_adapters.api.lifecycle import build_app_lifespan
from takt.interface_adapters.api.mappers.cases import (
    case_to_detail,
    decision_brief_to_detail,
    domain_case_from_detail,
    formal_verdict_record_to_detail,
    invariant_details_for_hits,
    manual_permit_to_detail,
    parse_import_created_at,
)
from takt.interface_adapters.api.metrics import register_prometheus_if_enabled
from takt.interface_adapters.api.openapi import (
    attach_custom_openapi,
    is_openapi_public_path,
    openapi_api_key_configured,
    patch_openapi_servers,
    patch_openapi_with_takt_api_key,
)
from takt.interface_adapters.api.openapi import (
    openapi_server_entries_from_env as _openapi_server_entries_from_env,
)
from takt.interface_adapters.api.pagination import offset_limit_link_header
from takt.interface_adapters.api.routers.analytics import register_analytics_routes
from takt.interface_adapters.api.routers.assemble import register_assemble_routes
from takt.interface_adapters.api.routers.attack_chain import register_attack_chain_routes
from takt.interface_adapters.api.routers.audit_engagements import register_audit_engagement_routes
from takt.interface_adapters.api.routers.audit_ledger import register_audit_ledger_routes
from takt.interface_adapters.api.routers.case_actions import register_case_action_routes
from takt.interface_adapters.api.routers.cases import register_case_routes
from takt.interface_adapters.api.routers.catalog import register_catalog_routes
from takt.interface_adapters.api.routers.compliance import register_compliance_routes
from takt.interface_adapters.api.routers.correlation import register_correlation_routes
from takt.interface_adapters.api.routers.enrichment import register_enrichment_routes
from takt.interface_adapters.api.routers.entities import register_entity_routes
from takt.interface_adapters.api.routers.events import register_event_routes
from takt.interface_adapters.api.routers.export import register_export_routes
from takt.interface_adapters.api.routers.findings import register_finding_routes
from takt.interface_adapters.api.routers.forensic import register_forensic_routes
from takt.interface_adapters.api.routers.ingest import register_ingest_routes
from takt.interface_adapters.api.routers.integrations import register_integration_routes
from takt.interface_adapters.api.routers.simulation import register_simulation_routes
from takt.interface_adapters.api.routers.system import register_system_routes
from takt.interface_adapters.api.routers.workspace import register_workspace_routes
from takt.interface_adapters.api.schemas.cases import (
    AssessResponse,
)
from takt.interface_adapters.api.schemas.errors import MIDDLEWARE_ERROR_OPENAPI
from takt.interface_adapters.api.schemas.ingest import (
    AssessRequest,
    EventBatchBody,
    EventIngestBody,
    IpfixIngestBody,
    NetflowIngestBody,
    SnmpTrapIngestBody,
    SyslogRfc5424IngestBody,
)

_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_CFG = _ROOT / "config" / "risk_weights.yaml"


def _read_installed_package_version(default: str = "0.6.23") -> str:
    """Р’РµСЂСЃРёСЏ РґРёСЃС‚СЂРёР±СѓС‚РёРІР°; РїСЂРё РѕС€РёР±РєРµ **`importlib.metadata`** (editable/Р±РёС‚С‹Р№ venv) вЂ” **`default`**."""

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
_parse_import_created_at = parse_import_created_at
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
    """РќРµРѕР±СЏР·Р°С‚РµР»СЊРЅР°СЏ РјРµС‚РєР° СЃР±РѕСЂРєРё РёР· **`TAKT_BUILD_REVISION`** РґР»СЏ **`GET /health`**: **`build_revision`** (РґРѕ **256** СЃРёРјРІРѕР»РѕРІ); РїСѓСЃС‚Р°СЏ вЂ” **`None`**."""
    raw = os.environ.get("TAKT_BUILD_REVISION", "").strip()
    if not raw:
        return None
    return raw[:_TAKT_BUILD_REVISION_MAX_LEN]


def _python_runtime_tag() -> str:
    """**`python_implementation`/`python_version`** РІ РѕРґРЅРѕРј С‚РµРіРµ (СЃС‚СЂРѕРєРё **`TAKT API ready`** / **`shutdown`**)."""
    return f"{sys.implementation.name}/{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def apply_takt_api_log_level_from_env() -> None:
    """РЈСЂРѕРІРµРЅСЊ Р»РѕРіРіРµСЂР° **`takt.api`** РёР· **`TAKT_LOG_LEVEL`** (`DEBUG`, `INFO`, `WARNING`/`WARN`, `ERROR`, `CRITICAL`); РЅРµРІРµСЂРЅРѕРµ Р·РЅР°С‡РµРЅРёРµ РёРіРЅРѕСЂРёСЂСѓРµС‚СЃСЏ."""
    raw = os.environ.get("TAKT_LOG_LEVEL", "").strip().upper()
    if not raw:
        return
    level = _TAKT_LOG_LEVEL_MAP.get(raw)
    if level is None:
        return
    _LOGGER.setLevel(level)


def _main_module_callable(name: str):
    def _call(*args: Any, **kwargs: Any) -> Any:
        fn = getattr(sys.modules[__name__], name)
        return fn(*args, **kwargs)

    return _call


def _is_openapi_public_path(path: str) -> bool:
    return is_openapi_public_path(path)


def _openapi_api_key_configured() -> bool:
    return openapi_api_key_configured()


def openapi_server_entries_from_env() -> list[dict[str, str]]:
    """Р’Р°Р»РёРґРЅС‹Рµ СЌР»РµРјРµРЅС‚С‹ **`servers`** РёР· **TAKT_OPENAPI_SERVER_URL** (OpenAPI Рё **GET /health**)."""
    return _openapi_server_entries_from_env(logger=_LOGGER)


def _patch_openapi_servers(schema: dict[str, Any]) -> None:
    """Р•СЃР»Рё Р·Р°РґР°РЅ **TAKT_OPENAPI_SERVER_URL**, РґРѕР±Р°РІР»СЏРµС‚ **`servers`** РґР»СЏ Swagger Р·Р° РїСЂРѕРєСЃРё."""
    patch_openapi_servers(schema, logger=_LOGGER)


def _patch_openapi_with_takt_api_key(schema: dict[str, Any]) -> None:
    """**components.securitySchemes.TaktApiKey**; РїСЂРё **TAKT_API_KEY** вЂ” **security** РЅР° РЅРµРїСѓР±Р»РёС‡РЅС‹С… РѕРїРµСЂР°С†РёСЏС…."""
    patch_openapi_with_takt_api_key(schema)


def _attach_custom_openapi(app: FastAPI) -> None:
    attach_custom_openapi(app, logger=_LOGGER)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _register_prometheus_if_enabled(application: FastAPI) -> None:
    register_prometheus_if_enabled(
        application,
        package_version=_PACKAGE_VERSION,
        build_revision_from_env=build_revision_from_env,
        logger=_LOGGER,
    )


def _offset_limit_link_header(
    request: Request,
    *,
    offset: int,
    limit: int | None,
    total_before_slice: int,
) -> str | None:
    """РџСЂРё Р·Р°РґР°РЅРЅРѕРј `limit` вЂ” `Link` СЃ `rel=next` / `rel=prev` (РѕСЃС‚Р°Р»СЊРЅС‹Рµ query-РїР°СЂР°РјРµС‚СЂС‹ СЃРѕС…СЂР°РЅСЏСЋС‚СЃСЏ)."""
    return offset_limit_link_header(
        request,
        offset=offset,
        limit=limit,
        total_before_slice=total_before_slice,
    )


def _resolve_config_path() -> Path:
    """РџСѓС‚СЊ Рє YAML: `TAKT_CONFIG` РёР»Рё `config/risk_weights.yaml` РІ РєРѕСЂРЅРµ РїСЂРѕРµРєС‚Р°."""
    return resolve_config_path(default_cfg=_DEFAULT_CFG)


def _ensure_explicit_takt_config_under_project(cfg_path: Path) -> None:
    """РџСЂРё РЅРµРїСѓСЃС‚РѕРј `TAKT_CONFIG` С„Р°Р№Р» РєРѕРЅС„РёРіСѓСЂР°С†РёРё РґРѕР»Р¶РµРЅ Р»РµР¶Р°С‚СЊ РІРЅСѓС‚СЂРё РґРµСЂРµРІР° `_ROOT`."""
    ensure_explicit_takt_config_under_project(cfg_path=cfg_path, project_root=_ROOT)


def _invariant_catalog_dir_for_config(cfg_path: Path) -> Path:
    """РљР°С‚Р°Р»РѕРі `invariants`: СЂСЏРґРѕРј СЃ Р°РєС‚РёРІРЅС‹Рј YAML РёР»Рё РёР· РєРѕСЂРѕР±РєРё (`config/invariants` РїСЂРѕРµРєС‚Р°)."""
    return invariant_catalog_dir_for_config(cfg_path=cfg_path, default_cfg=_DEFAULT_CFG)


_app_lifespan = build_app_lifespan(
    package_version=_PACKAGE_VERSION,
    python_runtime_tag=_python_runtime_tag,
    validate_startup_auth_or_raise=validate_startup_auth_or_raise,
    security_startup_config_snapshot=security_startup_config_snapshot,
    logger=_LOGGER,
)


def _coerce_event_source(raw: str | None) -> EventSource:
    return coerce_event_source(raw)

_CASE_LIST_SORT = CASE_LIST_SORT_KEYS

def _as_utc_boundary(dt: datetime) -> datetime:
    return CasesQueryService.as_utc_boundary(dt)

def _sort_cases_copy(items: list[Case], sort_key: str) -> list[Case]:
    try:
        return CasesQueryService(repo=None).sort_cases(items, sort_key)
    except ValueError as e:
        raise RuntimeError(f"unsupported sort: {sort_key!r}") from e

def create_app() -> FastAPI:
    apply_takt_api_log_level_from_env()
    app = FastAPI(
        title="РўРђРљРў Industrial Risk Layer",
        version=_PACKAGE_VERSION,
        lifespan=_app_lifespan,
        responses=MIDDLEWARE_ERROR_OPENAPI,
    )
    app.state.prometheus_metrics_active = False
    app.state.booted_at_utc = datetime.now(UTC)
    app.state.boot_monotonic = time.monotonic()
    app.state.rate_limit_lock = threading.Lock()
    app.state.rate_limit_buckets = {}
    cfg_path = _resolve_config_path()
    _ensure_explicit_takt_config_under_project(cfg_path)
    weights = load_risk_weights(cfg_path)
    apply_storage_env_overrides(weights)
    raw_storage = weights.get("storage")
    stor: dict[str, Any] = raw_storage if isinstance(raw_storage, dict) else {}
    case_backend = str(stor.get("backend", "memory")).strip().lower()
    app.state.case_storage_backend = "sqlite" if case_backend == "sqlite" else "memory"
    app.state.expected_behavior_backend = app.state.case_storage_backend
    repo = case_repository_from_weights(weights, project_root=_ROOT)
    baseline = expected_behavior_from_weights(weights, project_root=_ROOT)
    pipeline = build_assessment_pipeline(
        weights,
        repo=repo,
        invariant_catalog_dir=_invariant_catalog_dir_for_config(cfg_path),
        expected_behavior=baseline,
    )
    inv_catalog = pipeline.invariant_catalog
    app.state.invariant_catalog = inv_catalog
    process = pipeline.process
    demo_edges = pipeline.graph_edges
    app.state.event_window = []
    recent_event_store = SqliteRecentEventStore(repo.database_path) if isinstance(repo, SqliteCaseStore) else None
    ingest_facade = IngestAssessmentFacade(
        process=process,
        repo=repo,
        event_window=app.state.event_window,
        event_window_max=_EVENT_WINDOW_MAX,
        graph_edges=demo_edges,
        polling_intervals_us=list(pipeline.polling_intervals_us),
        raw_row_to_normalized=raw_row_to_normalized,
        recent_event_store=recent_event_store,
    )
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
    manual_correlation_uc = ManualCorrelationUseCase(repo)
    case_findings_uc = CaseFindingsUseCase(repo)
    decoder_service = LocalDecoderService()
    formal_verdict_confirmation_uc = ConfirmFormalVerdictUseCase(repo, default_clock)
    remediation_uc = RecordRemediationAttemptUseCase(repo, default_clock, default_id_provider)
    remediation_list_uc = ListRemediationAttemptsUseCase(repo)
    cases_query_service = CasesQueryService(repo, default_clock)
    audit_engagement_store: AuditEngagementRepositoryPort
    if isinstance(repo, SqliteCaseStore):
        audit_engagement_store = SqliteAuditEngagementStore(repo.database_path)
    else:
        audit_engagement_store = InMemoryAuditEngagementStore()
    audit_engagement_uc = ManageAuditEngagementUseCase(
        audit_engagement_store,
        default_clock,
        default_id_provider,
    )
    audit_ledger_facade = AuditLedgerFacade(repo)
    backtest_uc = RunBacktestUseCase(process)
    app.state.ingest_recent_for_context = process.recent_context_event_count

    app.state.repo = repo
    app.state.ingest_facade = ingest_facade
    app.state.recent_event_store = recent_event_store
    app.state.idempotency_store = repo if isinstance(repo, SqliteCaseStore) else InMemoryIdempotencyStore()
    app.state.baseline = baseline
    app.state.audit_engagement_store = audit_engagement_store
    app.state.last_dq = None
    raw_webhook = weights.get("siem_webhook")
    sw: dict[str, Any] = raw_webhook if isinstance(raw_webhook, dict) else {}
    raw_prefixes = sw.get("allowed_url_prefixes")
    app.state.siem_webhook_prefixes = list(raw_prefixes) if isinstance(raw_prefixes, list) else []
    raw_export = weights.get("export")
    exp: dict[str, Any] = raw_export if isinstance(raw_export, dict) else {}
    wh_retries, wh_backoff = siem_webhook_retries(weights)
    app.state.webhook_retries = wh_retries
    app.state.webhook_backoff_sec = wh_backoff
    raw_font = exp.get("pdf_unicode_font")
    app.state.pdf_unicode_font = str(raw_font).strip() if raw_font else None
    app.state.risk_weights = weights
    app.state.trust_by_source = pipeline.trust_by_source
    app.state.risk_weights_version = str(weights.get("version") or "")

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

    def _assess_normalized_event(
        ev: NormalizedEvent,
        *,
        persist_case: bool = True,
        raw_evidence_ref: Any | None = None,
    ) -> AssessResponse:
        out = ingest_facade.assess_normalized_event(
            ev,
            persist_case=persist_case,
            raw_evidence_ref=raw_evidence_ref,
            trust_by_source=app.state.trust_by_source,
        )
        app.state.last_dq = out.assessment.data_quality
        dq = out.assessment.data_quality
        hits = list(out.case.invariant_hits)
        latency_seconds: float | None = None
        try:
            latency_seconds = max(
                0.0,
                (datetime.now(UTC) - ev.observed_at.astimezone(UTC)).total_seconds(),
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
            invariant_details=invariant_details_for_hits(hits),
            xai_what=out.assessment.xai.what,
            xai_why=out.assessment.xai.why_unusual,
            case_id=out.case.case_id,
            dq_score=dq.dq_score,
            dq_partial=dq.partial_observability,
            merged_into_existing=out.merged_into_existing,
        )

    def _assess_prepared_ingest_event(prepared: Any) -> AssessResponse:
        raw_ref = ingest_facade.build_raw_evidence_ref(
            raw_payload=prepared.raw_payload,
            source=prepared.source.value,
            event_id=prepared.event.event_id,
            captured_at=prepared.event.observed_at,
            note=prepared.note,
        )
        return _assess_normalized_event(prepared.event, raw_evidence_ref=raw_ref)

    def _assess_event_ingest_body(body: EventIngestBody, *, raw_payload: bytes) -> AssessResponse:
        try:
            src = _coerce_event_source(body.source)
            prepared = ingest_facade.prepared_event_ingest_body(
                body,
                raw_payload=raw_payload,
                source=src,
                note="events_ingest",
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_prepared_ingest_event(prepared)

    def _assess_event_batch_body(body: EventBatchBody) -> list[AssessResponse]:
        results: list[AssessResponse] = []
        for i, item in enumerate(body.events):
            try:
                src = _coerce_event_source(item.source)
                item_raw = json.dumps(item.model_dump(exclude_none=True), ensure_ascii=False, sort_keys=True).encode("utf-8")
                prepared = ingest_facade.prepared_event_ingest_body(
                    item,
                    raw_payload=item_raw,
                    source=src,
                    note="events_batch_ingest",
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"events[{i}]: {e}") from e
            results.append(_assess_prepared_ingest_event(prepared))
        return results

    compliance_facade = ComplianceFacade(
        repo=repo,
        clock=default_clock,
        compliance_report_uc=compliance_report_uc,
        forensic_readiness_uc=forensic_readiness_uc,
        evidence_checklist_uc=evidence_checklist_uc,
        remediation_uc=remediation_uc,
        remediation_list_uc=remediation_list_uc,
        audit_engagement_uc=audit_engagement_uc,
    )
    forensic_export_facade = ForensicExportFacade(
        forensic_uc=forensic_uc,
        forensic_verify_uc=forensic_verify_uc,
        audit_engagement_uc=audit_engagement_uc,
    )
    export_facade = ExportFacade(
        repo=repo,
        clock=default_clock,
        render_case_pdf=_main_module_callable("render_case_pdf"),
        render_decision_brief_pdf=_main_module_callable("render_decision_brief_pdf"),
        post_case_to_webhook_sync=_main_module_callable("post_case_to_webhook_sync"),
        post_case_to_webhook=_main_module_callable("post_case_to_webhook"),
        case_to_siem_payload=case_to_siem_payload,
        case_to_gossopka_card=case_to_gossopka_card,
        case_to_gossopka_transport_payload=case_to_gossopka_transport_payload,
        case_to_gossopka_official_card=case_to_gossopka_official_card,
        case_to_gossopka_official_transport_payload=case_to_gossopka_official_transport_payload,
        require_allowed_siem_url=require_allowed_siem_url,
    )
    case_actions_facade = CaseActionsFacade(
        repo=repo,
        clock=default_clock,
        manual_permit_uc=manual_permit_uc,
        formal_verdict_confirmation_uc=formal_verdict_confirmation_uc,
        decision_uc=decision_uc,
    )

    def _assess_from_plc_demo_body(body: AssessRequest) -> AssessResponse:
        try:
            ev = ingest_facade.normalized_event_from_plc_demo_body(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_normalized_event(ev, persist_case=body.persist_case)

    def _assess_syslog_rfc5424_body(body: SyslogRfc5424IngestBody) -> AssessResponse:
        try:
            prepared = ingest_facade.prepared_syslog_rfc5424_body(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_prepared_ingest_event(prepared)

    def _assess_snmp_trap_body(body: SnmpTrapIngestBody) -> AssessResponse:
        try:
            prepared = ingest_facade.prepared_snmp_trap_body(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_prepared_ingest_event(prepared)

    def _assess_netflow_body(body: NetflowIngestBody) -> AssessResponse:
        try:
            prepared = ingest_facade.prepared_netflow_body(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_prepared_ingest_event(prepared)

    def _assess_ipfix_body(body: IpfixIngestBody) -> AssessResponse:
        try:
            prepared = ingest_facade.prepared_ipfix_body(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _assess_prepared_ingest_event(prepared)

    api_ctx = ApiContext(
        app=app,
        repo=repo,
        baseline=baseline,
        clock=default_clock,
        package_version=_PACKAGE_VERSION,
        root=_ROOT,
        gzip_minimum_size_bytes=_GZIP_MINIMUM_SIZE_BYTES,
        export_full_max=_EXPORT_FULL_MAX,
        event_window_max=_EVENT_WINDOW_MAX,
        ingest_batch_max=_INGEST_BATCH_MAX,
        case_list_max_limit=_CASE_LIST_MAX_LIMIT,
        case_list_default_sort=_CASE_LIST_DEFAULT_SORT,
        build_revision_from_env=build_revision_from_env,
        openapi_server_entries_from_env=openapi_server_entries_from_env,
        forensic_crypto_mode=_forensic_crypto_mode,
        forensic_strict_missing=_forensic_strict_missing,
        demo_edges=list(demo_edges),
        jump_host=pipeline.jump_host,
        plc_hosts=set(pipeline.plc_hosts),
        backtest_uc=backtest_uc,
        audit_ledger_facade=audit_ledger_facade,
        forensic_uc=forensic_uc,
        forensic_verify_uc=forensic_verify_uc,
        forensic_export_facade=forensic_export_facade,
        export_facade=export_facade,
        audit_engagement_uc=audit_engagement_uc,
        compliance_report_uc=compliance_report_uc,
        forensic_readiness_uc=forensic_readiness_uc,
        evidence_checklist_uc=evidence_checklist_uc,
        remediation_uc=remediation_uc,
        remediation_list_uc=remediation_list_uc,
        compliance_facade=compliance_facade,
        cases_query_service=cases_query_service,
        offset_limit_link_header=offset_limit_link_header,
        case_to_detail=case_to_detail,
        decision_brief_to_detail=decision_brief_to_detail,
        domain_case_from_detail=domain_case_from_detail,
        coerce_event_source=_coerce_event_source,
        manual_permit_uc=manual_permit_uc,
        formal_verdict_confirmation_uc=formal_verdict_confirmation_uc,
        decision_uc=decision_uc,
        case_actions_facade=case_actions_facade,
        manual_permit_to_detail=manual_permit_to_detail,
        formal_verdict_record_to_detail=formal_verdict_record_to_detail,
        manual_correlation_uc=manual_correlation_uc,
        case_findings_uc=case_findings_uc,
        decoder_service=decoder_service,
        assess_from_plc_demo_body=_assess_from_plc_demo_body,
        assess_event_ingest_body=_assess_event_ingest_body,
        assess_event_batch_body=_assess_event_batch_body,
        assess_syslog_rfc5424_body=_assess_syslog_rfc5424_body,
        assess_snmp_trap_body=_assess_snmp_trap_body,
        assess_netflow_body=_assess_netflow_body,
        assess_ipfix_body=_assess_ipfix_body,
    )
    register_system_routes(api_ctx)
    register_catalog_routes(api_ctx)
    register_event_routes(api_ctx)
    register_assemble_routes(api_ctx)
    register_entity_routes(api_ctx)
    register_audit_ledger_routes(api_ctx)
    register_export_routes(api_ctx)
    register_integration_routes(api_ctx)
    register_analytics_routes(api_ctx)
    register_forensic_routes(api_ctx)
    register_audit_engagement_routes(api_ctx)
    register_compliance_routes(api_ctx)
    register_case_routes(api_ctx)
    register_attack_chain_routes(api_ctx)
    register_simulation_routes(api_ctx)
    register_workspace_routes(api_ctx)
    register_enrichment_routes(api_ctx)
    register_case_action_routes(api_ctx)
    register_correlation_routes(api_ctx)
    register_finding_routes(api_ctx)
    register_ingest_routes(api_ctx)

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


app = create_app()
