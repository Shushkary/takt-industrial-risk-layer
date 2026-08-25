from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_TAKT_BUILD_REVISION_MAX_LEN = 256


class HealthAuthBlock(BaseModel):
    mode: str
    roles_configured: int = Field(default=0, ge=0)
    role_counts: dict[str, int] = Field(default_factory=dict)


class HealthSiemBlock(BaseModel):
    allowlist_mode: str
    profile: str


class HealthProxyBlock(BaseModel):
    trusted_count: int = Field(ge=0)


class HealthRateLimitGate(BaseModel):
    proxy_mode: Literal["direct", "trusted_header"]


class HealthSecurityLogGate(BaseModel):
    status: str
    entries_last_hour: int = Field(ge=0)


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: Literal["ok"] = "ok"
    product: str
    version: str
    python_version: str
    python_implementation: str
    api_log_level: str
    uptime_seconds: float
    booted_at_utc: str
    process_id: int
    hostname: str
    platform: str
    python_executable: str
    working_directory: str
    api_key_enabled: bool
    auth: HealthAuthBlock
    siem: HealthSiemBlock
    proxy: HealthProxyBlock
    rate_limit: HealthRateLimitGate
    security_log: HealthSecurityLogGate
    takt_config_env_set: bool
    takt_storage_env_set: bool
    takt_sqlite_path_env_set: bool
    takt_sqlite_busy_timeout_ms_env_set: bool
    takt_log_level_env_set: bool
    takt_max_request_body_mb_env_set: bool
    takt_slow_request_log_env_set: bool
    takt_cors_origins_env_set: bool
    takt_hsts_max_age_env_set: bool
    takt_hsts_preload_env_set: bool
    cors_enabled: bool
    hsts_enabled: bool
    hsts_preload_enabled: bool
    gzip_minimum_size_bytes: int
    openapi_servers_count: int = 0
    takt_openapi_server_url_env_set: bool
    takt_request_id_header_env_set: bool
    request_id_alternate_header: str | None = None
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
    sqlite_busy_timeout_ms: int | None = None
    max_request_body_bytes: int | None = None
    slow_request_log_threshold_sec: float | None = None
    takt_catalog_cache_max_age_sec_env_set: bool
    catalog_cache_max_age_sec: int | None = None
    takt_metrics_env_enabled: bool = False
    prometheus_metrics_enabled: bool = False
    takt_rate_limit_env_set: bool
    takt_rate_limit_max_ips_env_set: bool
    takt_rate_limit_ip_header_env_set: bool
    rate_limit_per_minute: int | None = None
    rate_limit_max_tracked_ips: int | None = None
    rate_limit_tracked_ips: int | None = None
    rate_limit_ip_header: str | None = None
    takt_build_revision_env_set: bool
    build_revision: str | None = Field(default=None, max_length=_TAKT_BUILD_REVISION_MAX_LEN)


class LiveResponse(BaseModel):
    live: Literal[True] = True
    product: str
    version: str
    build_revision: str | None = Field(default=None, max_length=_TAKT_BUILD_REVISION_MAX_LEN)


class ReadyResponse(BaseModel):
    ready: Literal[True] = True
    case_storage: str
    expected_behavior_storage: str
    forensic_crypto_mode: str = "mvp"
    forensic_strict_ready: bool = False
    forensic_strict_missing: list[str] = Field(default_factory=list)
    build_revision: str | None = Field(default=None, max_length=_TAKT_BUILD_REVISION_MAX_LEN)


class DataQualityResponse(BaseModel):
    dq_score: float
    partial_observability: bool
    reasons: list[str]


class SessionPermissions(BaseModel):
    """Что роль может делать — вычисляется той же матрицей, которая проверяет запросы.

    Отдаётся, чтобы рабочее место **скрывало** недоступное действие, а не показывало его и
    отвечало ошибкой после нажатия. Собственной копии матрицы в интерфейсе нет намеренно:
    она разошлась бы с `rbac.py` при первом же изменении правил и разошлась бы молча.
    """

    case_write: bool
    """Квалификация, решение по делу, находки и ручные наряды."""

    case_relink: bool
    """Ручные `attach`/`detach`, `merge`/`split` — вторая линия."""

    administration: bool
    """Импорт полного реестра, пересылка в СОБИ, аудит сервисного движка."""


class SessionResponse(BaseModel):
    """Кто работает в текущей сессии — для шапки рабочего места и для авторства находок.

    `actor_id` — тот же идентификатор, который уходит в append-only журнал кейса. До появления
    этого ответа интерфейс не мог назвать автора: в журнале оставался IP-адрес клиента.
    """

    actor_id: str
    role: str
    auth_mode: Literal["required", "optional", "disabled"]
    permissions: SessionPermissions
