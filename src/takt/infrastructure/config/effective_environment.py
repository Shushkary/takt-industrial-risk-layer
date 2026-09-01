"""Снимок действующей конфигурации окружения для `GET /health`.

Значения читаются в момент вызова, а не запоминаются на старте: `/health` показывает то,
что действует сейчас, и это нарочно — эндпойнт диагностический.

Модуль появился, чтобы разбор переменных окружения жил в том слое, чей это предмет.
Раньше `routers/system.py` ради одного ответа импортировал четырнадцать модулей
инфраструктуры (`http/*`, `security/*`, `stores/*`) и сам собирал два десятка флагов
`os.environ` — слой доставки знал внутреннее устройство инфраструктуры пофайлово.
"""

from __future__ import annotations

import os
from typing import Any

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
from takt.infrastructure.security.api_keys import api_key_entries_from_env
from takt.infrastructure.security.auth_env import auth_mode_for_health
from takt.infrastructure.security.trusted_proxies import trusted_proxy_networks_from_env
from takt.infrastructure.security.webhook_allowlist import (
    siem_allowlist_mode_label,
    takt_security_profile_from_env,
)
from takt.infrastructure.stores.sqlite_store import sqlite_busy_timeout_ms_from_env

__all__ = ["auth_mode_for_health", "environment_health_snapshot", "sqlite_busy_timeout_ms_from_env"]


def _text(name: str, default: str = "") -> str:
    """Значение переменной без обрамляющих пробелов; пустая строка приравнена к отсутствию."""
    return os.environ.get(name, "").strip() or default


def _is_set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def _rbac_snapshot() -> dict[str, Any]:
    entries = api_key_entries_from_env()
    role_counts: dict[str, int] = {}
    for entry in entries:
        role_counts[entry.role] = role_counts.get(entry.role, 0) + 1
    return {"roles_configured": len(entries), "role_counts": role_counts}


def _rate_limit_entries() -> dict[str, Any]:
    """Действующий лимит запросов. Подчинённые ключи имеют смысл только при активном лимите."""
    per_minute = rate_limit_per_minute_from_env()
    if per_minute is None:
        return {}
    entries: dict[str, Any] = {
        "rate_limit_per_minute": per_minute,
        "rate_limit_max_tracked_ips": rate_limit_max_tracked_ips_from_env(),
    }
    ip_header = rate_limit_ip_header_from_env()
    if ip_header is not None:
        entries["rate_limit_ip_header"] = ip_header
    return entries


def _optional_entries() -> dict[str, Any]:
    """Ключи, которых в ответе нет, пока соответствующая настройка не задана."""
    candidates: dict[str, Any] = {
        "request_id_alternate_header": request_id_alternate_header_from_env(),
        "max_request_body_bytes": max_request_body_bytes_from_env(),
        "slow_request_log_threshold_sec": slow_log_threshold_seconds(),
        "catalog_cache_max_age_sec": catalog_cache_max_age_sec(),
    }
    return {key: value for key, value in candidates.items() if value is not None}


def environment_health_snapshot() -> dict[str, Any]:
    """Часть тела `GET /health`, целиком выводимая из переменных окружения."""
    gossopka_profile_raw = _text("TAKT_GOSSOPKA_PROFILE")
    snapshot: dict[str, Any] = {
        "api_key_enabled": _is_set("TAKT_API_KEY"),
        "auth": {"mode": auth_mode_for_health(), **_rbac_snapshot()},
        "siem": {
            "allowlist_mode": siem_allowlist_mode_label(),
            "profile": takt_security_profile_from_env(),
        },
        "proxy": {"trusted_count": len(trusted_proxy_networks_from_env())},
        "rate_limit": {"proxy_mode": rate_limit_proxy_mode_for_health()},
        "takt_config_env_set": _is_set("TAKT_CONFIG"),
        "takt_storage_env_set": _is_set("TAKT_STORAGE"),
        "takt_sqlite_path_env_set": _is_set("TAKT_SQLITE_PATH"),
        "takt_sqlite_busy_timeout_ms_env_set": _is_set("TAKT_SQLITE_BUSY_TIMEOUT_MS"),
        "takt_log_level_env_set": _is_set("TAKT_LOG_LEVEL"),
        "takt_max_request_body_mb_env_set": _is_set("TAKT_MAX_REQUEST_BODY_MB"),
        "takt_slow_request_log_env_set": _is_set("TAKT_SLOW_REQUEST_LOG_SEC"),
        "takt_cors_origins_env_set": _is_set("TAKT_CORS_ORIGINS"),
        "takt_hsts_max_age_env_set": _is_set("TAKT_HSTS_MAX_AGE"),
        "takt_hsts_preload_env_set": _is_set("TAKT_HSTS_PRELOAD"),
        "takt_openapi_server_url_env_set": _is_set("TAKT_OPENAPI_SERVER_URL"),
        "takt_request_id_header_env_set": _is_set("TAKT_REQUEST_ID_HEADER"),
        "takt_catalog_cache_max_age_sec_env_set": _is_set("TAKT_CATALOG_CACHE_MAX_AGE_SEC"),
        "takt_rate_limit_env_set": _is_set("TAKT_RATE_LIMIT_PER_MIN"),
        "takt_rate_limit_max_ips_env_set": _is_set("TAKT_RATE_LIMIT_MAX_IPS"),
        "takt_rate_limit_ip_header_env_set": _is_set("TAKT_RATE_LIMIT_IP_HEADER"),
        "takt_build_revision_env_set": _is_set("TAKT_BUILD_REVISION"),
        "takt_metrics_env_enabled": metrics_enabled_from_env(),
        "cors_enabled": cors_middleware_enabled_from_env(),
        "hsts_enabled": hsts_enabled_from_env(),
        "hsts_preload_enabled": hsts_preload_enabled_from_env(),
        "gossopka_profile": gossopka_profile_raw or "mvp",
        "gossopka_official_exchange_enabled": (
            gossopka_profile_raw.lower() == "official" or _is_set("TAKT_GOSSOPKA_OFFICIAL_CONTRACT_ID")
        ),
        "ingest_syslog_rfc5424_enabled": _is_set("TAKT_INGEST_SYSLOG_RFC5424"),
        "ingest_snmp_enabled": _is_set("TAKT_INGEST_SNMP"),
        "ingest_netflow_enabled": _is_set("TAKT_INGEST_NETFLOW"),
        "ingest_ipfix_enabled": _is_set("TAKT_INGEST_IPFIX"),
        "ldap_integration_configured": _is_set("TAKT_LDAP_URL"),
        "ad_integration_configured": _is_set("TAKT_AD_DOMAIN"),
        "timeseries_backend": _text("TAKT_TIMESERIES_BACKEND", "sqlite"),
        "timeseries_configured": _is_set("TAKT_TIMESERIES_DSN"),
        "object_storage_backend": _text("TAKT_OBJECT_STORAGE_BACKEND", "none"),
        "object_storage_configured": _is_set("TAKT_OBJECT_STORAGE_BUCKET"),
    }
    snapshot.update(_optional_entries())
    snapshot.update(_rate_limit_entries())
    return snapshot
