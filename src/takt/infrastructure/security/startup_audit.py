"""Снимок конфигурации безопасности при старте (журнал безопасности, Спринт 1)."""

from __future__ import annotations

from typing import Any

from takt.infrastructure.security.auth_env import (
    takt_api_key_value,
    takt_auth_required_from_env,
    takt_profile_from_env,
)
from takt.infrastructure.security.request_actor import mtls_dn_header_from_env
from takt.infrastructure.security.trusted_proxies import trusted_proxy_networks_from_env
from takt.infrastructure.security.webhook_allowlist import takt_security_profile_from_env


def security_startup_config_snapshot() -> dict[str, Any]:
    return {
        "takt_profile": takt_profile_from_env(),
        "takt_auth_required": takt_auth_required_from_env(),
        "takt_api_key_configured": bool(takt_api_key_value()),
        "takt_security_profile": takt_security_profile_from_env(),
        "mtls_dn_header_configured": mtls_dn_header_from_env() is not None,
        "trusted_proxy_cidrs_count": len(trusted_proxy_networks_from_env()),
    }
