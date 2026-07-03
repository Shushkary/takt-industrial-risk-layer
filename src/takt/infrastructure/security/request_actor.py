"""Извлечение actor для журнала безопасности: mTLS DN от доверенного прокси либо клиентский IP."""

from __future__ import annotations

import os
import re

from starlette.requests import Request

from takt.infrastructure.http.rate_limit_middleware import client_ip_for_rate_limit
from takt.infrastructure.security.trusted_proxies import (
    address_in_trusted_networks,
    trusted_proxy_networks_from_env,
)


def _valid_header_name(raw: str) -> bool:
    return bool(raw) and len(raw) <= 64 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", raw) is not None


def mtls_dn_header_from_env() -> str | None:
    raw = os.environ.get("TAKT_MTLS_DN_HEADER", "").strip()
    if not raw or not _valid_header_name(raw):
        return None
    return raw


def mtls_dn_from_request(request: Request) -> str:
    """
    Значение DN из **TAKT_MTLS_DN_HEADER**, только если прямой peer входит в
    **TAKT_TRUSTED_PROXIES** / **TAKT_TRUSTED_PROXY_CIDRS**.
    """
    hdr = mtls_dn_header_from_env()
    if hdr is None:
        return ""
    trusted = trusted_proxy_networks_from_env()
    if not trusted:
        return ""
    direct = request.client.host if request.client else None
    peer = (direct or "").strip()
    if not peer or not address_in_trusted_networks(peer, trusted):
        return ""
    return request.headers.get(hdr, "").strip()


def security_actor_from_request(request: Request) -> str:
    """
    Приоритет: проверенный mTLS DN, иначе `actor_id` именованного API-ключа
    (см. `takt.infrastructure.security.api_keys`), иначе IP для rate limit
    (с учётом доверенных прокси).
    """
    dn = mtls_dn_from_request(request)
    if dn:
        return dn
    key_actor = getattr(request.state, "takt_actor_id", "")
    if key_actor and key_actor != "no-auth":
        return key_actor
    ip = client_ip_for_rate_limit(request)
    return ip if ip else "unknown"
