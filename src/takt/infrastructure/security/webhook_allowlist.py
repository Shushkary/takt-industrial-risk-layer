"""Структурный allowlist для SIEM webhook и профиль безопасности (Спринт 1)."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from takt.infrastructure.security.auth_env import takt_profile_from_env

SecurityProfile = Literal["dev", "prod"]


def takt_security_profile_from_env() -> SecurityProfile:
    """**TAKT_SECURITY_PROFILE**: **prod** / **production** — строгий SIEM; иначе **dev** (loopback/private в DNS)."""
    raw = os.environ.get("TAKT_SECURITY_PROFILE", "").strip().lower()
    if raw in ("prod", "production"):
        return "prod"
    return "dev"


def siem_allowlist_mode_label() -> str:
    return "structural"


def internal_webhook_rfc1918_bypass_from_env() -> bool:
    """
    Сегмент air-gap (план v0.7.0): при **TAKT_PROFILE=airgap** и **TAKT_ALLOW_INTERNAL_WEBHOOK**
    исходящий webhook может резолвиться в RFC1918 / loopback без отказа **assert_egress_ips_allowed**.
    """
    if takt_profile_from_env() != "airgap":
        return False
    raw = os.environ.get("TAKT_ALLOW_INTERNAL_WEBHOOK", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True, slots=True)
class _AllowRule:
    scheme: str
    host: str
    port: int | None
    path_prefix: str


def _default_port_for_scheme(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _normalize_path(path: str) -> str:
    if not path or path == "":
        return "/"
    return path if path.startswith("/") else f"/{path}"


def _parse_rule(raw: str) -> _AllowRule:
    u = urlparse(raw.strip())
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("siem allowlist: только схемы http/https")
    if not host:
        raise ValueError("siem allowlist: нужен hostname в правиле")
    port = u.port
    if port is None:
        port_eff: int | None = None
    else:
        port_eff = port
    path = _normalize_path(u.path or "/")
    return _AllowRule(scheme=scheme, host=host, port=port_eff, path_prefix=path)


def _effective_port(parsed, scheme: str) -> int:
    return parsed.port if parsed.port is not None else _default_port_for_scheme(scheme)


def _loopback_host_ok(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def _structural_match_target(url: str, rules: tuple[_AllowRule, ...], *, profile: SecurityProfile) -> None:
    raw = url.strip()
    t = urlparse(raw)
    scheme = (t.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("webhook: только схемы http/https")
    if profile == "prod" and scheme != "https":
        raise ValueError("webhook: в профиле prod разрешён только https")
    if t.username or t.password:
        raise ValueError("webhook: userinfo в URL запрещён")
    host = (t.hostname or "").lower()
    if not host:
        raise ValueError("webhook: нужен hostname")
    port = _effective_port(t, scheme)
    path = t.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    if not rules:
        if _loopback_host_ok(host) and scheme in ("http", "https"):
            if profile == "prod" and scheme != "https":
                raise ValueError("webhook: в профиле prod разрешён только https")
            def_p = _default_port_for_scheme(scheme)
            if port != def_p and profile == "prod":
                raise ValueError("webhook: при пустом allowlist нестандартные порты недопустимы в prod")
            return
        raise ValueError(
            "webhook: при пустом allowed_url_prefixes разрешены только 127.0.0.1, localhost, ::1"
        )

    for rule in rules:
        if rule.scheme != scheme:
            continue
        if host != rule.host and not host.endswith(f".{rule.host}"):
            continue
        rule_def = _default_port_for_scheme(rule.scheme)
        if rule.port is None:
            if port != rule_def:
                continue
        else:
            if port != rule.port:
                continue
        if not _path_allowed(path, rule.path_prefix):
            continue
        return

    raise ValueError("webhook: URL не соответствует структурному siem_webhook.allowed_url_prefixes")


def _path_allowed(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def parse_allowlist_rules(allowed_prefixes: Sequence[str]) -> tuple[_AllowRule, ...]:
    return tuple(_parse_rule(x) for x in allowed_prefixes if str(x).strip())


def require_allowed_siem_url(url: str, allowed_prefixes: Sequence[str] | None) -> None:
    profile = takt_security_profile_from_env()
    seq = list(allowed_prefixes) if allowed_prefixes else []
    rules = parse_allowlist_rules(seq) if seq else ()
    _structural_match_target(url, rules, profile=profile)


def assert_egress_ips_allowed(resolved_ips: Sequence[str], *, profile: SecurityProfile) -> None:
    """DNS rebinding / SSRF: в **prod** запрещены loopback, RFC1918, link-local (кроме bypass air-gap)."""
    if internal_webhook_rfc1918_bypass_from_env():
        return
    if profile != "prod":
        return
    for ip_s in resolved_ips:
        try:
            addr = ipaddress.ip_address(ip_s)
        except ValueError as e:
            raise ValueError(f"webhook: некорректный IP из DNS: {ip_s!r}") from e
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        ):
            raise ValueError(f"webhook: в профиле prod хост резолвится в запрещённый адрес: {ip_s}")
