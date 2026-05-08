"""Доверенные прокси (CIDR) для извлечения реального клиентского IP (Спринт 1)."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Sequence


def trusted_proxy_networks_from_env() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """
    **TAKT_TRUSTED_PROXIES** и **TAKT_TRUSTED_PROXY_CIDRS**: списки CIDR через запятую
    (напр. **10.0.0.0/8,192.168.0.0/16**). Объединяются. Пусто — заголовки **X-Forwarded-For** /
    **TAKT_RATE_LIMIT_IP_HEADER** не доверяются для лимита.
    """
    raw_a = os.environ.get("TAKT_TRUSTED_PROXIES", "").strip()
    raw_b = os.environ.get("TAKT_TRUSTED_PROXY_CIDRS", "").strip()
    parts = [p.strip() for p in f"{raw_a},{raw_b}".split(",") if p.strip()]
    if not parts:
        return ()
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for s in parts:
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _parse_ip(maybe_bracketed: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    s = maybe_bracketed.strip()
    if not s:
        return None
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def address_in_trusted_networks(addr: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    ip = _parse_ip(addr)
    if ip is None:
        return False
    return any(ip in net for net in networks)


def client_ip_for_trusted_proxy_chain(
    *,
    direct_peer: str | None,
    forwarded_chain: str,
    trusted: Sequence[ipaddress._BaseNetwork],
) -> str:
    """
    Если прямой peer не в доверенных сетях — возвращаем его (заголовки игнорируются).

    Если peer доверенный — разбираем цепочку **XFF** слева направо и берём **правыйmost**
    IP, который **не** входит в доверенные сети; если все доверенные или цепочка пуста — peer.
    """
    peer = (direct_peer or "").strip()
    if not trusted:
        return peer if peer else "unknown"

    parts = [p.strip() for p in forwarded_chain.split(",") if p.strip()]
    if not peer:
        return "unknown"
    if not address_in_trusted_networks(peer, trusted):
        return peer

    if not parts:
        return peer

    for hop in reversed(parts):
        if address_in_trusted_networks(hop, trusted):
            continue
        return hop
    return parts[0]


def is_valid_env_token_name(s: str) -> bool:
    """Такие же правила, что и для **TAKT_RATE_LIMIT_IP_HEADER**."""
    return bool(s) and len(s) <= 64 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", s) is not None
