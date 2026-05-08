from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


def _strict_transport_security() -> str | None:
    """Если задана **TAKT_HSTS_MAX_AGE** (секунды, > 0), добавляется HSTS за TLS-терминатором."""
    raw = os.environ.get("TAKT_HSTS_MAX_AGE", "").strip()
    if not raw:
        return None
    try:
        sec = int(raw)
    except ValueError:
        return None
    if sec <= 0:
        return None
    parts = [f"max-age={sec}", "includeSubDomains"]
    pre = os.environ.get("TAKT_HSTS_PRELOAD", "").strip().lower()
    if pre in ("1", "true", "yes"):
        parts.append("preload")
    return "; ".join(parts)


def hsts_enabled_from_env() -> bool:
    """`True`, если задан валидный **TAKT_HSTS_MAX_AGE** > 0 (заголовок HSTS на ответах)."""
    return _strict_transport_security() is not None


def hsts_preload_enabled_from_env() -> bool:
    """`True`, если HSTS включён и **TAKT_HSTS_PRELOAD** — **1**/**true**/**yes** (**preload** в **Strict-Transport-Security**)."""
    if not hsts_enabled_from_env():
        return False
    pre = os.environ.get("TAKT_HSTS_PRELOAD", "").strip().lower()
    return pre in ("1", "true", "yes")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Базовые заголовки безопасности для всех ответов API."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        hsts = _strict_transport_security()
        if hsts:
            response.headers.setdefault("Strict-Transport-Security", hsts)
        return response
