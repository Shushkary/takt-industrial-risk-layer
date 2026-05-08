from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


def catalog_cache_max_age_sec() -> int | None:
    """Эффективный **max-age** (сек) для каталожных **GET**; **`None`** — **Cache-Control** для каталога не выставляется."""
    raw = os.environ.get("TAKT_CATALOG_CACHE_MAX_AGE_SEC", "").strip()
    if raw == "":
        return 60
    try:
        n = int(raw)
    except ValueError:
        return 60
    if n <= 0:
        return None
    return min(n, 86400)


_CATALOG_GET_PATHS: frozenset[str] = frozenset(
    {
        "/invariants",
        "/catalog/event-sources",
        "/topology/demo-graph",
    }
)


class CatalogCacheControlMiddleware(BaseHTTPMiddleware):
    """Короткий **Cache-Control** для каталожных **GET**, не зависящих от сессии (по умолчанию **60** с)."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        if request.method != "GET":
            return response
        if request.url.path not in _CATALOG_GET_PATHS:
            return response
        max_age = catalog_cache_max_age_sec()
        if max_age is None:
            return response
        response.headers.setdefault("Cache-Control", f"public, max-age={max_age}")
        return response


class CasesPrivateNoStoreMiddleware(BaseHTTPMiddleware):
    """**GET** по **`/cases…`** — данные кейсов; по умолчанию **`private, no-store`**, чтобы прокси не кэшировали."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        if request.method != "GET":
            return response
        path = request.url.path
        if not path.startswith("/cases"):
            return response
        response.headers.setdefault("Cache-Control", "private, no-store")
        return response
