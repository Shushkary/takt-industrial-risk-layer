from __future__ import annotations

import math
import os
import re
import threading
import time
from typing import Literal

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from takt.infrastructure.http.error_json import error_json_content
from takt.infrastructure.http.prometheus_metrics import record_rate_limit_rejection
from takt.infrastructure.security.trusted_proxies import (
    client_ip_for_trusted_proxy_chain,
    trusted_proxy_networks_from_env,
)

_EXEMPT_EXACT: frozenset[str] = frozenset({"/health", "/live", "/ready", "/openapi.json", "/metrics"})
_EXEMPT_PREFIX: tuple[str, ...] = ("/docs", "/redoc")
_DEFAULT_MAX_TRACKED_IPS = 8192
_MIN_MAX_TRACKED = 256
_MAX_MAX_TRACKED = 500_000


def rate_limit_per_minute_from_env() -> int | None:
    """Лимит запросов в минуту на клиента; `None` — выключено (нет или невалидная **`TAKT_RATE_LIMIT_PER_MIN`**)."""
    raw = os.environ.get("TAKT_RATE_LIMIT_PER_MIN", "").strip()
    if not raw:
        return None
    try:
        n = int(raw, 10)
    except ValueError:
        return None
    return n if n > 0 else None


def rate_limit_max_tracked_ips_from_env() -> int:
    """Верхняя граница числа IP в счётчике; по умолчанию **`_DEFAULT_MAX_TRACKED_IPS`**, настраивается **`TAKT_RATE_LIMIT_MAX_IPS`**."""
    raw = os.environ.get("TAKT_RATE_LIMIT_MAX_IPS", "").strip()
    if not raw:
        return _DEFAULT_MAX_TRACKED_IPS
    try:
        n = int(raw, 10)
    except ValueError:
        return _DEFAULT_MAX_TRACKED_IPS
    return max(_MIN_MAX_TRACKED, min(n, _MAX_MAX_TRACKED))


def rate_limit_ip_header_from_env() -> str | None:
    """
    Имя HTTP-заголовка для клиентского IP в лимите (**`TAKT_RATE_LIMIT_IP_HEADER`**) — напр. у CDN (**`CF-Connecting-IP`**).
    Допустимые символы: буквы, цифры, **`-`**, **`_`**, длина 1–64; иначе — как без переменной.
    """
    raw = os.environ.get("TAKT_RATE_LIMIT_IP_HEADER", "").strip()
    if not raw:
        return None
    if len(raw) > 64 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", raw):
        return None
    return raw


def rate_limit_proxy_mode_for_health() -> Literal["direct", "trusted_header"]:
    """**GET /health**: **direct**, если доверенных CIDR нет; иначе **trusted_header**."""
    return "trusted_header" if trusted_proxy_networks_from_env() else "direct"


def prune_rate_limit_store(
    store: dict[str, tuple[int, int]],
    current_win: int,
    max_entries: int,
) -> None:
    """
    Удаляет записи прошлых минутных окон; при переполнении — самые старые ключи (порядок вставки в ``dict``).
    Снятые по переполнению IP теряют счётчик до следующего запроса (чуть мягче лимит для них).
    """
    if len(store) <= max_entries:
        stale = [ip for ip, (w, _) in store.items() if w != current_win]
        for ip in stale:
            del store[ip]
        return
    stale = [ip for ip, (w, _) in store.items() if w != current_win]
    for ip in stale:
        del store[ip]
    if len(store) <= max_entries:
        return
    overflow = len(store) - max_entries
    for ip in list(store.keys())[:overflow]:
        del store[ip]


def rate_limit_exempt_path(path: str) -> bool:
    """Пути без лимита (пробы, OpenAPI, **`/metrics`**, Swagger)."""
    if path in _EXEMPT_EXACT:
        return True
    return any(path == p or path.startswith(f"{p}/") for p in _EXEMPT_PREFIX)


def client_ip_for_rate_limit(request: Request) -> str:
    """
    Клиентский IP для ключа лимита. Цепочка **X-Forwarded-For** (или **`TAKT_RATE_LIMIT_IP_HEADER**)
    учитывается только если **`TAKT_TRUSTED_PROXIES`** непуст и прямой peer входит в эти CIDR;
    иначе используется адрес сокета (заголовки игнорируются — заащита от подмены).
    """
    direct = request.client.host if request.client else None
    trusted = trusted_proxy_networks_from_env()
    hdr = rate_limit_ip_header_from_env()
    if hdr:
        chain = request.headers.get(hdr, "")
    else:
        chain = request.headers.get("x-forwarded-for", "")
    return client_ip_for_trusted_proxy_chain(
        direct_peer=direct,
        forwarded_chain=chain or "",
        trusted=trusted,
    )


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory лимит запросов в минуту по IP (**`TAKT_RATE_LIMIT_PER_MIN`** > 0).
    Окно — календарная минута (UTC epoch). Исключения: **`/live`**, **`/ready`**, **`/health`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`**.
    При превышении — **429**, **`Retry-After`** и заголовки **`X-RateLimit-Limit`** / **`X-RateLimit-Remaining`** / **`X-RateLimit-Reset`** (конец текущего минутного окна, Unix UTC).
    Число отслеживаемых IP ограничено (**`TAKT_RATE_LIMIT_MAX_IPS`**, по умолчанию **8192**): старые окна и избыток ключей вычищаются.
    Опционально **`TAKT_RATE_LIMIT_IP_HEADER`**: доверенный заголовок клиентского IP (перед **`X-Forwarded-For`**).
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        limit = rate_limit_per_minute_from_env()
        if limit is None:
            return await call_next(request)
        path = request.url.path
        if rate_limit_exempt_path(path):
            return await call_next(request)

        ip = client_ip_for_rate_limit(request)
        now = time.time()
        win = int(now // 60)
        lock: threading.Lock = request.app.state.rate_limit_lock  # type: ignore[attr-defined]
        store: dict[str, tuple[int, int]] = request.app.state.rate_limit_buckets  # type: ignore[attr-defined]
        cap = rate_limit_max_tracked_ips_from_env()

        reset_ts = str((win + 1) * 60)
        rate_hdrs: dict[str, str] = {}

        with lock:
            entry = store.get(ip)
            if entry is None or entry[0] != win:
                current = 1
                store[ip] = (win, current)
            else:
                w, c = entry
                if c >= limit:
                    ra = max(1, min(60, int(math.ceil(60.0 - (now % 60.0)))))
                    record_rate_limit_rejection()
                    prune_rate_limit_store(store, win, cap)
                    return JSONResponse(
                        status_code=429,
                        content=error_json_content("rate limit exceeded", request),
                        headers={
                            "Retry-After": str(ra),
                            "X-RateLimit-Limit": str(limit),
                            "X-RateLimit-Remaining": "0",
                            "X-RateLimit-Reset": reset_ts,
                        },
                    )
                current = c + 1
                store[ip] = (w, current)
            prune_rate_limit_store(store, win, cap)
            rate_hdrs = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(max(0, limit - current)),
                "X-RateLimit-Reset": reset_ts,
            }

        response = await call_next(request)
        for hk, hv in rate_hdrs.items():
            response.headers[hk] = hv
        return response
