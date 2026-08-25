from __future__ import annotations

import logging
import os
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_LOG = logging.getLogger("takt.api")


def slow_log_threshold_seconds() -> float | None:
    """Порог (сек) для **WARNING** в `takt.api`; `None` — выключено или невалидная env."""
    raw = os.environ.get("TAKT_SLOW_REQUEST_LOG_SEC", "").strip()
    if not raw:
        return None
    try:
        v = float(raw)
    except ValueError:
        return None
    return v if v > 0.0 else None


class ProcessTimeMiddleware(BaseHTTPMiddleware):
    """Добавляет **X-Process-Time**: длительность обработки запроса в секундах (строка float)."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        t0 = time.perf_counter()
        response = await call_next(request)
        dt = time.perf_counter() - t0
        response.headers["X-Process-Time"] = f"{dt:.6f}"
        thr = slow_log_threshold_seconds()
        if thr is not None and dt >= thr:
            rid = getattr(request.state, "request_id", None)
            _LOG.warning(
                "slow request %s %s %.3fs request_id=%s",
                request.method,
                request.url.path,
                dt,
                rid or "-",
            )
        return response
