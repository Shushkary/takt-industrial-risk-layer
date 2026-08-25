from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from takt.infrastructure.http.error_json import error_json_content

_SIZE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def request_has_chunked_transfer_encoding(request: Request) -> bool:
    """`True`, если в **`Transfer-Encoding`** есть **`chunked`** (после разбора по запятой, без учёта регистра)."""
    raw = request.headers.get("transfer-encoding", "")
    if not raw.strip():
        return False
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    return "chunked" in parts


def max_request_body_bytes_from_env() -> int | None:
    """Максимум размера тела (байт) из **`TAKT_MAX_REQUEST_BODY_MB`**; `None` — без лимита."""
    raw = os.environ.get("TAKT_MAX_REQUEST_BODY_MB", "").strip()
    if not raw:
        return None
    try:
        mb = float(raw)
    except ValueError:
        return None
    if mb <= 0.0:
        return None
    return int(mb * 1024 * 1024)


class RequestBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Если задана **`TAKT_MAX_REQUEST_BODY_MB`** (> 0), для **POST**/**PUT**/**PATCH**:
    при **`Transfer-Encoding: chunked`** — **411** (нужен **`Content-Length`** для лимита на входе);
    при **`Content-Length`** больше лимита — **413**;
    без **`Content-Length`** и без chunked — пропуск (как раньше: лимит до чтения тела не применяется).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        max_b = max_request_body_bytes_from_env()
        if max_b is None or request.method not in _SIZE_METHODS:
            return await call_next(request)
        if request_has_chunked_transfer_encoding(request):
            return JSONResponse(
                status_code=411,
                content=error_json_content(
                    "chunked request body is not accepted when TAKT_MAX_REQUEST_BODY_MB is set; "
                    "send Content-Length instead",
                    request,
                ),
            )
        cl = request.headers.get("content-length")
        if not cl or not cl.strip():
            return await call_next(request)
        try:
            n = int(cl.strip())
        except ValueError:
            return await call_next(request)
        if n > max_b:
            return JSONResponse(
                status_code=413,
                content=error_json_content(f"request body too large (limit {max_b} bytes)", request),
            )
        return await call_next(request)
