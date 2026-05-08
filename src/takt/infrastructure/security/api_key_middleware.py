from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from takt.infrastructure.http.error_json import error_json_content
from takt.infrastructure.security.auth_env import takt_api_key_value, takt_auth_required_from_env

_EXACT_PUBLIC: frozenset[str] = frozenset(
    {"/health", "/live", "/ready", "/openapi.json", "/metrics"}
)
_PREFIX_PUBLIC: tuple[str, ...] = ("/docs", "/redoc")


def _is_public_path(path: str) -> bool:
    if path in _EXACT_PUBLIC:
        return True
    return any(path == p or path.startswith(f"{p}/") for p in _PREFIX_PUBLIC)


def _extract_key(request: Request) -> str:
    got = request.headers.get("x-takt-api-key", "").strip()
    if got:
        return got
    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


class OptionalApiKeyMiddleware(BaseHTTPMiddleware):
    """
    **TAKT_AUTH_REQUIRED** (по умолчанию **true**): все пути, кроме публичных, требуют ключ.
    При **TAKT_AUTH_REQUIRED=false** без ключа — доступ открыт; если **TAKT_API_KEY** задан,
    поведение как раньше (опциональная защита для путей вне публичного списка).

    Публичные пути: **`/health`**, **`/live`**, **`/ready`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`**.
    Ошибка аутентификации: **401 Unauthorized**.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if _is_public_path(path):
            return await call_next(request)

        expected = takt_api_key_value()
        required_mode = takt_auth_required_from_env()

        if required_mode:
            if not expected:
                return JSONResponse(
                    error_json_content("missing or invalid API key", request),
                    status_code=401,
                )
            got = _extract_key(request)
            exp_b = expected.encode("utf-8")
            got_b = got.encode("utf-8")
            if len(got_b) != len(exp_b) or not hmac.compare_digest(got_b, exp_b):
                return JSONResponse(
                    error_json_content("missing or invalid API key", request),
                    status_code=401,
                )
            return await call_next(request)

        if not expected:
            return await call_next(request)

        got = _extract_key(request)
        exp_b = expected.encode("utf-8")
        got_b = got.encode("utf-8")
        if len(got_b) != len(exp_b) or not hmac.compare_digest(got_b, exp_b):
            return JSONResponse(
                error_json_content("missing or invalid API key", request),
                status_code=401,
            )
        return await call_next(request)
