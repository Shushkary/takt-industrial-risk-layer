from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from takt.infrastructure.security.request_actor import security_actor_from_request

_EXACT_PUBLIC: frozenset[str] = frozenset(
    {"/health", "/live", "/ready", "/openapi.json", "/metrics"},
)
_PREFIX_PUBLIC: tuple[str, ...] = ("/docs", "/redoc")
_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_public_path(path: str) -> bool:
    if path in _EXACT_PUBLIC:
        return True
    return any(path == p or path.startswith(f"{p}/") for p in _PREFIX_PUBLIC)


def _present_auth_headers(request: Request) -> dict[str, bool]:
    return {
        "x_takt_api_key_present": bool(request.headers.get("x-takt-api-key", "").strip()),
        "authorization_present": bool(request.headers.get("authorization", "").strip()),
    }


class SecurityLogMiddleware(BaseHTTPMiddleware):
    """Журнал безопасности: **auth_failure** и **http_mutating** (ФСТЭК 239/31)."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        path = request.url.path
        method = request.method.upper()
        if method not in _MUTATING or _is_public_path(path):
            return response

        slog = getattr(request.app.state, "security_log", None)
        if slog is None:
            return response

        rid = getattr(request.state, "request_id", None)
        rid_s = rid.strip() if isinstance(rid, str) else ""
        actor = security_actor_from_request(request)
        base = {
            "actor": actor,
            "method": method,
            "path": path,
            "status_code": response.status_code,
            "request_id": rid_s or None,
            "client_host": request.client.host if request.client else None,
        }

        if response.status_code == 401:
            slog.record(
                "auth_failure",
                {
                    **base,
                    **_present_auth_headers(request),
                },
            )
        else:
            slog.record("http_mutating", base)

        return response
