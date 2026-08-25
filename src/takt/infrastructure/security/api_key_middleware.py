from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from takt.infrastructure.http.error_json import error_json_content
from takt.infrastructure.security.api_keys import ApiKeyEntry, api_key_entries_from_env, resolve_api_key
from takt.infrastructure.security.auth_env import takt_auth_required_from_env
from takt.infrastructure.security.rbac import required_role_for_route, role_satisfies

_EXACT_PUBLIC: frozenset[str] = frozenset(
    {"/health", "/live", "/ready", "/openapi.json", "/metrics"}
)
_PREFIX_PUBLIC: tuple[str, ...] = ("/docs", "/redoc")

# Роль, назначаемая запросу, когда аутентификация не настроена вовсе
# (TAKT_AUTH_REQUIRED=0 и ни TAKT_API_KEY, ни TAKT_API_KEYS не заданы).
# Только для разработки: без ключей нет способа различить роли, поэтому
# разрешается всё — как и до появления RBAC.
_NO_AUTH_ROLE = "admin"
_NO_AUTH_ACTOR_ID = "no-auth"


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
    При **TAKT_AUTH_REQUIRED=false** без ключа — доступ открыт; если ключи заданы
    (**TAKT_API_KEY**/**TAKT_API_KEYS**), поведение как раньше (опциональная защита
    для путей вне публичного списка).

    Ключ определяет `actor_id` и роль (`operator`/`auditor`/`admin`, см.
    `takt.infrastructure.security.api_keys`); после успешной аутентификации
    выполняется RBAC-проверка по методу и пути (`takt.infrastructure.security.rbac`).

    Публичные пути: **`/health`**, **`/live`**, **`/ready`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`**.
    Ошибка аутентификации: **401 Unauthorized**. Ошибка авторизации (роль не подходит): **403 Forbidden**.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if _is_public_path(path):
            return await call_next(request)

        entries = api_key_entries_from_env()
        required_mode = takt_auth_required_from_env()
        got = _extract_key(request)
        matched: ApiKeyEntry | None = resolve_api_key(entries, got) if got else None

        if required_mode or entries:
            if matched is None:
                return JSONResponse(
                    error_json_content("missing or invalid API key", request),
                    status_code=401,
                )
        else:
            # Ни один ключ не настроен и строгий режим выключен: аутентификации нет вовсе.
            matched = ApiKeyEntry(key="", actor_id=_NO_AUTH_ACTOR_ID, role=_NO_AUTH_ROLE)

        request.state.takt_actor_id = matched.actor_id
        request.state.takt_role = matched.role

        required_role = required_role_for_route(request.method, path)
        if not role_satisfies(matched.role, required_role):
            return JSONResponse(
                error_json_content(f"role '{matched.role}' is not allowed for this operation", request),
                status_code=403,
            )

        return await call_next(request)
