"""Монтирование surface ``/api/v1`` в основное приложение FastAPI.

Стратегия — изолированное под-приложение (sub-app), примонтированное по пути
``/api/v1``. Такой приём даёт версии API собственные обработчики ошибок
(RFC 9457) и роутеры, не затрагивая корневое приложение: существующие маршруты
и прежний формат ошибок остаются без изменений (полная обратная совместимость).

Starlette пробрасывает ``scope["state"]`` через границу mount, поэтому
``request.state.takt_role`` / ``takt_actor_id``, выставленные middleware
корневого приложения, доступны и внутри под-приложения (RBAC работает сквозно).
"""

from __future__ import annotations

from fastapi import FastAPI

from takt.interface_adapters.api.v1.context import SocApiContext
from takt.interface_adapters.api.v1.problem import register_problem_handlers
from takt.interface_adapters.api.v1.routers import build_router

_MOUNT_PATH = "/api/v1"


def build_subapp(*, sqlite_path: str | None = None) -> FastAPI:
    """Собрать изолированное под-приложение ``/api/v1``.

    :param sqlite_path: путь к SQLite для dead-letter стора; ``None`` — хранение
        в памяти (безопасно для тестов и не требует внешнего состояния).
    """
    ctx = SocApiContext(sqlite_path=sqlite_path)
    subapp = FastAPI(
        title="TAKT SOC API v1",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # Ссылку на контекст храним на приложении — удобно для тестов и доступа к брокеру.
    subapp.state.soc_ctx = ctx
    register_problem_handlers(subapp)
    subapp.include_router(build_router(ctx))
    return subapp


def register_v1(app: FastAPI, *, sqlite_path: str | None = None) -> FastAPI:
    """Примонтировать surface ``/api/v1`` к корневому приложению.

    Возвращает собранное под-приложение (полезно в тестах для доступа к брокеру
    SSE и контексту зависимостей).
    """
    subapp = build_subapp(sqlite_path=sqlite_path)
    app.mount(_MOUNT_PATH, subapp)
    return subapp
