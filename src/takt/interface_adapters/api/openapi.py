from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

OPENAPI_PUBLIC_PATHS: frozenset[str] = frozenset({"/health", "/live", "/ready", "/openapi.json", "/metrics"})
OPENAPI_PUBLIC_PREFIXES: tuple[str, ...] = ("/docs", "/redoc")


def is_openapi_public_path(path: str) -> bool:
    if path in OPENAPI_PUBLIC_PATHS:
        return True
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in OPENAPI_PUBLIC_PREFIXES)


def openapi_api_key_configured() -> bool:
    return bool(os.environ.get("TAKT_API_KEY", "").strip())


def openapi_server_entries_from_env(*, logger: logging.Logger | None = None) -> list[dict[str, str]]:
    raw = os.environ.get("TAKT_OPENAPI_SERVER_URL", "").strip()
    if not raw:
        return []
    entries: list[dict[str, str]] = []
    for part in (p.strip() for p in raw.split(",") if p.strip()):
        url = part.rstrip("/")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            if logger is not None:
                logger.warning("TAKT_OPENAPI_SERVER_URL entry %r ignored (scheme must be http or https)", part)
            continue
        if not parsed.netloc:
            if logger is not None:
                logger.warning("TAKT_OPENAPI_SERVER_URL entry %r ignored (missing host)", part)
            continue
        entries.append({"url": url, "description": "From TAKT_OPENAPI_SERVER_URL"})
    return entries


def patch_openapi_servers(schema: dict[str, Any], *, logger: logging.Logger | None = None) -> None:
    entries = openapi_server_entries_from_env(logger=logger)
    if entries:
        schema["servers"] = entries


def patch_openapi_with_takt_api_key(schema: dict[str, Any]) -> None:
    components = schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["TaktApiKey"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-TAKT-API-Key",
        "description": (
            "Тот же ключ можно передать как Authorization: Bearer. "
            "Нужен для путей, не относящихся к /health, /live, /ready, /metrics, /openapi.json и UI /docs, /redoc, "
            "если задана переменная окружения TAKT_API_KEY."
        ),
    }
    if not openapi_api_key_configured():
        return
    http_methods = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
    req: dict[str, list[str]] = {"TaktApiKey": []}
    for path_key, path_item in schema.get("paths", {}).items():
        if is_openapi_public_path(path_key):
            continue
        for method, operation in path_item.items():
            if method.lower() not in http_methods or not isinstance(operation, dict):
                continue
            sec = operation.setdefault("security", [])
            if req not in sec:
                sec.append(req)


def attach_custom_openapi(app: FastAPI, *, logger: logging.Logger | None = None) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            routes=app.routes,
        )
        patch_openapi_servers(openapi_schema, logger=logger)
        patch_openapi_with_takt_api_key(openapi_schema)
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    # Подмена метода — штатный приём FastAPI для собственной схемы (см. Custom OpenAPI в
    # документации). Проверке типов присваивание метода экземпляру запрещено, здесь оно
    # намеренное и единственное.
    app.openapi = custom_openapi  # type: ignore[method-assign]
