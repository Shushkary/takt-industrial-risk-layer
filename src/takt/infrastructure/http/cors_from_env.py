from __future__ import annotations

import os

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


def add_cors_middleware_if_configured(app: FastAPI) -> None:
    """
    Если задана **TAKT_CORS_ORIGINS** (список через запятую; один элемент `*` — все источники),
    добавляет CORS. Регистрируйте **последним**, чтобы обёртка была внешней.
    """
    raw = os.environ.get("TAKT_CORS_ORIGINS", "").strip()
    if not raw:
        return
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return
    allow_all = parts == ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if allow_all else parts,
        allow_credentials=not allow_all,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-ID",
            "X-Process-Time",
            "X-Total-Count",
            "Link",
            "Cache-Control",
            "Retry-After",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ],
    )


def cors_middleware_enabled_from_env() -> bool:
    """`True`, если по **`TAKT_CORS_ORIGINS`** в приложение будет добавлен **CORS** (непустой список origin)."""
    raw = os.environ.get("TAKT_CORS_ORIGINS", "").strip()
    if not raw:
        return False
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return bool(parts)
