from __future__ import annotations

import os
import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_HEADER_DEFAULT = "x-request-id"
_MAX_HEADER_NAME_LEN = 64


def _valid_request_id_header_name(raw: str) -> bool:
    return bool(
        raw
        and len(raw) <= _MAX_HEADER_NAME_LEN
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", raw)
    )


def request_id_incoming_header_names() -> tuple[str, ...]:
    """Имена входящих заголовков по приоритету (для **Request.headers**, сравнение без учёта регистра)."""
    raw = os.environ.get("TAKT_REQUEST_ID_HEADER", "").strip()
    names: list[str] = []
    if raw and _valid_request_id_header_name(raw):
        names.append(raw.lower())
    if _HEADER_DEFAULT not in names:
        names.append(_HEADER_DEFAULT)
    return tuple(names)


def request_id_alternate_header_from_env() -> str | None:
    """Для **`GET /health`**: непустая **`TAKT_REQUEST_ID_HEADER`**, если она валидна и не дублирует **`X-Request-ID`**."""
    raw = os.environ.get("TAKT_REQUEST_ID_HEADER", "").strip()
    if not raw or not _valid_request_id_header_name(raw):
        return None
    if raw.lower() == _HEADER_DEFAULT:
        return None
    return raw


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Прокидывает или генерирует **X-Request-ID** (в ответе и `request.state`)."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = ""
        for name in request_id_incoming_header_names():
            rid = request.headers.get(name, "").strip()
            if rid:
                break
        if not rid:
            rid = str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response
