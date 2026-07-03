from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MiddlewareErrorJson(BaseModel):
    """JSON body for HTTP middleware error responses."""

    detail: str = Field(..., description="Short refusal reason.")
    request_id: str | None = Field(
        None,
        description="Request identifier; matches X-Request-ID when provided or generated.",
    )


MIDDLEWARE_ERROR_OPENAPI: dict[int | str, dict[str, Any]] = {
    401: {
        "description": (
            "Unauthorized: when authentication is active, the X-TAKT-API-Key or Authorization: Bearer value is missing "
            "or invalid. X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
    411: {
        "description": (
            "Length Required: POST/PUT/PATCH with Transfer-Encoding: chunked requires Content-Length. "
            "X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
    413: {
        "description": (
            "Payload Too Large: request body exceeds the configured TAKT_MAX_REQUEST_BODY_MB limit. "
            "X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
    429: {
        "description": (
            "Too Many Requests: in-memory TAKT_RATE_LIMIT_PER_MIN limit exceeded. Retry-After, X-RateLimit-*, "
            "X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
}
