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


# Отказы самого приложения, возможные на любой операции. Держатся отдельно от
# `MIDDLEWARE_ERROR_OPENAPI`, чтобы не размывать его смысл: там — то, что отдаёт слой
# посредников до роутера, здесь — то, что отдаёт сам обработчик.
#
# Появились после прогона schemathesis: гвард сообщал «Undocumented HTTP status code» на
# 33 операциях для 400 и на 28 для 404. Коды отдавались всегда, в схеме их не было — то есть
# клиент, сгенерированный по схеме, не знал об отказах, которые обязан уметь разбирать.
APP_ERROR_OPENAPI: dict[int | str, dict[str, Any]] = {
    400: {
        "description": (
            "Bad Request: the operation refused the request — malformed query or path value, "
            "an unparsable filter, or a body the handler rejected before validation. "
            "X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
    404: {
        "description": (
            "Not Found: the addressed resource does not exist — an unknown case, engagement, "
            "event or artifact identifier. X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
}


# Наборы для отдельных маршрутов — то, что отдают конкретные обработчики, а не приложение
# целиком. Держатся здесь, чтобы описание кода жило в одном месте, а не расползалось по
# роутерам разными формулировками.

# Приём читает тело сырым (`request: Request`), схемы тела в сигнатуре нет — и FastAPI не
# добавляет 422 автоматически, хотя обработчик его отдаёт при невалидном JSON.
RAW_BODY_VALIDATION_OPENAPI: dict[int | str, dict[str, Any]] = {
    422: {
        "description": (
            "Unprocessable Entity: the request body is not valid JSON or does not match the "
            "expected document. The report lists error type, field path and message; the raw "
            "body is not echoed back. X-Request-ID, X-Process-Time."
        ),
    },
}

CONFLICT_OPENAPI: dict[int | str, dict[str, Any]] = {
    409: {
        "description": (
            "Conflict: the case is in a state that does not allow the operation — assembly is "
            "already running, or the case has no events to work with. X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
}

# Журнал с хэш-цепочкой живёт в SQLite. При `TAKT_STORAGE=memory` возможности нет вовсе, и
# отказ объявляется кодом 501: это не сбой, а отсутствие функциональности в этой конфигурации.
NOT_IMPLEMENTED_OPENAPI: dict[int | str, dict[str, Any]] = {
    501: {
        "description": (
            "Not Implemented: the append-only ledger requires the SQLite storage backend and is "
            "unavailable while TAKT_STORAGE=memory. X-Request-ID, X-Process-Time."
        ),
        "model": MiddlewareErrorJson,
    },
}


# Правка весов отказывает текстом нарушенного правила, а не списком ошибок валидации:
# «сумма весов должна равняться 1.000, получено 2.907». Форма ответа другая, чем у
# автоматического 422 FastAPI, и описывать её нужно отдельно, иначе клиент по схеме ждёт массив.
class WeightsRewriteErrorJson(BaseModel):
    """Отказ правки весов: у 422 на этом маршруте две формы, и обе настоящие.

    Строка — нарушено правило конфигурации («сумма весов должна равняться 1.000, получено
    2.907»). Список — обычный отчёт валидации тела, который отдаёт FastAPI. Описывать только
    одну из них нельзя: клиент по схеме готовится к одной форме и спотыкается о другую.
    """

    detail: str | list[dict[str, Any]] = Field(
        ...,
        description="Violated configuration rule, or the field-level validation report.",
    )
    request_id: str | None = Field(
        None,
        description="Request identifier; matches X-Request-ID when provided or generated.",
    )


WEIGHTS_REWRITE_OPENAPI: dict[int | str, dict[str, Any]] = {
    422: {
        "description": (
            "Unprocessable Entity: the submitted weights or thresholds violate a rule of the "
            "configuration — for example the factor weights do not sum to 1.000 — or the body "
            "itself failed validation. X-Request-ID, X-Process-Time."
        ),
        "model": WeightsRewriteErrorJson,
    },
}
