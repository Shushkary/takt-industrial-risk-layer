"""Единый формат ошибок RFC 9457 (application/problem+json).

Поля ответа: ``type``, ``title``, ``status``, ``detail``, ``instance``. Единый
обработчик приводит и ``HTTPException`` FastAPI, и доменные ошибки к одному виду.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

PROBLEM_CONTENT_TYPE = "application/problem+json"
_PROBLEM_BASE_URI = "https://takt.example/problems"


class ProblemException(Exception):
    """Доменная/прикладная ошибка, транслируемая в RFC 9457."""

    def __init__(
        self,
        *,
        status: int,
        title: str,
        detail: str = "",
        type_suffix: str = "about:blank",
    ) -> None:
        super().__init__(detail or title)
        self.status = status
        self.title = title
        self.detail = detail
        self.type_suffix = type_suffix


def _problem_type(suffix: str) -> str:
    if suffix == "about:blank" or suffix.startswith("http"):
        return suffix
    return f"{_PROBLEM_BASE_URI}/{suffix}"


def problem_response(
    *, status: int, title: str, detail: str, instance: str, type_suffix: str = "about:blank"
) -> JSONResponse:
    """Собрать ответ problem+json."""
    body = {
        "type": _problem_type(type_suffix),
        "title": title,
        "status": status,
        "detail": detail,
        "instance": instance,
    }
    return JSONResponse(status_code=status, content=body, media_type=PROBLEM_CONTENT_TYPE)


_TITLES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
}


def register_problem_handlers(app: FastAPI) -> None:
    """Зарегистрировать обработчики RFC 9457 на sub-app ``/api/v1``.

    Обработчики изолированы в примонтированном под-приложении, поэтому остальной
    API сохраняет прежний формат ошибок (полная обратная совместимость).
    """

    @app.exception_handler(ProblemException)
    async def _handle_problem(request: Request, exc: ProblemException) -> JSONResponse:
        return problem_response(
            status=exc.status,
            title=exc.title,
            detail=exc.detail,
            instance=request.url.path,
            type_suffix=exc.type_suffix,
        )

    @app.exception_handler(HTTPException)
    async def _handle_http(request: Request, exc: HTTPException) -> JSONResponse:
        title = _TITLES.get(exc.status_code, "Error")
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return problem_response(
            status=exc.status_code,
            title=title,
            detail=detail,
            instance=request.url.path,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            status=422,
            title=_TITLES[422],
            detail="; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()),
            instance=request.url.path,
            type_suffix="validation-error",
        )
