"""Заголовок `Allow` в ответе 405 перечисляет все методы пути, а не методы одного маршрута.

Методы одного и того же пути объявляются в проекте раздельно — `@app.get("/config/risk-weights")`
и `@app.put("/config/risk-weights")` создают два независимых маршрута. Starlette, отвечая 405,
берёт первый совпавший по пути маршрут и перечисляет только **его** методы: на
`/config/risk-weights` в заголовке оказывался `GET`, хотя `PUT` объявлен и работает.

Клиент, который читает `Allow`, чтобы понять, чем пользоваться, получал неполный ответ и не
узнавал о половине интерфейса. RFC 9110 §10.2.1 требует перечислить методы, поддерживаемые
**целевым ресурсом**, а ресурс здесь — путь целиком.

Прогон schemathesis сообщал об этом как «Invalid Allow header — missing documented methods»
на пяти путях: `/config/risk-weights`, `/audit-engagements`, `/cases/{case_id}/artifacts`,
`/cases/{case_id}/findings`, `/cases/{case_id}/summary`.

Посредник не меняет код ответа и не трогает ничего, кроме заголовка у 405.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match


class AllowHeaderMiddleware(BaseHTTPMiddleware):
    """Дособирает `Allow` у ответа 405 по всем маршрутам, совпавшим с путём запроса.

    Приложение берётся из области запроса, а не из конструктора: `add_middleware` передаёт
    в конструктор следующий слой ASGI, а не объект FastAPI, и обращение к его маршрутам
    закончилось бы ошибкой на первом же запросе.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        if response.status_code != 405:
            return response

        methods = self._methods_for(request)
        if methods:
            response.headers["allow"] = ", ".join(methods)
        return response

    def _methods_for(self, request: Request) -> list[str]:
        """Объединение методов всех маршрутов, чей шаблон совпал с путём запроса.

        Совпадение проверяется штатным `route.matches`: он учитывает параметры пути, поэтому
        `/cases/{case_id}/findings` находится и для конкретного идентификатора. Сопоставление
        по методу здесь не нужно — интересен как раз полный их набор.
        """
        app = request.scope.get("app")
        routes = getattr(app, "routes", None)
        if not routes:
            return []

        found: set[str] = set()
        for route in routes:
            matcher = getattr(route, "matches", None)
            if matcher is None:
                continue
            match, _ = matcher(request.scope)
            if match is Match.NONE:
                continue
            found.update(getattr(route, "methods", None) or ())
        # HEAD отдаётся Starlette автоматически вместе с GET; в перечень он попадает только
        # если объявлен маршрутом, поэтому добавляется здесь, а не додумывается клиентом.
        if "GET" in found:
            found.add("HEAD")
        return sorted(found)
