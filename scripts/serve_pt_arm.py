"""Локальный стенд АРМ: раздача `frontend/takt-pt-arm` и прокси `/api/*` на backend.

Заменяет nginx на машине разработчика. На боевом контуре статику раздаёт nginx по
`frontend/takt-pt-arm/nginx.takt-pt-arm.conf`; там АРМ живёт на подпути `/takt_pt_arm/`, а
`/takt_pt_arm/api/` проксируется на backend, поднятый с префиксом `/api`. Локальный backend
поднимается без префикса, поэтому здесь префикс снимается — см. `backend_url`.

Запуск (из корня репозитория):

    python -m scripts.serve_pt_arm

Backend поднимается отдельно, командой из README и docs/pt_techlab/analyst_window.md.
Сервер намеренно однофайловый и без зависимостей: он нужен, чтобы стенд поднимался из
репозитория одной командой, а не воспроизводился по памяти при каждой проверке.
"""

from __future__ import annotations

import argparse
import http.server
import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARM_ROOT = _ROOT / "frontend" / "takt-pt-arm"
DEFAULT_PORT = 8091
DEFAULT_API_BASE = "http://127.0.0.1:8090"
API_PREFIX = "/api"
# Заголовки, которые имеет смысл пронести к backend. Остальные (Host, Connection,
# Content-Length) пересобирает urllib, а лишние ломают запрос.
_FORWARDED_HEADERS = (
    "Content-Type",
    "Accept",
    "Authorization",
    "X-TAKT-API-Key",
    "X-Request-Id",
    "Idempotency-Key",
)
# Заголовки ответа, которые АРМ читает сам. Молча потерянный `X-Total-Count` выглядит не как
# ошибка прокси, а как «счётчик очереди показывает не то»: в счётчике пропадает общее число дел.
_RELAYED_RESPONSE_HEADERS = ("X-Total-Count", "X-Request-ID")
_PROXY_TIMEOUT_SEC = 30.0


def backend_url(path: str, *, api_base: str, api_prefix: str = API_PREFIX) -> str | None:
    """URL backend для запроса АРМ или None, если запрос надо отдать статикой.

    Граница проходит по сегменту пути, а не по префиксу строки: `/apiary.html` — статика,
    `/api/cases` — прокси. Префикс снимается, потому что локальный backend поднят без него;
    `/api` и `/api/` попадают в корень backend.
    """
    if path != api_prefix and not path.startswith(api_prefix + "/") and not path.startswith(api_prefix + "?"):
        return None
    rest = path[len(api_prefix) :]
    if not rest.startswith("/") and not rest.startswith("?"):
        rest = "/" + rest
    if rest.startswith("?"):
        rest = "/" + rest
    return api_base.rstrip("/") + rest


def build_server(*, root: Path, port: int, api_base: str) -> http.server.ThreadingHTTPServer:
    """HTTP-сервер стенда. `port=0` — свободный порт (используется тестами)."""
    directory = str(root)

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=directory, **kwargs)  # type: ignore[arg-type]

        def _proxy(self, method: str) -> None:
            target = backend_url(self.path, api_base=api_base)
            assert target is not None  # вызывается только когда backend_url вернул адрес
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            request = urllib.request.Request(target, data=body, method=method)
            for name in _FORWARDED_HEADERS:
                value = self.headers.get(name)
                if value:
                    request.add_header(name, value)
            try:
                with urllib.request.urlopen(request, timeout=_PROXY_TIMEOUT_SEC) as response:
                    self._relay(
                        response.status,
                        response.headers.get("Content-Type"),
                        response.read(),
                        extra=response.headers,
                    )
            except urllib.error.HTTPError as err:
                # Ошибку backend АРМ должен увидеть как есть: коды 4xx он разбирает сам.
                self._relay(
                    err.code,
                    err.headers.get("Content-Type") if err.headers else None,
                    err.read(),
                    extra=err.headers,
                )
            except OSError as err:
                # Backend стенда часто не поднят. Молчание выглядит как зависший АРМ, поэтому
                # ответ явный и машиночитаемый.
                payload = json.dumps(
                    {"error": "backend_unreachable", "backend": api_base, "detail": str(err)},
                    ensure_ascii=False,
                ).encode("utf-8")
                self._relay(502, "application/json; charset=utf-8", payload)

        def _relay(
            self,
            status: int,
            content_type: str | None,
            payload: bytes,
            extra: Message | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type or "application/json")
            self.send_header("Content-Length", str(len(payload)))
            for name in _RELAYED_RESPONSE_HEADERS:
                value = extra.get(name) if extra else None
                if value:
                    self.send_header(name, value)
            # Сборка АРМ кэшируется агрессивно; на стенде это скрывает свежие правки.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            if backend_url(self.path, api_base=api_base) is None:
                super().do_GET()
            else:
                self._proxy("GET")

        def do_HEAD(self) -> None:
            if backend_url(self.path, api_base=api_base) is None:
                super().do_HEAD()
            else:
                self._proxy("HEAD")

        def do_POST(self) -> None:
            self._proxy_or_405("POST")

        def do_PUT(self) -> None:
            self._proxy_or_405("PUT")

        def do_PATCH(self) -> None:
            self._proxy_or_405("PATCH")

        def do_DELETE(self) -> None:
            self._proxy_or_405("DELETE")

        def _proxy_or_405(self, method: str) -> None:
            if backend_url(self.path, api_base=api_base) is None:
                self.send_error(405, "method allowed only for /api")
            else:
                self._proxy(method)

        def end_headers(self) -> None:
            if backend_url(self.path, api_base=api_base) is None:
                self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            """Тишина по умолчанию: стенд поднимают, чтобы смотреть в АРМ, а не в консоль."""

    return http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Локальный стенд АРМ takt-pt-arm")
    parser.add_argument("--root", type=Path, default=DEFAULT_ARM_ROOT, help="каталог со сборкой АРМ")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="порт стенда")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help="адрес backend, куда идёт /api/*")
    args = parser.parse_args(argv)

    if not (args.root / "index.html").is_file():
        parser.error(f"в {args.root} нет index.html — АРМ не собран или указан не тот каталог")
    if not (args.root / "app.min.js").is_file():
        parser.error(
            f"в {args.root} нет app.min.js: index.html подключает сборку, а не исходник. "
            "Собери — `node build-production.mjs` в каталоге АРМ"
        )

    server = build_server(root=args.root, port=args.port, api_base=args.api_base)
    # Адрес берётся не из server_address: там он объявлен как произвольный, а привязка
    # всегда к петле — стенд наружу не выставляется.
    print(f"АРМ:     http://127.0.0.1:{int(server.server_address[1])}/")
    print(f"/api/* -> {args.api_base}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("остановлен")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
