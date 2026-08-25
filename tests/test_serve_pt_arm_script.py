"""Локальный сервер АРМ: граница между статикой и проксированием.

Сервер заменяет nginx на машине разработчика: раздаёт `frontend/takt-pt-arm` и проксирует
`/api/*` на backend. Проверяется то, что легко сломать незаметно, — где проходит граница
между статикой и прокси, снимается ли префикс и что происходит, когда backend не поднят.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "serve_pt_arm.py"
_API = "http://127.0.0.1:8090"


def _load_script():
    spec = importlib.util.spec_from_file_location("serve_pt_arm_script", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


serve_pt_arm = _load_script()


def _closed_port() -> int:
    """Порт, который точно никто не слушает: занимаем и сразу отпускаем."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.parametrize(
    ("path", "want"),
    [
        ("/api/cases", f"{_API}/cases"),
        ("/api/cases/INC-002", f"{_API}/cases/INC-002"),
        ("/api/cases?limit=5&sort=risk_score_desc", f"{_API}/cases?limit=5&sort=risk_score_desc"),
        ("/api", f"{_API}/"),
        ("/api/", f"{_API}/"),
    ],
)
def test_api_paths_are_proxied_with_prefix_stripped(path: str, want: str) -> None:
    """Префикс снимается: backend стенда живёт без /api, префикс есть только у nginx снаружи."""
    assert serve_pt_arm.backend_url(path, api_base=_API) == want


@pytest.mark.parametrize(
    "path",
    ["/", "/index.html", "/app.min.js", "/styles.min.css", "/apiary.html", "/apis/list"],
)
def test_non_api_paths_stay_static(path: str) -> None:
    """Граница проходит по сегменту пути, а не по префиксу строки: /apiary.html — статика."""
    assert serve_pt_arm.backend_url(path, api_base=_API) is None


def test_trailing_slash_in_api_base_does_not_double() -> None:
    assert serve_pt_arm.backend_url("/api/cases", api_base=f"{_API}/") == f"{_API}/cases"


@pytest.fixture
def arm_root(tmp_path: Path) -> Path:
    root = tmp_path / "arm"
    root.mkdir()
    (root / "index.html").write_text("<title>АРМ</title>", encoding="utf-8")
    (root / "app.min.js").write_text("// сборка", encoding="utf-8")
    return root


@pytest.fixture
def running_server(arm_root: Path) -> Iterator[str]:
    """Сервер с заведомо недоступным backend: проверяется поведение стенда без него."""
    server = serve_pt_arm.build_server(
        root=arm_root,
        port=0,
        api_base=f"http://127.0.0.1:{_closed_port()}",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_static_files_are_served(running_server: str) -> None:
    with urllib.request.urlopen(f"{running_server}/index.html", timeout=5) as response:
        assert response.status == 200
        assert "АРМ" in response.read().decode("utf-8")


def test_root_serves_index(running_server: str) -> None:
    with urllib.request.urlopen(f"{running_server}/", timeout=5) as response:
        assert response.status == 200
        assert "АРМ" in response.read().decode("utf-8")


def test_unreachable_backend_answers_502_instead_of_hanging(running_server: str) -> None:
    """Backend стенда часто не поднят; АРМ должен получить внятный ответ, а не зависнуть."""
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(f"{running_server}/api/cases", timeout=10)

    assert err.value.code == 502
    assert json.loads(err.value.read())["error"] == "backend_unreachable"


def test_key_header_reaches_the_backend_and_total_count_comes_back(arm_root: Path) -> None:
    """Без этого заголовка стенд отвечал бы 401 на каждый запрос АРМ при включённой аутентификации.

    Проверяется именно проброс: список `_FORWARDED_HEADERS` — белый, и забытая в нём строка
    выглядит как «АРМ не умеет авторизоваться», а не как ошибка прокси.
    """
    import http.server

    seen: dict[str, str] = {}

    class _Backend(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.update({k.lower(): v for k, v in self.headers.items()})
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Total-Count", "282")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            """Тишина в выводе теста."""

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()

    stand = serve_pt_arm.build_server(
        root=arm_root,
        port=0,
        api_base=f"http://127.0.0.1:{backend.server_address[1]}",
    )
    stand_thread = threading.Thread(target=stand.serve_forever, daemon=True)
    stand_thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{stand.server_address[1]}/api/session",
            headers={"X-TAKT-API-Key": "stand-key-42"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            # Счётчик очереди читает общее число дел из этого заголовка: потерянный по дороге,
            # он выглядит как «АРМ показывает не то», а не как ошибка стенда.
            assert response.headers.get("X-Total-Count") == "282"
    finally:
        stand.shutdown()
        stand.server_close()
        stand_thread.join(timeout=5)
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=5)

    assert seen.get("x-takt-api-key") == "stand-key-42"
