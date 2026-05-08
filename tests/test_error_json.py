from __future__ import annotations

from starlette.requests import Request

from takt.infrastructure.http.error_json import error_json_content


def test_error_json_includes_request_id_when_present() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "headers": [],
        "scheme": "http",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("t", 80),
    }
    req = Request(scope)
    req.state.request_id = "rid-test"
    assert error_json_content("oops", req) == {"detail": "oops", "request_id": "rid-test"}


def test_error_json_detail_only_without_request_id() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": [],
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("t", 80),
    }
    req = Request(scope)
    assert error_json_content("x", req) == {"detail": "x"}


def test_error_json_omits_blank_request_id() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": [],
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("t", 80),
    }
    req = Request(scope)
    req.state.request_id = "   "
    assert error_json_content("bad", req) == {"detail": "bad"}


def test_error_json_ignores_non_string_request_id() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": [],
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("t", 80),
    }
    req = Request(scope)
    req.state.request_id = 12345
    assert error_json_content("no", req) == {"detail": "no"}
