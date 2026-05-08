from __future__ import annotations

import pytest

from takt.infrastructure.http.request_id_middleware import (
    request_id_alternate_header_from_env,
    request_id_incoming_header_names,
)


def test_request_id_incoming_names_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_REQUEST_ID_HEADER", raising=False)
    assert request_id_incoming_header_names() == ("x-request-id",)


def test_request_id_incoming_names_custom_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Correlation-ID")
    assert request_id_incoming_header_names() == ("x-correlation-id", "x-request-id")


def test_request_id_incoming_names_invalid_env_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "not valid!")
    assert request_id_incoming_header_names() == ("x-request-id",)


def test_request_id_incoming_names_too_long_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "H" * 65)
    assert request_id_incoming_header_names() == ("x-request-id",)


def test_request_id_alternate_header_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAKT_REQUEST_ID_HEADER", raising=False)
    assert request_id_alternate_header_from_env() is None


def test_request_id_alternate_header_none_when_duplicate_x_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_REQUEST_ID_HEADER", "X-Request-ID")
    assert request_id_alternate_header_from_env() is None
