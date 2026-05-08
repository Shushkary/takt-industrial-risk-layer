from __future__ import annotations

import pytest

from takt.infrastructure.http.security_headers import _strict_transport_security


def test_strict_transport_security_invalid_env_not_int(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_HSTS_MAX_AGE", "not-an-int")
    assert _strict_transport_security() is None


def test_strict_transport_security_non_positive_max_age(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_HSTS_MAX_AGE", "0")
    assert _strict_transport_security() is None
