from __future__ import annotations

import logging
import os
import socket
import sys

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_startup_log_includes_build_revision_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("TAKT_BUILD_REVISION", "ci-abc")
    caplog.set_level(logging.INFO, logger="takt.api")
    create_app()
    assert any(
        "TAKT API ready" in r.message
        and "build_revision=ci-abc" in r.message
        and "python=" in r.message
        and sys.implementation.name in r.message
        and f"pid={os.getpid()}" in r.message
        and socket.gethostname() in r.message
        and f"platform={sys.platform}" in r.message
        and sys.executable in r.message
        and os.getcwd() in r.message
        for r in caplog.records
    )


def test_startup_log_omits_build_revision_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("TAKT_BUILD_REVISION", raising=False)
    caplog.set_level(logging.INFO, logger="takt.api")
    create_app()
    ready = [r for r in caplog.records if "TAKT API ready" in r.message]
    assert len(ready) == 1
    assert "build_revision" not in ready[0].message
    assert "python=" in ready[0].message
    assert sys.implementation.name in ready[0].message
    assert f"pid={os.getpid()}" in ready[0].message
    assert socket.gethostname() in ready[0].message
    assert f"platform={sys.platform}" in ready[0].message
    assert sys.executable in ready[0].message
    assert os.getcwd() in ready[0].message


def test_lifespan_shutdown_logs_info(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="takt.api")
    with TestClient(create_app()) as client:
        assert client.get("/live").status_code == 200
    assert any(
        "TAKT API shutdown" in r.message
        and "python=" in r.message
        and sys.implementation.name in r.message
        and f"pid={os.getpid()}" in r.message
        and socket.gethostname() in r.message
        and f"platform={sys.platform}" in r.message
        and sys.executable in r.message
        and os.getcwd() in r.message
        for r in caplog.records
    )
