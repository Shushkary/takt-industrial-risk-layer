from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from uuid import uuid4

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("HYPOTHESIS_STORAGE_DIRECTORY", str(_PROJECT_ROOT / ".pytest_tmp_path_local" / "hypothesis"))

import pytest
from hypothesis import settings

settings.register_profile("no_disk_examples", database=None)
settings.load_profile("no_disk_examples")


@pytest.fixture(autouse=True)
def _takt_tests_relax_default_strict_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """В тестах по умолчанию отключаем fail-closed (**TAKT_AUTH_REQUIRED**), чтобы не задавать ключ в каждом файле."""
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "false")


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Path:
    """Windows-safe tmp_path replacement for locked pytest temp roots."""
    root = Path(__file__).resolve().parents[1] / ".pytest_tmp_path_local"
    root.mkdir(exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.nodeid)[-120:]
    path = root / f"{safe_name}-{uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        try:
            root.rmdir()
        except OSError:
            pass
