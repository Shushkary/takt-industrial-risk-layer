from __future__ import annotations

from pathlib import Path

import pytest

from takt.infrastructure.config.settings_helpers import sqlite_storage_db_path


def test_sqlite_storage_db_path_uses_takt_sqlite_path_env(tmp_path: Path, monkeypatch) -> None:
    env_db = tmp_path / "from_env.db"
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(env_db))
    weights = {"storage": {"backend": "sqlite", "sqlite_path": "data/ignored.db"}}
    p = sqlite_storage_db_path(weights, project_root=tmp_path)
    assert p == env_db.resolve()


def test_sqlite_storage_db_path_env_only_when_backend_sqlite(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(tmp_path / "x.db"))
    weights = {"storage": {"backend": "memory"}}
    assert sqlite_storage_db_path(weights, project_root=tmp_path) is None


def test_sqlite_storage_db_path_none_when_storage_not_dict(tmp_path: Path) -> None:
    assert sqlite_storage_db_path({"storage": "sqlite"}, project_root=tmp_path) is None


def test_sqlite_storage_db_path_rejects_paths_outside_project(tmp_path: Path, monkeypatch) -> None:
    outside = Path(Path(__file__).anchor) / "takt-outside.db"
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(outside))
    weights = {"storage": {"backend": "sqlite", "sqlite_path": "data/ignored.db"}}
    with pytest.raises(ValueError, match="project root"):
        sqlite_storage_db_path(weights, project_root=tmp_path)
