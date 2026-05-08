from __future__ import annotations

import tomllib
from pathlib import Path

from takt import __version__


def test_package_version_matches_pyproject() -> None:
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == data["project"]["version"]
