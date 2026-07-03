from __future__ import annotations

import os
from pathlib import Path


def resolve_config_path(*, default_cfg: Path) -> Path:
    raw = os.environ.get("TAKT_CONFIG", "").strip()
    if not raw:
        return default_cfg
    return Path(raw).expanduser().resolve()


def ensure_explicit_takt_config_under_project(*, cfg_path: Path, project_root: Path) -> None:
    if not os.environ.get("TAKT_CONFIG", "").strip():
        return
    root_res = project_root.resolve()
    try:
        cfg_path.resolve().relative_to(root_res)
    except ValueError as exc:
        raise ValueError(f"TAKT_CONFIG must stay under project root: {root_res}") from exc


def invariant_catalog_dir_for_config(*, cfg_path: Path, default_cfg: Path) -> Path:
    sibling = cfg_path.parent / "invariants"
    if sibling.is_dir():
        return sibling
    return default_cfg.parent / "invariants"
