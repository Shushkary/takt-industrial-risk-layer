#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _project_local_path(path: Path, *, label: str) -> Path:
    root = ROOT.resolve()
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under project root: {root}") from exc
    return resolved


def backup(src: Path, dst: Path) -> int:
    src = _project_local_path(src, label="--src")
    dst = _project_local_path(dst, label="--dst")
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(src)) as source_conn, sqlite3.connect(str(dst)) as dest_conn:
        source_conn.backup(dest_conn)
    print(f"backup_created={dst}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create SQLite backup for TAKT case store.")
    parser.add_argument("--src", required=True, help="Path to source SQLite DB.")
    parser.add_argument("--dst", required=True, help="Path to destination backup DB.")
    args = parser.parse_args()
    return backup(Path(args.src), Path(args.dst))


if __name__ == "__main__":
    raise SystemExit(main())
