from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _project_local_path(path: Path, *, label: str) -> Path:
    root = _PROJECT_ROOT.resolve()
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under project root: {root}") from exc
    return resolved


def backup(src: Path, output: Path) -> int:
    """Create a consistent SQLite backup using sqlite3.Connection.backup()."""
    src = _project_local_path(src, label="--src")
    output = _project_local_path(output, label="--output")
    output.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(src)) as source_conn, sqlite3.connect(str(output)) as dest_conn:
        source_conn.backup(dest_conn)
    print(f"backup_created={output}")
    return 0


def _default_source_from_env() -> Path | None:
    raw = os.environ.get("TAKT_SQLITE_PATH", "").strip()
    if not raw:
        return None
    return _project_local_path(Path(raw), label="TAKT_SQLITE_PATH")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create SQLite backup for TAKT case store.")
    parser.add_argument("--output", required=True, help="Path to destination backup SQLite DB.")
    parser.add_argument(
        "--src",
        default="",
        help="Path to source SQLite DB. Defaults to TAKT_SQLITE_PATH when omitted.",
    )
    args = parser.parse_args()
    src = _project_local_path(Path(args.src), label="--src") if args.src else _default_source_from_env()
    if src is None:
        parser.error("--src is required when TAKT_SQLITE_PATH is not set")
    return backup(src, Path(args.output))


if __name__ == "__main__":
    raise SystemExit(main())
