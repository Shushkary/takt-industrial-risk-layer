#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run(package_dir: Path) -> int:
    manifest_path = package_dir / "manifest.json"
    if not manifest_path.is_file():
        print("release_package_verify=FAILED")
        print("reason=manifest.json missing")
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    included = manifest.get("included_files")
    checksums = manifest.get("sha256")
    if not isinstance(included, list) or not included:
        print("release_package_verify=FAILED")
        print("reason=manifest.included_files missing or empty")
        return 2
    if not isinstance(checksums, dict):
        print("release_package_verify=FAILED")
        print("reason=manifest.sha256 missing")
        return 2
    for name in included:
        if not isinstance(name, str) or not name:
            print("release_package_verify=FAILED")
            print("reason=manifest.included_files contains invalid entry")
            return 2
        fp = package_dir / name
        if not fp.is_file():
            print("release_package_verify=FAILED")
            print(f"reason=missing file {name}")
            return 2
        got = _sha256_file(fp)
        exp = str(checksums.get(name, ""))
        if got != exp:
            print("release_package_verify=FAILED")
            print(f"reason=checksum mismatch for {name}")
            return 2
    print("release_package_verify=OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify release package manifest and file checksums.")
    parser.add_argument("--package-dir", required=True, help="Path to release package directory.")
    args = parser.parse_args()
    return run(Path(args.package_dir).expanduser().resolve())


if __name__ == "__main__":
    raise SystemExit(main())
