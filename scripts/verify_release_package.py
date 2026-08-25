#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import zipfile
from json import JSONDecodeError
from pathlib import Path

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UNIX_FILE_TYPE_MASK = 0o170000
_UNIX_SYMLINK_TYPE = 0o120000
_MAX_ZIP_FILES = 1000
_MAX_ZIP_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
_MAX_ZIP_COMPRESSION_RATIO = 100.0
_UTC_STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
_PACKAGE_DIR_NAME_RE = re.compile(r"^release-package-(\d{8}T\d{6}Z)$")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"{name} must be >= 1")
    return value


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be a number") from exc
    if value < 1.0:
        raise argparse.ArgumentTypeError(f"{name} must be >= 1.0")
    return value


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & _UNIX_FILE_TYPE_MASK) == _UNIX_SYMLINK_TYPE


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
    root_manifest = manifest_path.resolve()
    if not manifest_path.is_file():
        print("release_package_verify=FAILED")
        print("reason=manifest.json missing")
        return 2
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, JSONDecodeError) as exc:
        print("release_package_verify=FAILED")
        print(f"reason=manifest.json is not readable JSON: {exc.__class__.__name__}")
        return 2
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
    if manifest.get("status") != "READY":
        print("release_package_verify=FAILED")
        print("reason=manifest.status is not READY")
        return 2
    if any(not isinstance(name, str) or not name for name in included):
        print("release_package_verify=FAILED")
        print("reason=manifest.included_files contains invalid entry")
        return 2
    if any(Path(name).name != name for name in included):
        print("release_package_verify=FAILED")
        print("reason=manifest.included_files entries must be package-root filenames")
        return 2
    generated_at = manifest.get("generated_at_utc")
    if not isinstance(generated_at, str) or not _UTC_STAMP_RE.match(generated_at):
        print("release_package_verify=FAILED")
        print("reason=manifest.generated_at_utc is invalid")
        return 2
    package_dir_value = manifest.get("package_dir")
    if not isinstance(package_dir_value, str) or not package_dir_value.strip():
        print("release_package_verify=FAILED")
        print("reason=manifest.package_dir missing")
        return 2
    if Path(package_dir_value).is_absolute():
        print("release_package_verify=FAILED")
        print("reason=manifest.package_dir must be relative")
        return 2
    package_dir_name = Path(package_dir_value).name
    package_dir_match = _PACKAGE_DIR_NAME_RE.match(package_dir_name)
    if not package_dir_match:
        print("release_package_verify=FAILED")
        print("reason=manifest.package_dir is not a release-package timestamped path")
        return 2
    if package_dir_match.group(1) != generated_at:
        print("release_package_verify=FAILED")
        print("reason=manifest.package_dir timestamp does not match generated_at_utc")
        return 2
    evidence_file = manifest.get("evidence_file")
    prod_ready_file = manifest.get("prod_ready_file")
    if not isinstance(evidence_file, str) or not evidence_file:
        print("release_package_verify=FAILED")
        print("reason=manifest.evidence_file missing")
        return 2
    if not isinstance(prod_ready_file, str) or not prod_ready_file:
        print("release_package_verify=FAILED")
        print("reason=manifest.prod_ready_file missing")
        return 2
    if evidence_file == prod_ready_file:
        print("release_package_verify=FAILED")
        print("reason=manifest.evidence_file and prod_ready_file must be different")
        return 2
    for field_name, filename in (("evidence_file", evidence_file), ("prod_ready_file", prod_ready_file)):
        if Path(filename).name != filename:
            print("release_package_verify=FAILED")
            print(f"reason=manifest.{field_name} must be a package-root filename")
            return 2
    if len(set(included)) != len(included):
        print("release_package_verify=FAILED")
        print("reason=manifest.included_files contains duplicate entries")
        return 2
    if evidence_file not in included or prod_ready_file not in included:
        print("release_package_verify=FAILED")
        print("reason=manifest evidence/prod-ready files are not included")
        return 2
    symlinks = sorted(
        path.relative_to(package_dir).as_posix()
        for path in package_dir.rglob("*")
        if path.is_symlink()
    )
    if symlinks:
        print("release_package_verify=FAILED")
        print("reason=symlinks are not allowed in package:" + ",".join(symlinks))
        return 2
    actual_files = {
        path.relative_to(package_dir).as_posix()
        for path in package_dir.rglob("*")
        if path.is_file() and path.resolve() != root_manifest
    }
    expected_files = set(included)
    checksum_keys = set(checksums)
    if checksum_keys != expected_files:
        print("release_package_verify=FAILED")
        print("reason=manifest.sha256 keys do not match included_files")
        return 2
    invalid_digests = sorted(name for name, digest in checksums.items() if not isinstance(digest, str) or not _SHA256_RE.match(digest))
    if invalid_digests:
        print("release_package_verify=FAILED")
        print("reason=manifest.sha256 contains invalid digest for:" + ",".join(invalid_digests))
        return 2
    if actual_files != expected_files:
        unexpected = sorted(actual_files - expected_files)
        missing = sorted(expected_files - actual_files)
        print("release_package_verify=FAILED")
        if unexpected:
            print("reason=unexpected files in package:" + ",".join(unexpected))
        else:
            print("reason=manifest lists missing files:" + ",".join(missing))
        return 2
    for name in included:
        fp = (package_dir / name).resolve()
        try:
            fp.relative_to(package_dir.resolve())
        except ValueError:
            print("release_package_verify=FAILED")
            print(f"reason=manifest.included_files escapes package root: {name}")
            return 2
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


def _safe_extract_zip(
    package_zip: Path,
    target_dir: Path,
    *,
    max_files: int = _MAX_ZIP_FILES,
    max_uncompressed_bytes: int = _MAX_ZIP_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = _MAX_ZIP_COMPRESSION_RATIO,
) -> Path | None:
    try:
        with zipfile.ZipFile(package_zip) as zf:
            seen_entries: set[str] = set()
            file_count = 0
            total_uncompressed = 0
            for info in zf.infolist():
                name = info.filename
                if not name or name.endswith("/"):
                    continue
                file_count += 1
                if file_count > max_files:
                    print("release_package_verify=FAILED")
                    print(f"reason=zip contains too many files: {file_count}")
                    return None
                total_uncompressed += int(info.file_size)
                if total_uncompressed > max_uncompressed_bytes:
                    print("release_package_verify=FAILED")
                    print(f"reason=zip uncompressed size exceeds limit: {total_uncompressed}")
                    return None
                if info.file_size > 0 and info.compress_size == 0:
                    print("release_package_verify=FAILED")
                    print(f"reason=zip entry has zero compressed size: {name}")
                    return None
                if info.compress_size > 0 and (info.file_size / info.compress_size) > max_compression_ratio:
                    print("release_package_verify=FAILED")
                    print(f"reason=zip compression ratio exceeds limit: {name}")
                    return None
                if _zip_entry_is_symlink(info):
                    print("release_package_verify=FAILED")
                    print(f"reason=symlinks are not allowed in zip: {name}")
                    return None
                if name in seen_entries:
                    print("release_package_verify=FAILED")
                    print(f"reason=duplicate zip entry: {name}")
                    return None
                seen_entries.add(name)
                destination = (target_dir / name).resolve()
                try:
                    destination.relative_to(target_dir.resolve())
                except ValueError:
                    print("release_package_verify=FAILED")
                    print(f"reason=zip entry escapes package root: {name}")
                    return None
            zf.extractall(target_dir)
    except zipfile.BadZipFile:
        print("release_package_verify=FAILED")
        print("reason=invalid zip file")
        return None

    manifest_path = target_dir / "manifest.json"
    if not manifest_path.is_file():
        print("release_package_verify=FAILED")
        print("reason=zip manifest.json missing at archive root")
        return None
    return target_dir


def run_zip(
    package_zip: Path,
    *,
    max_files: int = _MAX_ZIP_FILES,
    max_uncompressed_bytes: int = _MAX_ZIP_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = _MAX_ZIP_COMPRESSION_RATIO,
) -> int:
    if not package_zip.is_file():
        print("release_package_verify=FAILED")
        print("reason=package zip missing")
        return 2
    with tempfile.TemporaryDirectory(prefix="takt-release-package-verify-") as tmp:
        package_dir = _safe_extract_zip(
            package_zip,
            Path(tmp),
            max_files=max_files,
            max_uncompressed_bytes=max_uncompressed_bytes,
            max_compression_ratio=max_compression_ratio,
        )
        if package_dir is None:
            return 2
        return run(package_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify release package manifest and file checksums.")
    try:
        default_max_zip_files = _env_int("TAKT_RELEASE_VERIFY_MAX_ZIP_FILES", _MAX_ZIP_FILES)
        default_max_zip_uncompressed_bytes = _env_int(
            "TAKT_RELEASE_VERIFY_MAX_ZIP_UNCOMPRESSED_BYTES",
            _MAX_ZIP_UNCOMPRESSED_BYTES,
        )
        default_max_zip_compression_ratio = _env_float(
            "TAKT_RELEASE_VERIFY_MAX_ZIP_COMPRESSION_RATIO",
            _MAX_ZIP_COMPRESSION_RATIO,
        )
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    parser.add_argument("package", nargs="?", help="Path to release package directory or zip archive.")
    parser.add_argument("--package-dir", help="Path to release package directory.")
    parser.add_argument("--package-zip", help="Path to release package zip archive.")
    parser.add_argument(
        "--max-zip-files",
        type=int,
        default=default_max_zip_files,
        help="Maximum files allowed in a zip archive.",
    )
    parser.add_argument(
        "--max-zip-uncompressed-bytes",
        type=int,
        default=default_max_zip_uncompressed_bytes,
        help="Maximum total uncompressed zip size.",
    )
    parser.add_argument(
        "--max-zip-compression-ratio",
        type=float,
        default=default_max_zip_compression_ratio,
        help="Maximum per-entry zip compression ratio.",
    )
    args = parser.parse_args()
    selected = [value for value in (args.package, args.package_dir, args.package_zip) if value]
    if len(selected) != 1:
        parser.error("provide exactly one of package, --package-dir, or --package-zip")
    if args.max_zip_files < 1:
        parser.error("--max-zip-files must be >= 1")
    if args.max_zip_uncompressed_bytes < 1:
        parser.error("--max-zip-uncompressed-bytes must be >= 1")
    if args.max_zip_compression_ratio < 1.0:
        parser.error("--max-zip-compression-ratio must be >= 1.0")
    zip_limits = {
        "max_files": args.max_zip_files,
        "max_uncompressed_bytes": args.max_zip_uncompressed_bytes,
        "max_compression_ratio": args.max_zip_compression_ratio,
    }
    if args.package:
        package = Path(args.package).expanduser().resolve()
        if package.suffix.lower() == ".zip":
            return run_zip(package, **zip_limits)
        return run(package)
    if args.package_dir:
        return run(Path(args.package_dir).expanduser().resolve())
    return run_zip(Path(args.package_zip).expanduser().resolve(), **zip_limits)


if __name__ == "__main__":
    raise SystemExit(main())
