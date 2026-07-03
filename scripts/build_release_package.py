#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def _load_script_function(script_name: str, function_name: str):
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(f"bundle_{script_name}", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _manifest_package_dir(out_dir: Path, repo_root: Path) -> str:
    """Use a repo-relative POSIX path when the package sits under repo (portable manifests)."""

    try:
        rel = out_dir.resolve().relative_to(repo_root.resolve())
        return rel.as_posix()
    except ValueError:
        return str(out_dir)


def _required_release_evidence(root: Path) -> list[Path]:
    return [
        root / "dist" / "sbom.cyclonedx.json",
        root / "frontend" / "takt-arm" / "dist" / "frontend-sbom.cyclonedx.json",
        root / "frontend" / "takt-arm" / "nginx" / "csp.conf",
    ]


def run(
    db_path: Path,
    *,
    package_root: Path,
    prod_ready: Path,
    readiness: Path,
    apply_migrate: bool,
    strict: bool,
    strict_generate_sbom: bool,
) -> int:
    root = Path(__file__).resolve().parents[1]
    stamp = _utc_stamp()
    out_dir = package_root / f"release-package-{stamp}"
    evidence_path = out_dir / "operational_tails_evidence.md"
    prod_out = out_dir / prod_ready.name

    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(prod_ready, prod_out)

    finalize = _load_script_function("release_finalize.py", "run")
    rc = finalize(
        db_path,
        evidence_path,
        prod_out,
        apply_migrate=apply_migrate,
        strict=strict,
        strict_generate_sbom=strict_generate_sbom,
    )
    if rc != 0:
        print("release_package_status=FAILED")
        return rc

    optional_files = [
        readiness,
        root / "docs" / "releases" / "runbook_pre_deploy.md",
        root / "docs" / "releases" / "runbook_smoke_checks.md",
        root / "docs" / "releases" / "runbook_rollback.md",
        root / "deploy" / "monitoring" / "grafana" / "takt-business-observability-dashboard.json",
        root / "deploy" / "monitoring" / "prometheus" / "alerts.business-observability.rules.yml",
        root / "scripts" / "verify_audit_ledger.py",
        root / "scripts" / "verify_operation_ledger.py",
    ]
    required_release_evidence = _required_release_evidence(root)
    missing_required = [str(src.relative_to(root)) for src in required_release_evidence if not src.exists()]
    if strict and missing_required:
        print("release_package_status=FAILED")
        print("reason=missing_required_release_evidence:" + ",".join(missing_required))
        return 2

    copied: list[str] = []
    for src in optional_files + required_release_evidence:
        if not src.exists():
            continue
        dst = out_dir / src.name
        shutil.copy2(src, dst)
        copied.append(dst.name)

    included = sorted(copied + [evidence_path.name, prod_out.name])
    checksums = {name: _sha256_file(out_dir / name) for name in included}
    manifest = {
        "generated_at_utc": stamp,
        "package_dir": _manifest_package_dir(out_dir, root),
        "evidence_file": evidence_path.name,
        "prod_ready_file": prod_out.name,
        "included_files": included,
        "sha256": checksums,
        "status": "READY",
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    archive = shutil.make_archive(str(out_dir), "zip", root_dir=str(out_dir))
    print(f"release_package_status=READY")
    print(f"release_package_dir={out_dir}")
    print(f"release_package_zip={archive}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build complete release package bundle.")
    parser.add_argument("--db", required=True, help="Path to target SQLite DB.")
    parser.add_argument("--package-root", default="dist", help="Directory where package folder will be created.")
    parser.add_argument(
        "--prod-ready",
        default="docs/releases/2026-05-07_v0.6.23_prod_ready.md",
        help="Path to prod-ready card.",
    )
    parser.add_argument(
        "--readiness",
        default="docs/releases/2026-05-07_v0.6.23_readiness.md",
        help="Path to full readiness card.",
    )
    parser.add_argument("--apply-migrate", action="store_true", help="Apply db migration in finalize flow.")
    parser.add_argument("--strict", action="store_true", help="Enable strict release finalize checks.")
    parser.add_argument(
        "--strict-generate-sbom",
        action="store_true",
        help="Generate SBOM in strict mode if it is missing.",
    )
    args = parser.parse_args()
    return run(
        Path(args.db).expanduser().resolve(),
        package_root=Path(args.package_root).expanduser().resolve(),
        prod_ready=Path(args.prod_ready).expanduser().resolve(),
        readiness=Path(args.readiness).expanduser().resolve(),
        apply_migrate=bool(args.apply_migrate),
        strict=bool(args.strict),
        strict_generate_sbom=bool(args.strict_generate_sbom),
    )


if __name__ == "__main__":
    raise SystemExit(main())
