#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path


def _load_script_function(script_name: str, function_name: str):
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(f"release_{script_name}", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


def _required_artifact_paths(root: Path) -> list[Path]:
    return [
        root / "scripts" / "verify_audit_ledger.py",
        root / "scripts" / "verify_operation_ledger.py",
        root / "deploy" / "monitoring" / "grafana" / "takt-business-observability-dashboard.json",
        root / "deploy" / "monitoring" / "prometheus" / "alerts.business-observability.rules.yml",
    ]


def _ensure_strict_sbom(root: Path, *, strict_generate_sbom: bool) -> tuple[bool, str]:
    sbom_path = root / "dist" / "sbom.cyclonedx.json"
    if sbom_path.is_file():
        return True, ""
    if not strict_generate_sbom:
        return False, f"strict mode: missing SBOM at {sbom_path}"
    script = root / "scripts" / "generate_sbom.py"
    subprocess.check_call([sys.executable, str(script)])
    if not sbom_path.is_file():
        return False, f"strict mode: SBOM generation did not create {sbom_path}"
    return True, ""


def _extract_evidence_bool(text: str, key: str) -> bool | None:
    m = re.search(rf"-\s+{re.escape(key)}:\s+`([^`]+)`", text)
    if not m:
        return None
    raw = m.group(1).strip().lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def run(
    db_path: Path,
    evidence_path: Path,
    prod_ready_path: Path,
    *,
    apply_migrate: bool,
    forensic_mode: str = "",
    strict: bool = False,
    strict_generate_sbom: bool = False,
) -> int:
    root = Path(__file__).resolve().parents[1]
    close_tails_run = _load_script_function("close_operational_tails.py", "run")
    fill_prod_ready_run = _load_script_function("fill_prod_ready_from_evidence.py", "run")
    validate_prod_ready_run = _load_script_function("validate_prod_ready.py", "run")

    missing = [str(p) for p in _required_artifact_paths(root) if not p.is_file()]
    if missing:
        print("release_status=NOT_READY")
        print(f"release_reason=required artifacts are missing: {missing}")
        return 2
    if strict:
        ok, reason = _ensure_strict_sbom(root, strict_generate_sbom=strict_generate_sbom)
        if not ok:
            print("release_status=NOT_READY")
            print(f"release_reason={reason}")
            return 2

    close_tails_run(db_path, evidence_path, apply_migrate=apply_migrate)
    evidence_text = evidence_path.read_text(encoding="utf-8")
    gossopka_official_ok = _extract_evidence_bool(evidence_text, "gossopka_official_ok")
    if gossopka_official_ok is not True:
        print("release_status=NOT_READY")
        print("release_reason=pre-release smoke failed: gossopka_official_ok is not true")
        return 2
    forensic_signing_unavailable = _extract_evidence_bool(evidence_text, "forensic_signing_unavailable")
    if forensic_signing_unavailable is True:
        print("release_status=NOT_READY")
        print("release_reason=pre-release smoke failed: forensic_signing_unavailable is true")
        return 2
    forensic_verify_ok = _extract_evidence_bool(evidence_text, "forensic_verify_ok")
    if forensic_verify_ok is not True:
        print("release_status=NOT_READY")
        print("release_reason=pre-release smoke failed: forensic_verify_ok is not true")
        return 2
    audit_engagement_api_ok = _extract_evidence_bool(evidence_text, "audit_engagement_api_ok")
    if audit_engagement_api_ok is not True:
        print("release_status=NOT_READY")
        print("release_reason=pre-release smoke failed: audit_engagement_api_ok is not true")
        return 2
    fill_prod_ready_run(evidence_path, prod_ready_path, forensic_mode=forensic_mode)

    validation_rc = validate_prod_ready_run(prod_ready_path)
    if validation_rc != 0:
        print("release_status=NOT_READY")
        print("release_reason=prod_ready placeholders policy validation failed")
        return 2
    print("release_status=READY")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run release evidence prep and prod-ready autofill in one command.")
    parser.add_argument("--db", required=True, help="Path to target SQLite DB.")
    parser.add_argument(
        "--evidence",
        default="docs/releases/operational_tails_evidence.md",
        help="Output path for generated evidence markdown.",
    )
    parser.add_argument(
        "--prod-ready",
        default="docs/releases/2026-05-07_v0.6.23_prod_ready.md",
        help="Path to prod-ready markdown to update.",
    )
    parser.add_argument(
        "--apply-migrate",
        action="store_true",
        help="Apply db_migrate.py before checks when generating evidence.",
    )
    parser.add_argument(
        "--forensic-mode",
        default="",
        help="Optional explicit value for prod-ready field 7.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable stricter checks (currently SBOM presence in dist/sbom.cyclonedx.json).",
    )
    parser.add_argument(
        "--strict-generate-sbom",
        action="store_true",
        help="In strict mode, generate SBOM if missing by invoking scripts/generate_sbom.py.",
    )
    args = parser.parse_args()
    return run(
        Path(args.db).expanduser().resolve(),
        Path(args.evidence).expanduser().resolve(),
        Path(args.prod_ready).expanduser().resolve(),
        apply_migrate=bool(args.apply_migrate),
        forensic_mode=args.forensic_mode,
        strict=bool(args.strict),
        strict_generate_sbom=bool(args.strict_generate_sbom),
    )


if __name__ == "__main__":
    raise SystemExit(main())
