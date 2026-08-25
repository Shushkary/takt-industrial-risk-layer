#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient


def _utc_now_tag() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _ensure_db_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    conn = sqlite3.connect(str(path))
    conn.close()


def _has_cases_table(path: Path) -> bool:
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cases' LIMIT 1"
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _bootstrap_sqlite_schema(path: Path) -> None:
    from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

    store = SqliteCaseStore(path)
    store.close()


def _load_script_function(script_name: str, function_name: str):
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(f"ops_{script_name}", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


def _backup_db(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(src)) as source_conn, sqlite3.connect(str(dst)) as dest_conn:
        source_conn.backup(dest_conn)


def _run_local_smoke(sqlite_path: Path) -> dict[str, object]:
    from takt.interface_adapters.api.main import create_app

    env_keys = ["TAKT_STORAGE", "TAKT_SQLITE_PATH", "TAKT_AUTH_REQUIRED"]
    old_env = {k: os.environ.get(k) for k in env_keys}
    try:
        os.environ["TAKT_STORAGE"] = "sqlite"
        os.environ["TAKT_SQLITE_PATH"] = str(sqlite_path)
        os.environ["TAKT_AUTH_REQUIRED"] = "false"
        with TestClient(create_app()) as client:
            health = client.get("/health")
            assess = client.post(
                "/assess",
                json={
                    "observed_at": "2026-05-07T12:00:00+00:00",
                    "operation": "READ",
                    "asset_id": "plc-ops-smoke",
                },
            )
            case_id = str(assess.json().get("case_id", "")) if assess.status_code == 200 else ""
            forensic_verify_ok = False
            forensic_signing_unavailable = False
            gossopka_official_ok = False
            audit_engagement_api_ok = False
            if case_id:
                archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
                if archive.status_code == 200:
                    verify = client.post(
                        "/forensic-bundle/verify",
                        content=archive.content,
                        headers={"content-type": "application/zip"},
                    )
                    forensic_verify_ok = verify.status_code == 200 and bool(verify.json().get("ok", False))
                elif archive.status_code == 503:
                    detail = str((archive.json() or {}).get("detail", ""))
                    forensic_signing_unavailable = "forensic_signing_unavailable" in detail
                gossopka_official = client.get(f"/cases/{case_id}/export/gossopka-official-transport.json")
                gossopka_official_ok = gossopka_official.status_code == 200
                engagement = client.post(
                    "/audit-engagements",
                    json={
                        "customer": "ops-smoke",
                        "scope": "release smoke engagement api",
                        "case_ids": [case_id],
                        "nda_signed": True,
                        "evidence_intake_checklist": ["nda", "logs"],
                    },
                )
                if engagement.status_code == 200:
                    eid = str(engagement.json().get("engagement_id", "")).strip()
                    if eid:
                        report = client.get(f"/audit-engagements/{eid}/export/report.json")
                        audit_engagement_api_ok = report.status_code == 200
            return {
                "health_status_code": health.status_code,
                "assess_status_code": assess.status_code,
                "case_id": case_id,
                "forensic_verify_ok": forensic_verify_ok,
                "forensic_signing_unavailable": forensic_signing_unavailable,
                "gossopka_official_ok": gossopka_official_ok,
                "audit_engagement_api_ok": audit_engagement_api_ok,
            }
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def run(db_path: Path, output_path: Path, *, apply_migrate: bool) -> int:
    migrate_run = _load_script_function("db_migrate.py", "run")
    verify_case_ledger = _load_script_function("verify_audit_ledger.py", "verify")
    verify_operation_ledger = _load_script_function("verify_operation_ledger.py", "verify")

    _ensure_db_file(db_path)
    if not _has_cases_table(db_path):
        _bootstrap_sqlite_schema(db_path)
    stamp = _utc_now_tag()
    backup_path = db_path.parent / f"{db_path.stem}.backup.{stamp}.sqlite"
    _backup_db(db_path, backup_path)

    migrated = False
    if apply_migrate:
        migrate_run(db_path)
        migrated = True

    ledger_case = verify_case_ledger(db_path, "smoke-case")
    ledger_operation = verify_operation_ledger(db_path, "")

    smoke_db = db_path.parent / f"{db_path.stem}.smoke.{stamp}.sqlite"
    _backup_db(db_path, smoke_db)
    smoke = _run_local_smoke(smoke_db)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(
            [
                f"# Operational tails evidence ({stamp})",
                "",
                "## Inputs",
                f"- db_path: `{db_path}`",
                f"- apply_migrate: `{str(apply_migrate).lower()}`",
                "",
                "## Actions",
                f"- backup_created: `{backup_path}`",
                f"- migrate_executed: `{str(migrated).lower()}`",
                f"- smoke_db_created: `{smoke_db}`",
                "",
                "## Ledger verify",
                f"- case_ledger: `{ledger_case}`",
                f"- operation_ledger: `{ledger_operation}`",
                "",
                "## API smoke",
                f"- smoke_result: `{smoke}`",
                "",
                "## Ready-to-copy fields",
                f"- backup_path: `{backup_path}`",
                f"- migrate_done: `{str(migrated).lower()}`",
                f"- smoke_case_id: `{smoke.get('case_id', '')}`",
                f"- forensic_verify_ok: `{str(bool(smoke.get('forensic_verify_ok', False))).lower()}`",
                f"- forensic_signing_unavailable: `{str(bool(smoke.get('forensic_signing_unavailable', False))).lower()}`",
                f"- gossopka_official_ok: `{str(bool(smoke.get('gossopka_official_ok', False))).lower()}`",
                f"- audit_engagement_api_ok: `{str(bool(smoke.get('audit_engagement_api_ok', False))).lower()}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"evidence_written={output_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Close operational tails and write release evidence markdown.")
    parser.add_argument("--db", required=True, help="Path to target SQLite DB.")
    parser.add_argument(
        "--output",
        default="docs/releases/operational_tails_evidence.md",
        help="Path to markdown evidence output.",
    )
    parser.add_argument(
        "--apply-migrate",
        action="store_true",
        help="Apply db_migrate.py to the target DB before running checks.",
    )
    args = parser.parse_args()
    return run(
        Path(args.db).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
        apply_migrate=bool(args.apply_migrate),
    )


if __name__ == "__main__":
    raise SystemExit(main())
