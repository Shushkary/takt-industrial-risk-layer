#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def verify(db_path: Path, case_id: str) -> dict[str, object]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """
            SELECT seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256
            FROM case_audit_ledger
            WHERE case_id = ?
            ORDER BY seq ASC
            """,
            (case_id,),
        ).fetchall()
    finally:
        conn.close()

    prev_chain = ""
    checked = 0
    for row in rows:
        _seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256 = row
        line = str(audit_line)
        expected_line = hashlib.sha256(line.encode("utf-8")).hexdigest()
        if expected_line != str(line_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "line_sha_mismatch"}
        if str(prev_chain_sha256) != prev_chain:
            return {"ok": False, "checked_entries": checked, "issue": "prev_chain_mismatch"}
        expected_chain = hashlib.sha256(
            f"{prev_chain}:{case_id}:{expected_line}:{len(line)}".encode("utf-8")
        ).hexdigest()
        if expected_chain != str(chain_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "chain_mismatch"}
        prev_chain = expected_chain
        checked += 1
    return {"ok": True, "checked_entries": checked, "issue": ""}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify TAKT immutable audit ledger chain for a case.")
    parser.add_argument("--db", required=True, help="Path to SQLite database.")
    parser.add_argument("--case-id", required=True, help="Case ID to verify.")
    args = parser.parse_args()
    result = verify(Path(args.db).expanduser().resolve(), args.case_id.strip())
    print(json.dumps(result, ensure_ascii=False))
    return 0 if bool(result.get("ok")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
