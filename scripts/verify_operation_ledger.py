#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def verify(db_path: Path, stream_key: str = "") -> dict[str, object]:
    conn = sqlite3.connect(str(db_path))
    try:
        if stream_key.strip():
            rows = conn.execute(
                """
                SELECT stream_key, payload_json, payload_sha256, prev_chain_sha256, chain_sha256
                FROM operation_audit_ledger
                WHERE stream_key = ?
                ORDER BY stream_key ASC, seq ASC
                """,
                (stream_key.strip(),),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT stream_key, payload_json, payload_sha256, prev_chain_sha256, chain_sha256
                FROM operation_audit_ledger
                ORDER BY stream_key ASC, seq ASC
                """
            ).fetchall()
    finally:
        conn.close()

    checked = 0
    active_stream = ""
    prev_chain = ""
    for row in rows:
        row_stream, payload_json, payload_sha256, prev_chain_sha256, chain_sha256 = row
        row_stream = str(row_stream)
        payload_json = str(payload_json)
        if row_stream != active_stream:
            active_stream = row_stream
            prev_chain = ""
        expected_payload = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        if expected_payload != str(payload_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "payload_sha_mismatch"}
        if str(prev_chain_sha256) != prev_chain:
            return {"ok": False, "checked_entries": checked, "issue": "prev_chain_mismatch"}
        expected_chain = hashlib.sha256(
            f"{prev_chain}:{row_stream}:{expected_payload}:{len(payload_json)}".encode()
        ).hexdigest()
        if expected_chain != str(chain_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "chain_mismatch"}
        prev_chain = expected_chain
        checked += 1
    return {"ok": True, "checked_entries": checked, "issue": ""}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify TAKT operation audit ledger chain.")
    parser.add_argument("--db", required=True, help="Path to SQLite database.")
    parser.add_argument("--stream-key", default="", help="Optional operation stream key (e.g. decision:<case_id>).")
    args = parser.parse_args()
    result = verify(Path(args.db).expanduser().resolve(), args.stream_key)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if bool(result.get("ok")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
