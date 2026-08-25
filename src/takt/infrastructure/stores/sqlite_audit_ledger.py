from __future__ import annotations

import hashlib
import sqlite3


def append_case_audit_ledger_line(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    audit_line: str,
    created_at: str,
) -> None:
    row = conn.execute(
        "SELECT chain_sha256 FROM case_audit_ledger WHERE case_id = ? ORDER BY seq DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    prev_chain = str(row[0]) if row is not None else ""
    line_sha = hashlib.sha256(audit_line.encode("utf-8")).hexdigest()
    chain_sha = hashlib.sha256(
        f"{prev_chain}:{case_id}:{line_sha}:{len(audit_line)}".encode()
    ).hexdigest()
    conn.execute(
        """
        INSERT INTO case_audit_ledger (
          case_id, audit_line, line_sha256, prev_chain_sha256, chain_sha256, created_at
        ) VALUES (?,?,?,?,?,?)
        """,
        (case_id, audit_line, line_sha, prev_chain, chain_sha, created_at),
    )


def verify_case_audit_ledger(conn: sqlite3.Connection, case_id: str) -> dict[str, object]:
    rows = conn.execute(
        """
        SELECT seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256
        FROM case_audit_ledger
        WHERE case_id = ?
        ORDER BY seq ASC
        """,
        (case_id,),
    ).fetchall()
    prev_chain = ""
    checked = 0
    for row in rows:
        _seq, audit_line, line_sha256, prev_chain_sha256, chain_sha256 = row
        audit_line = str(audit_line)
        expected_line = hashlib.sha256(audit_line.encode("utf-8")).hexdigest()
        if expected_line != str(line_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "line_sha_mismatch"}
        if str(prev_chain_sha256) != prev_chain:
            return {"ok": False, "checked_entries": checked, "issue": "prev_chain_mismatch"}
        expected_chain = hashlib.sha256(
            f"{prev_chain}:{case_id}:{expected_line}:{len(audit_line)}".encode()
        ).hexdigest()
        if expected_chain != str(chain_sha256):
            return {"ok": False, "checked_entries": checked, "issue": "chain_mismatch"}
        prev_chain = expected_chain
        checked += 1
    return {"ok": True, "checked_entries": checked, "issue": ""}


def record_operation_event(
    conn: sqlite3.Connection,
    *,
    operation_type: str,
    entity_id: str,
    actor: str,
    payload_json: str,
    created_at: str,
) -> None:
    operation = operation_type.strip()
    entity = entity_id.strip()
    if not operation or not entity:
        raise ValueError("operation_type and entity_id are required")
    stream_key = f"{operation}:{entity}"
    row = conn.execute(
        "SELECT chain_sha256 FROM operation_audit_ledger WHERE stream_key = ? ORDER BY seq DESC LIMIT 1",
        (stream_key,),
    ).fetchone()
    prev_chain = str(row[0]) if row is not None else ""
    payload_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    chain_sha = hashlib.sha256(
        f"{prev_chain}:{stream_key}:{payload_sha}:{len(payload_json)}".encode()
    ).hexdigest()
    conn.execute(
        """
        INSERT INTO operation_audit_ledger (
          stream_key, operation_type, entity_id, actor, payload_json,
          payload_sha256, prev_chain_sha256, chain_sha256, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (stream_key, operation, entity, actor.strip(), payload_json, payload_sha, prev_chain, chain_sha, created_at),
    )


def verify_operation_ledger(conn: sqlite3.Connection, stream_key: str = "") -> dict[str, object]:
    where = ""
    params: tuple[str, ...] = ()
    if stream_key.strip():
        where = "WHERE stream_key = ?"
        params = (stream_key.strip(),)
    rows = conn.execute(
        f"""
        SELECT stream_key, payload_json, payload_sha256, prev_chain_sha256, chain_sha256
        FROM operation_audit_ledger
        {where}
        ORDER BY stream_key ASC, seq ASC
        """,
        params,
    ).fetchall()
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
