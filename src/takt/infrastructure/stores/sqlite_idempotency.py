from __future__ import annotations

import sqlite3
from datetime import UTC, datetime


def _now_iso_z() -> str:
    """Текущее время в формате ISO без микросекунд и с суффиксом ``Z`` (UTC)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def idempotency_delete_expired(conn: sqlite3.Connection) -> None:
    """Удалить просроченные ключи идемпотентности из таблицы ``idempotency_keys``."""
    now = _now_iso_z()
    conn.execute("DELETE FROM idempotency_keys WHERE expires_at < ?", (now,))


def idempotency_get(conn: sqlite3.Connection, key: str) -> tuple[str, str] | None:
    """Вернуть ``(body_hash, response_json)`` непросроченного ключа либо ``None``.

    Если ключ найден, но его срок истёк, он удаляется и возвращается ``None``.
    Вызывающий обязан удерживать блокировку хранилища вокруг этого вызова.
    """
    cur = conn.execute(
        "SELECT body_hash, response_json, expires_at FROM idempotency_keys WHERE idem_key = ?",
        (key,),
    )
    row = cur.fetchone()
    if row is None:
        return None
    now = _now_iso_z()
    if str(row[2]) < now:
        conn.execute("DELETE FROM idempotency_keys WHERE idem_key = ?", (key,))
        return None
    return str(row[0]), str(row[1])


def idempotency_put(
    conn: sqlite3.Connection,
    key: str,
    body_hash: str,
    response_json: str,
    expires_at_iso: str,
) -> None:
    """Сохранить или обновить ключ идемпотентности (UPSERT по ``idem_key``)."""
    conn.execute(
        """
        INSERT INTO idempotency_keys (idem_key, body_hash, response_json, expires_at)
        VALUES (?,?,?,?)
        ON CONFLICT(idem_key) DO UPDATE SET
          body_hash = excluded.body_hash,
          response_json = excluded.response_json,
          expires_at = excluded.expires_at
        """,
        (key, body_hash, response_json, expires_at_iso),
    )
