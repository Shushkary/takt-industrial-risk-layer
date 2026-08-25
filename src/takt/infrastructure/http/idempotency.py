"""Идемпотентный ingest: **Idempotency-Key**, TTL (**TAKT_IDEMPOTENCY_TTL_SEC**)."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Protocol

from fastapi import HTTPException
from starlette.requests import Request

_IDEM_KEY_MAX_LEN = 256
_DEFAULT_TTL_SEC = 86400
_MIN_TTL = 60
_MAX_TTL_SEC = 7 * 86400


def idempotency_ttl_sec_from_env() -> int:
    raw = os.environ.get("TAKT_IDEMPOTENCY_TTL_SEC", "").strip()
    if not raw:
        return _DEFAULT_TTL_SEC
    try:
        v = int(raw, 10)
    except ValueError:
        return _DEFAULT_TTL_SEC
    return max(_MIN_TTL, min(v, _MAX_TTL_SEC))


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def utc_expires_iso(ttl_sec: int) -> str:
    dt = datetime.now(UTC) + timedelta(seconds=ttl_sec)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_idempotency_header(request: Request) -> str | None:
    raw = request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key")
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    if len(s) > _IDEM_KEY_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Idempotency-Key must not exceed {_IDEM_KEY_MAX_LEN} characters",
        )
    return s


class IdempotencyStorePort(Protocol):
    def idempotency_delete_expired(self) -> None: ...
    def idempotency_get(self, key: str) -> tuple[str, str] | None: ...
    def idempotency_put(self, key: str, body_hash: str, response_json: str, expires_at_iso: str) -> None: ...


def idempotent_json_response_or_none(
    *,
    request: Request,
    raw_body: bytes,
    store: IdempotencyStorePort | None,
) -> tuple[dict, bool] | None:
    """
    При совпадении ключа и тела возвращает (dict, True) для ответа с **X-Idempotent-Replayed**.
    При конфликте ключа и другого тела — бросает **HTTPException 409**.
    Без заголовка или без store — **None**.
    """
    idem_key = parse_idempotency_header(request)
    if idem_key is None or store is None:
        return None
    body_hash = body_sha256_hex(raw_body)
    store.idempotency_delete_expired()
    row = store.idempotency_get(idem_key)
    if row is None:
        return None
    prev_hash, prev_json = row
    if prev_hash != body_hash:
        raise HTTPException(
            status_code=409,
            detail="Idempotency-Key already used with a different request body",
        )
    return json.loads(prev_json), True


def idempotency_record_success(
    *,
    request: Request,
    raw_body: bytes,
    store: IdempotencyStorePort | None,
    response_json: str,
) -> None:
    idem_key = parse_idempotency_header(request)
    if idem_key is None or store is None:
        return
    ttl = idempotency_ttl_sec_from_env()
    expires = utc_expires_iso(ttl)
    store.idempotency_put(idem_key, body_sha256_hex(raw_body), response_json, expires)
