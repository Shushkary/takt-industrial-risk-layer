"""Именованные API-ключи с ролями (Спринт RBAC).

Формат **TAKT_API_KEYS**: список записей через запятую, каждая запись —
`ключ:actor_id:роль`. Роль — одна из `operator`, `auditor`, `admin`.
Ключ и actor_id не должны содержать `:` или `,`. Некорректные записи
(пустой ключ/actor_id, неизвестная роль, дубликат ключа) отбрасываются
с предупреждением в лог, процесс не падает.

Обратная совместимость: если задан одиночный **TAKT_API_KEY** и он не
встречается среди ключей из **TAKT_API_KEYS**, для него добавляется
неявная запись с ролью **admin** и `actor_id=legacy-api-key`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from takt.infrastructure.security.auth_env import takt_api_key_value

_log = logging.getLogger("takt.auth")

VALID_ROLES: frozenset[str] = frozenset(
    {"analyst_l1", "analyst_l2", "manager", "admin", "operator", "auditor"}
)

_LEGACY_ACTOR_ID = "legacy-api-key"
_LEGACY_ROLE = "admin"


@dataclass(frozen=True, slots=True)
class ApiKeyEntry:
    key: str
    actor_id: str
    role: str


def _parse_entry(raw: str) -> ApiKeyEntry | None:
    parts = raw.split(":")
    if len(parts) != 3:
        _log.warning("TAKT_API_KEYS: skipping malformed entry (expected key:actor_id:role)")
        return None
    key, actor_id, role = (p.strip() for p in parts)
    if not key or not actor_id:
        _log.warning("TAKT_API_KEYS: skipping entry with empty key or actor_id")
        return None
    role = role.lower()
    if role not in VALID_ROLES:
        _log.warning("TAKT_API_KEYS: skipping entry with unknown role %r (actor_id=%s)", role, actor_id)
        return None
    return ApiKeyEntry(key=key, actor_id=actor_id, role=role)


def api_key_entries_from_env() -> tuple[ApiKeyEntry, ...]:
    """Разбор `TAKT_API_KEYS` + обратная совместимость с одиночным `TAKT_API_KEY`."""
    raw = os.environ.get("TAKT_API_KEYS", "").strip()
    entries: list[ApiKeyEntry] = []
    seen_keys: set[str] = set()
    if raw:
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            entry = _parse_entry(chunk)
            if entry is None:
                continue
            if entry.key in seen_keys:
                _log.warning("TAKT_API_KEYS: skipping duplicate key for actor_id=%s", entry.actor_id)
                continue
            seen_keys.add(entry.key)
            entries.append(entry)

    legacy_key = takt_api_key_value()
    if legacy_key and legacy_key not in seen_keys:
        entries.append(ApiKeyEntry(key=legacy_key, actor_id=_LEGACY_ACTOR_ID, role=_LEGACY_ROLE))

    return tuple(entries)


def resolve_api_key(entries: tuple[ApiKeyEntry, ...], presented: str) -> ApiKeyEntry | None:
    """Поиск записи по предъявленному ключу (constant-time сравнение на каждую запись)."""
    import hmac

    if not presented:
        return None
    presented_b = presented.encode("utf-8")
    match: ApiKeyEntry | None = None
    for entry in entries:
        entry_b = entry.key.encode("utf-8")
        if len(entry_b) == len(presented_b) and hmac.compare_digest(entry_b, presented_b):
            match = entry
    return match
