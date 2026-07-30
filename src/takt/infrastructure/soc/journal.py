"""Append-only hash-chain журнал (реализация ``AuditJournalPort``).

Каждая запись содержит хеш предыдущей записи, образуя цепочку: любое изменение
исторической записи ломает ``verify_chain()``. Используется write use cases для
фиксации решений/находок/ручных группировок.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from takt.application.soc.ports import JournalEntry

_GENESIS = "0" * 64


class HashChainJournal:
    """Журнал с хеш-цепочкой в памяти (реализация порта ``AuditJournalPort``)."""

    def __init__(self) -> None:
        self._entries: list[JournalEntry] = []

    @staticmethod
    def _hash(seq: int, action: str, payload: dict[str, Any], prev_hash: str, ts: str) -> str:
        material = json.dumps(
            {"seq": seq, "action": action, "payload": payload, "prev_hash": prev_hash, "ts": ts},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def append(self, *, action: str, payload: dict[str, Any]) -> JournalEntry:
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].entry_hash if self._entries else _GENESIS
        ts = payload.get("ts") if isinstance(payload.get("ts"), str) else datetime.now(UTC).isoformat()
        entry_hash = self._hash(seq, action, payload, prev_hash, ts)
        entry = JournalEntry(
            seq=seq,
            action=action,
            payload=dict(payload),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            ts=ts,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[JournalEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        prev = _GENESIS
        for i, entry in enumerate(self._entries, start=1):
            if entry.seq != i or entry.prev_hash != prev:
                return False
            expected = self._hash(entry.seq, entry.action, entry.payload, entry.prev_hash, entry.ts)
            if expected != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True
