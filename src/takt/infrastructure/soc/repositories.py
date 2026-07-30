"""Реализации портов write/read-моделей ядра «SOC core» (in-memory).

Read-модель хранится в отдельных проекциях (``case_cards``, ``event_search_index``),
что отражает CQRS: запись обновляет проекции, чтение идёт напрямую из них.
Курсорная пагинация поиска использует монотонный ``seq`` как непрозрачный курсор.
"""

from __future__ import annotations

from typing import Any

from takt.domain.soc.normalized_event import NormalizedEvent


class InMemoryEventRepository:
    """Write-модель событий с индексом по ``content_hash`` (идемпотентность)."""

    def __init__(self) -> None:
        self._by_hash: dict[str, str] = {}
        self._events: dict[str, NormalizedEvent] = {}

    def exists_by_hash(self, content_hash: str) -> bool:
        return content_hash in self._by_hash

    def case_id_for_hash(self, content_hash: str) -> str | None:
        return self._by_hash.get(content_hash)

    def save(self, event: NormalizedEvent, *, case_id: str) -> None:
        self._by_hash[event.content_hash] = case_id
        self._events[event.content_hash] = event


class InMemoryCaseProjection:
    """Проекция карточек кейсов (денормализованная read-модель)."""

    def __init__(self) -> None:
        self._cards: dict[str, dict[str, Any]] = {}

    def upsert_case_card(self, card: dict[str, Any]) -> None:
        case_id = str(card["case_id"])
        self._cards[case_id] = dict(card)

    def get_case_card(self, case_id: str) -> dict[str, Any] | None:
        card = self._cards.get(case_id)
        return dict(card) if card is not None else None


class InMemoryEventSearchProjection:
    """Проекция полнотекстового поиска по событиям с курсорной пагинацией."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []
        self._seq = 0

    def index_event(self, row: dict[str, Any]) -> None:
        self._seq += 1
        stored = dict(row)
        stored["seq"] = self._seq
        haystack = " ".join(str(v) for v in row.values() if v is not None).lower()
        stored["_haystack"] = haystack
        self._rows.append(stored)

    def search(
        self, *, query: str | None, after_seq: int | None, limit: int
    ) -> tuple[list[dict[str, Any]], int | None, int]:
        needle = (query or "").strip().lower()
        matched = [r for r in self._rows if not needle or needle in r["_haystack"]]
        total = len(matched)
        if after_seq is not None:
            matched = [r for r in matched if r["seq"] > after_seq]
        page = matched[:limit]
        next_cursor = page[-1]["seq"] if len(matched) > limit and page else None
        items = [{k: v for k, v in r.items() if k != "_haystack"} for r in page]
        return items, next_cursor, total


class InMemoryAttackChainProjection:
    """Проекция реконструкции цепочки атаки по кейсу."""

    def __init__(self) -> None:
        self._chains: dict[str, list[dict[str, Any]]] = {}

    def set_chain(self, case_id: str, chain: list[dict[str, Any]]) -> None:
        self._chains[case_id] = [dict(step) for step in chain]

    def get_chain(self, case_id: str) -> list[dict[str, Any]]:
        return [dict(step) for step in self._chains.get(case_id, [])]
