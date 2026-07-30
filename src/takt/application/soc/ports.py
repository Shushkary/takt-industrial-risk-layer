"""Порты уровня приложения (L2): журнал hash-chain и проекции чтения.

Порты объявлены здесь (а не в домене), т.к. описывают потребности сценариев
использования. Реализации живут в L4 (``takt.infrastructure``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Запись hash-chain журнала (append-only)."""

    seq: int
    action: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    ts: str


@runtime_checkable
class AuditJournalPort(Protocol):
    """Append-only журнал с хеш-цепочкой (write-модель, аудит решений)."""

    def append(self, *, action: str, payload: dict[str, Any]) -> JournalEntry: ...

    def entries(self) -> list[JournalEntry]: ...

    def verify_chain(self) -> bool: ...


@runtime_checkable
class CaseProjectionPort(Protocol):
    """Проекция чтения карточек кейсов (денормализованная read-модель)."""

    def upsert_case_card(self, card: dict[str, Any]) -> None: ...

    def get_case_card(self, case_id: str) -> dict[str, Any] | None: ...


@runtime_checkable
class EventSearchProjectionPort(Protocol):
    """Проекция полнотекстового поиска по событиям (курсорная пагинация)."""

    def index_event(self, row: dict[str, Any]) -> None: ...

    def search(
        self, *, query: str | None, after_seq: int | None, limit: int
    ) -> tuple[list[dict[str, Any]], int | None, int]: ...


@runtime_checkable
class AttackChainProjectionPort(Protocol):
    """Проекция цепочки атаки по кейсу."""

    def get_chain(self, case_id: str) -> list[dict[str, Any]]: ...
