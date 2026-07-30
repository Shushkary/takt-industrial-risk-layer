"""Порты L1 (абстрактные интерфейсы). Реализации живут в L2/L4.

Источники недетерминизма (время, идентификаторы, обогащение) инъектируются,
поэтому домен остаётся чистым и полностью тестируемым.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from takt.domain.soc.normalized_event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class EnrichmentData:
    """Результат обогащения узла (окружение/типичность)."""

    host_id: str
    segment: str | None = None
    criticality: str | None = None
    is_air_gap: bool = False
    tags: tuple[str, ...] = ()


@runtime_checkable
class EnrichmentProvider(Protocol):
    """Порт обогащения: контекст узла по идентификатору."""

    def enrich(self, host_id: str) -> EnrichmentData | None: ...


@runtime_checkable
class Clock(Protocol):
    """Порт времени: текущий момент в UTC."""

    def now(self) -> datetime: ...


@runtime_checkable
class IdGenerator(Protocol):
    """Порт генерации идентификаторов (кейсов/находок)."""

    def generate(self) -> str: ...


@runtime_checkable
class EventRepository(Protocol):
    """Порт хранилища событий (write-модель) с проверкой идемпотентности."""

    def exists_by_hash(self, content_hash: str) -> bool: ...

    def case_id_for_hash(self, content_hash: str) -> str | None: ...

    def save(self, event: NormalizedEvent, *, case_id: str) -> None: ...
