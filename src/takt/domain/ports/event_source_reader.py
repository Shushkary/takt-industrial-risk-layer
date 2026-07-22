from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from takt.domain.entities.event import NormalizedEvent


class EventSourceReaderPort(Protocol):
    """Потоковое чтение нормализованных событий внешнего источника."""

    def __iter__(self) -> Iterator[NormalizedEvent]: ...

