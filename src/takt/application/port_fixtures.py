"""Тестовые реализации портов времени и идентификаторов."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


@dataclass
class FrozenClock(SystemClockPort):
    """Фиксированный момент UTC (удобно для детерминированных сценариев)."""

    at: datetime = field(default_factory=lambda: datetime(2024, 1, 15, 12, 0, tzinfo=UTC))

    def now_utc(self) -> datetime:
        return self.at


@dataclass
class SequentialIdProvider(IdProviderPort):
    """Предсказуемые короткие id для карточек (счётчик с произвольным префиксом)."""

    prefix: str = "c"
    _n: int = field(default=0, repr=False)

    def new_case_id_short(self) -> str:
        self._n += 1
        return f"{self.prefix}{self._n:05d}"
