"""Сущность ``EntityBaseline`` — базовая линия «типичности» по сущности.

Использует онлайн-статистику Уэлфорда (``BaselineStats``) для оценки того,
насколько наблюдаемая метрика (например, размер полезной нагрузки или интервал
опроса) отклоняется от исторически типичной для конкретной сущности.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from takt.domain.soc.welford import BaselineStats

# Порог |z| по умолчанию, за которым наблюдение считается нетипичным.
DEFAULT_ZSCORE_THRESHOLD = 3.0


@dataclass(slots=True)
class EntityBaseline:
    """Базовая линия одной сущности (узла/пользователя/процесса).

    Не является frozen: базовая линия по определению накапливает состояние.
    Неизменяемость требуется от событий (``NormalizedEvent``), а не от агрегатов
    статистики, которые обновляются инкрементально.
    """

    entity_key: str
    stats: BaselineStats = field(default_factory=BaselineStats)
    threshold: float = DEFAULT_ZSCORE_THRESHOLD

    def observe(self, value: float) -> None:
        """Учесть новое наблюдение метрики для этой сущности."""
        self.stats.update(value)

    def zscore(self, value: float) -> float:
        """z-оценка значения относительно накопленной базовой линии."""
        return self.stats.zscore(value)

    def is_typical(self, value: float) -> bool:
        """Признак «типичности» наблюдения (|z| в пределах порога)."""
        return abs(self.stats.zscore(value)) <= self.threshold

    @property
    def observations(self) -> int:
        """Число учтённых наблюдений."""
        return self.stats.n
