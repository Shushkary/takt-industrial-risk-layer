"""Онлайн-статистика Уэлфорда (Welford) для инкрементального mean/variance/stddev.

Алгоритм численно устойчив и не требует хранения всей истории наблюдений —
достаточно счётчика ``n``, среднего ``mean`` и агрегата квадратов отклонений ``m2``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(slots=True)
class BaselineStats:
    """Инкрементальные mean/variance/stddev по алгоритму Уэлфорда."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        """Учесть одно наблюдение (одна итерация Уэлфорда, без пересчёта истории)."""
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Выборочная дисперсия (n-1); ``0.0`` при недостатке наблюдений."""
        if self.n < 2:
            return 0.0
        return self.m2 / (self.n - 1)

    @property
    def population_variance(self) -> float:
        """Генеральная дисперсия (n); ``0.0`` при отсутствии наблюдений."""
        if self.n < 1:
            return 0.0
        return self.m2 / self.n

    @property
    def stddev(self) -> float:
        """Стандартное отклонение (корень из выборочной дисперсии)."""
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        """z-оценка значения относительно базовой линии.

        При нулевом (или ещё не набранном) отклонении возвращает ``0.0`` —
        «типичность» не может быть определена и не считается аномалией.
        """
        sd = self.stddev
        if self.n < 2 or sd == 0.0:
            return 0.0
        return (value - self.mean) / sd
