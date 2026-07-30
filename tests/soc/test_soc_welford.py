"""Property-тесты онлайн-статистики Уэлфорда (``BaselineStats``).

Сверяем инкрементальные mean/variance с «оффлайн»-расчётом по всей выборке.
"""

from __future__ import annotations

import statistics

from hypothesis import given, settings
from hypothesis import strategies as st

from takt.domain.soc.welford import BaselineStats

_floats = st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False)


@settings(max_examples=200)
@given(st.lists(_floats, min_size=2, max_size=200))
def test_mean_matches_offline(values: list[float]) -> None:
    stats = BaselineStats()
    for v in values:
        stats.update(v)
    assert stats.n == len(values)
    assert abs(stats.mean - statistics.fmean(values)) < 1e-6


@settings(max_examples=200)
@given(st.lists(_floats, min_size=2, max_size=200))
def test_variance_matches_offline(values: list[float]) -> None:
    stats = BaselineStats()
    for v in values:
        stats.update(v)
    expected = statistics.variance(values)  # выборочная (n-1)
    # Допуск относительный: величины могут быть большими.
    scale = max(1.0, abs(expected))
    assert abs(stats.variance - expected) <= 1e-6 * scale


def test_zscore_zero_when_insufficient_data() -> None:
    stats = BaselineStats()
    assert stats.zscore(10.0) == 0.0
    stats.update(5.0)
    assert stats.zscore(10.0) == 0.0  # n < 2 → 0


def test_zscore_zero_for_constant_series() -> None:
    stats = BaselineStats()
    for _ in range(10):
        stats.update(7.0)
    # Нулевое отклонение → z-оценка 0 (типичность не определена).
    assert stats.zscore(7.0) == 0.0
    assert stats.zscore(100.0) == 0.0


def test_zscore_sign_and_magnitude() -> None:
    stats = BaselineStats()
    for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
        stats.update(v)
    # Значение выше среднего → положительная z-оценка, ниже → отрицательная.
    assert stats.zscore(10.0) > 0
    assert stats.zscore(-10.0) < 0
