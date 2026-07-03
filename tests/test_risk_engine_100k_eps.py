"""Нагрузочный тест: асимптотическая стабильность Risk Engine при 100k+ EPS.

ТЗ: «стабильность вычислений даже при пиковой нагрузке в 100 000 EPS».
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from takt.domain.engines.risk_engine import (
    RiskBreakdown,
    asymptotic_normalize,
    combine_risk,
    mandelbrot_entropy_proxy,
)

_WEIGHTS = {
    "rhythm": 0.22,
    "graph": 0.22,
    "context": 0.18,
    "user": 0.18,
    "data_quality": 0.20,
}

_VECTORS = RiskBreakdown(rhythm=0.8, graph=0.7, context=0.6, user=0.5, data_quality=0.4)


class TestAsymptoticSafety:
    """Асимптотическая безопасность: плато при экстремальном EPS."""

    def test_100k_eps_stays_below_1(self) -> None:
        """При 100 000 EPS риск не превышает 1.0 и близок к плато."""
        assessment = combine_risk(
            _VECTORS,
            _WEIGHTS,
            dq_score=0.8,
            eps_estimate=100_000,
            mandel_cap=2.5,
            eps_soft_cap=100_000,
        )
        assert 0.0 <= assessment.score <= 1.0
        assert assessment.score < 1.0  # не насыщается

    def test_1m_eps_stays_below_1(self) -> None:
        """При 1 000 000 EPS риск остаётся ограниченным."""
        assessment = combine_risk(
            _VECTORS,
            _WEIGHTS,
            dq_score=0.8,
            eps_estimate=1_000_000,
            mandel_cap=2.5,
            eps_soft_cap=100_000,
        )
        assert 0.0 <= assessment.score <= 1.0

    def test_asymptotic_normalize_plateau(self) -> None:
        """asymptotic_normalize(raw, cap) → 1.0 при raw → ∞."""
        assert asymptotic_normalize(0, 100_000) == 0.0
        assert asymptotic_normalize(100_000, 100_000) == pytest.approx(0.5)
        assert asymptotic_normalize(1_000_000, 100_000) == pytest.approx(0.909, abs=0.01)
        assert asymptotic_normalize(1_000_000_000, 100_000) < 1.0
        assert asymptotic_normalize(1e18, 100_000) < 1.0

    def test_mandelbrot_entropy_proxy_bounds(self) -> None:
        """mandelbrot_entropy_proxy возвращает 0..1."""
        assert mandelbrot_entropy_proxy([], 2.5) == 1.0
        assert 0.0 <= mandelbrot_entropy_proxy([0.1, 0.2, 0.3], 2.5) <= 1.0
        assert 0.0 <= mandelbrot_entropy_proxy([0.0, 1.0, 0.0, 1.0], 0.01) <= 1.0

    def test_risk_monotonic_with_eps(self) -> None:
        """Риск монотонно не убывает с ростом EPS (при прочих равных)."""
        scores = []
        for eps in [100, 1_000, 10_000, 100_000, 1_000_000]:
            a = combine_risk(
                _VECTORS,
                _WEIGHTS,
                dq_score=0.8,
                eps_estimate=eps,
                mandel_cap=2.5,
                eps_soft_cap=100_000,
            )
            scores.append(a.score)
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 0.001  # допускаем погрешность округления

    def test_100k_combine_risk_performance(self) -> None:
        """Производительность: 100 000 вызовов combine_risk за < 10 секунд."""
        start = time.monotonic()
        for _ in range(100_000):
            combine_risk(
                _VECTORS,
                _WEIGHTS,
                dq_score=0.8,
                eps_estimate=100_000,
                mandel_cap=2.5,
                eps_soft_cap=100_000,
            )
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"100k combine_risk calls took {elapsed:.2f}s"
