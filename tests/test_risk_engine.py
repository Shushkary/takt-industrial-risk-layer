from __future__ import annotations

import pytest

from takt.domain.engines.risk_engine import (
    RiskAssessment,
    RiskBreakdown,
    asymptotic_normalize,
    combine_risk,
    mandelbrot_entropy_proxy,
)


def test_asymptotic_normalize_plateau():
    assert asymptotic_normalize(0.0, 100_000) == pytest.approx(0.0)
    assert asymptotic_normalize(1_000_000.0, 100_000) < 1.0
    assert asymptotic_normalize(1_000_000.0, 100_000) == pytest.approx(
        1_000_000.0 / (1_000_000.0 + 100_000.0)
    )


def test_asymptotic_normalize_zero_cap():
    assert asymptotic_normalize(99.0, 0.0) == 0.0


def test_asymptotic_normalize_negative_raw_clamped():
    assert asymptotic_normalize(-50_000.0, 100_000.0) == pytest.approx(0.0)


def test_mandelbrot_entropy_proxy_empty():
    assert mandelbrot_entropy_proxy([], 2.5) == 1.0


def test_mandelbrot_entropy_proxy_low_variance_full_trust():
    assert mandelbrot_entropy_proxy([0.2, 0.21, 0.19], 2.5) == 1.0


def test_mandelbrot_entropy_proxy_high_variance_dampens():
    out = mandelbrot_entropy_proxy([0.0, 1.0, 0.0, 1.0, 0.0], entropy_cap=0.01)
    assert 0.0 < out < 1.0


def test_mandelbrot_entropy_proxy_identical_values_full_trust():
    assert mandelbrot_entropy_proxy([0.5, 0.5, 0.5], entropy_cap=0.01) == pytest.approx(1.0)


@pytest.mark.parametrize(
    ("vectors", "dq_score", "want_class"),
    [
        (
            RiskBreakdown(
                rhythm=0.95,
                graph=0.95,
                context=0.95,
                user=0.95,
                data_quality=0.95,
            ),
            1.0,
            "CRITICAL",
        ),
        (
            RiskBreakdown(
                rhythm=0.7,
                graph=0.7,
                context=0.7,
                user=0.7,
                data_quality=0.7,
            ),
            1.0,
            "HIGH",
        ),
        (
            RiskBreakdown(
                rhythm=0.45,
                graph=0.45,
                context=0.45,
                user=0.45,
                data_quality=0.45,
            ),
            1.0,
            "MEDIUM",
        ),
        (
            RiskBreakdown(
                rhythm=0.1,
                graph=0.1,
                context=0.1,
                user=0.1,
                data_quality=0.1,
            ),
            1.0,
            "LOW",
        ),
    ],
)
def test_combine_risk_class_buckets(
    vectors: RiskBreakdown,
    dq_score: float,
    want_class: str,
) -> None:
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
    }
    res = combine_risk(
        vectors,
        weights,
        dq_score=dq_score,
        eps_estimate=50_000_000.0,
        mandel_cap=100.0,
        eps_soft_cap=100_000.0,
    )
    assert res.risk_class == want_class
    assert 0.0 <= res.score <= 1.0


def test_combine_risk_higher_dq_score_increases_final_score():
    """dq_score — качество данных источника; выше dq_score → больший dq_factor → выше итог."""
    weights = {
        "rhythm": 0.2,
        "graph": 0.2,
        "context": 0.2,
        "user": 0.2,
        "data_quality": 0.2,
    }
    v = RiskBreakdown(
        rhythm=0.5,
        graph=0.5,
        context=0.5,
        user=0.5,
        data_quality=0.9,
    )
    high_dq = combine_risk(
        v, weights, dq_score=0.9, eps_estimate=50_000_000.0, mandel_cap=100.0, eps_soft_cap=100_000.0
    )
    low_dq = combine_risk(
        v, weights, dq_score=0.4, eps_estimate=50_000_000.0, mandel_cap=100.0, eps_soft_cap=100_000.0
    )
    assert high_dq.score > low_dq.score


def test_combine_risk_returns_assessment_with_same_breakdown():
    weights = {
        "rhythm": 0.2,
        "graph": 0.2,
        "context": 0.2,
        "user": 0.2,
        "data_quality": 0.2,
    }
    v = RiskBreakdown(rhythm=0.1, graph=0.2, context=0.3, user=0.4, data_quality=0.5)
    res = combine_risk(v, weights, dq_score=1.0, eps_estimate=50_000_000.0, mandel_cap=100.0, eps_soft_cap=100_000.0)
    assert isinstance(res, RiskAssessment)
    assert res.breakdown is v
