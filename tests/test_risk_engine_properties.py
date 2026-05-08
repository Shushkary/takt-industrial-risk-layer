from __future__ import annotations

from unittest.mock import patch

from hypothesis import given, strategies as st

from takt.domain.engines.risk_engine import RiskBreakdown, combine_risk
from takt.domain.engines.risk_engine import worst_risk_class as wc


_WEIGHT_KEYS = ("rhythm", "graph", "context", "user", "data_quality")

_unit_weights = st.fixed_dictionaries(
    {k: st.floats(min_value=0.0, max_value=1.0, allow_nan=False) for k in _WEIGHT_KEYS}
).filter(lambda w: sum(w.values()) > 1e-9)


@given(
    rhythm=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    graph=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    context=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    user=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    data_quality_vec=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    dq_score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    eps=st.floats(min_value=0.0, max_value=1e6, allow_nan=False),
    mandel_cap=st.floats(min_value=1e-6, max_value=1.0, allow_nan=False),
    eps_soft_cap=st.floats(min_value=1e-6, max_value=1e6, allow_nan=False),
    weights=_unit_weights,
)
def test_combine_risk_score_bounded(
    rhythm: float,
    graph: float,
    context: float,
    user: float,
    data_quality_vec: float,
    dq_score: float,
    eps: float,
    mandel_cap: float,
    eps_soft_cap: float,
    weights: dict[str, float],
) -> None:
    vec = RiskBreakdown(
        rhythm=rhythm,
        graph=graph,
        context=context,
        user=user,
        data_quality=data_quality_vec,
    )
    out = combine_risk(
        vec,
        weights,
        dq_score=dq_score,
        eps_estimate=eps,
        mandel_cap=mandel_cap,
        eps_soft_cap=eps_soft_cap,
    )
    assert 0.0 <= out.score <= 1.0
    assert out.risk_class in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    again = combine_risk(
        vec,
        weights,
        dq_score=dq_score,
        eps_estimate=eps,
        mandel_cap=mandel_cap,
        eps_soft_cap=eps_soft_cap,
    )
    assert again.score == out.score
    assert again.risk_class == out.risk_class


_BREAKDOWN_FIVE = st.tuples(
    st.floats(min_value=0.0, max_value=0.75, allow_nan=False),
    st.floats(min_value=0.0, max_value=0.75, allow_nan=False),
    st.floats(min_value=0.0, max_value=0.75, allow_nan=False),
    st.floats(min_value=0.0, max_value=0.75, allow_nan=False),
    st.floats(min_value=0.0, max_value=0.75, allow_nan=False),
)


@given(
    base=_BREAKDOWN_FIVE,
    extra_bump=st.floats(min_value=0.01, max_value=0.24, allow_nan=False),
    axis=st.integers(min_value=0, max_value=4),
)
def test_combine_risk_monotone_in_breakdown_when_trust_fixed(
    base: tuple[float, ...],
    extra_bump: float,
    axis: int,
) -> None:
    """
    При фиксированном множителе доверия вклад wsum не убывает, если любая из осей breakdown
    не убывает (веса > 0): риск не должен «падать» из‑за усиления сигнала.
    """
    weights = {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
    }
    dq = 0.9
    eps = 10_000.0
    mandel_cap = 0.25
    eps_soft_cap = 100_000.0
    lo = RiskBreakdown(*base)
    hi_list = list(base)
    hi_list[axis] = min(1.0, hi_list[axis] + extra_bump)
    hi = RiskBreakdown(*hi_list)
    with patch("takt.domain.engines.risk_engine.mandelbrot_entropy_proxy", return_value=1.0):
        s_lo = combine_risk(lo, weights, dq_score=dq, eps_estimate=eps, mandel_cap=mandel_cap, eps_soft_cap=eps_soft_cap)
        s_hi = combine_risk(hi, weights, dq_score=dq, eps_estimate=eps, mandel_cap=mandel_cap, eps_soft_cap=eps_soft_cap)
    assert s_hi.score >= s_lo.score - 1e-12
    assert _risk_class_rank(s_hi.risk_class) >= _risk_class_rank(s_lo.risk_class)


def _risk_class_rank(rc: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(rc.upper(), -1)


def test_worst_risk_class_order() -> None:
    assert wc("LOW", "HIGH") == "HIGH"
    assert wc("CRITICAL", "MEDIUM") == "CRITICAL"
    assert wc("UNKNOWN", "LOW") == "UNKNOWN"
