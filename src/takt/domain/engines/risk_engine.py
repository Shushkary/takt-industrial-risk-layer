from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class RiskBreakdown:
    rhythm: float
    graph: float
    context: float
    user: float
    data_quality: float


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    risk_class: str
    breakdown: RiskBreakdown


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def asymptotic_normalize(raw: float, cap: float) -> float:
    """Плато при экстремальной нагрузке (мягкая отсечка)."""
    if cap <= 0:
        return 0.0
    return _clamp(raw / (raw + cap))


def mandelbrot_entropy_proxy(values: list[float], entropy_cap: float) -> float:
    """
    Упрощённый «порог устойчивости»: дисперсия нормированных вкладов не выше cap.
    Возвращает множитель доверия 0..1.
    """
    if not values:
        return 1.0
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / len(values)
    if var <= entropy_cap:
        return 1.0
    return _clamp(entropy_cap / var if var else 1.0)


def combine_risk(
    vectors: RiskBreakdown,
    weights: Mapping[str, float],
    *,
    dq_score: float,
    eps_estimate: float,
    mandel_cap: float,
    eps_soft_cap: float,
    risk_class_thresholds: Mapping[str, float] | None = None,
) -> RiskAssessment:
    """
    Risk = F(R, G, C, U, DQ) с учётом деградации DQ и асимптотики EPS.
    Пороги классов риска задаются через risk_class_thresholds (из YAML).
    """
    wsum = (
        weights["rhythm"] * vectors.rhythm
        + weights["graph"] * vectors.graph
        + weights["context"] * vectors.context
        + weights["user"] * vectors.user
        + weights["data_quality"] * vectors.data_quality
    )
    dq_factor = _clamp(dq_score if dq_score >= 0.5 else dq_score * 1.2)
    burst = asymptotic_normalize(eps_estimate, eps_soft_cap)
    # ВНИМАНИЕ при калибровке. Множитель растёт с интенсивностью потока — это намеренное
    # свойство, закреплённое `tests/test_risk_engine_100k_eps.py::test_risk_monotonic_with_eps`.
    # Следствие, о котором легко забыть: при `eps_soft_cap = 100000` (config/risk_weights.yaml)
    # `burst` не отрывается от нуля на достижимых частотах (10 000 соб/с — 0.09), множитель
    # равен 0.5, и потолок оценки — 0.5. Пороги HIGH (0.65) и CRITICAL (0.85) при такой
    # калибровке недостижимы: в `tests/test_risk_engine.py` они проверяются на
    # `eps_estimate=50_000_000`. Разбор и варианты — `docs/risk_scale_calibration.md`.
    adj = wsum * dq_factor * (0.5 + 0.5 * burst)
    trust = mandelbrot_entropy_proxy(
        [vectors.rhythm, vectors.graph, vectors.context, vectors.user, vectors.data_quality],
        mandel_cap,
    )
    score = _clamp(adj * trust)
    thresholds = risk_class_thresholds or {}
    critical = float(thresholds.get("critical", 0.85))
    high = float(thresholds.get("high", 0.65))
    medium = float(thresholds.get("medium", 0.4))
    if score >= critical:
        rclass = "CRITICAL"
    elif score >= high:
        rclass = "HIGH"
    elif score >= medium:
        rclass = "MEDIUM"
    else:
        rclass = "LOW"
    return RiskAssessment(score=score, risk_class=rclass, breakdown=vectors)


_RISK_CLASS_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def worst_risk_class(a: str, b: str) -> str:
    """Более «тяжёлый» из двух классов (для тот же score или агрегации при merge)."""
    ra = _RISK_CLASS_RANK.get(a.upper(), 0)
    rb = _RISK_CLASS_RANK.get(b.upper(), 0)
    return a if ra >= rb else b
