from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

# Референсное отношение при классе бифуркаций (используется только как число для эвристики, см. docs/feigenbaum_rationale.md).
BIFURCATION_RATIO_REFERENCE = 4.669201609
FEIGENBAUM_DELTA = BIFURCATION_RATIO_REFERENCE


@dataclass(frozen=True, slots=True)
class ChaosPrediction:
    """Результат Chaos Predictor для ряда интервалов опроса (мкс или относит.)."""

    bifurcation_ratio: float
    suggests_period_doubling_cluster: bool
    jitter_trend_increasing: bool


def predict_polling_chaos(intervals_us: Sequence[float]) -> ChaosPrediction | None:
    """
    Упрощённая эвристика: отношение соседних разниц интервалов сравнивается с референсным
    коэффициентом бифуркаций; см. **docs/feigenbaum_rationale.md**.
    """
    if len(intervals_us) < 4:
        return None
    seq = [float(x) for x in intervals_us if float(x) > 0]
    if len(seq) < 4:
        return None
    gaps = [abs(seq[i + 1] - seq[i]) for i in range(len(seq) - 1)]
    if len(gaps) < 2 or gaps[-1] == 0:
        return None
    ratio = gaps[-1] / gaps[-2] if gaps[-2] else 0.0
    near = abs(ratio - BIFURCATION_RATIO_REFERENCE) < 0.35
    increasing = gaps[-1] > gaps[0]
    return ChaosPrediction(
        bifurcation_ratio=ratio,
        suggests_period_doubling_cluster=near and increasing,
        jitter_trend_increasing=increasing,
    )
