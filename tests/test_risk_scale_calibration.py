"""Калибровка шкалы классов риска: пороги назначены по достижимому максимуму.

Достижимый максимум балла равен 1.000. Так было не всегда: пока `combine_risk` умножал итог
на множитель, выведенный из `dq_score`, вектор качества данных и этот множитель были связаны
обратно (вектор равен `1 - dq_score`), поднять вектор можно было только ценой множителя, и
потеря всегда превышала прибавку — вес 0.20 оставался недостижимым, а потолок шкалы равнялся
0.800. Под этот потолок пороги и пересчитывались 2026-08-24 (0.68 / 0.52 / 0.32).

Множитель снят решением владельца: качество данных влияет одним каналом — своим взвешенным
вектором, наравне с остальными четырьмя измерениями. Потолок вернулся к 1.000, пороги
откачены к исходным 0.85 / 0.65 / 0.40.

Здесь закреплено, что потолок именно такой, что пороги из конфигурации ему соответствуют и что
доли шкалы сохранены — иначе следующая правка порогов снова разойдётся с тем, что модель
способна выдать.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from takt.domain.engines.risk_engine import RiskBreakdown, combine_risk

_WEIGHTS = {"rhythm": 0.22, "graph": 0.22, "context": 0.18, "user": 0.18, "data_quality": 0.20}
_CEILING = 1.000
# Доли шкалы, заданные исходной калибровкой: критический — 85% шкалы, высокий — 65%, средний — 40%.
_SHARES = {"critical": 0.85, "high": 0.65, "medium": 0.40}


def _configured_thresholds() -> dict[str, float]:
    path = Path(__file__).resolve().parents[1] / "config" / "risk_weights.yaml"
    with path.open(encoding="utf-8") as handle:
        return dict(yaml.safe_load(handle)["risk_class_thresholds"])


def _score(dq_score: float, thresholds: dict[str, float]) -> tuple[float, str]:
    """Все признаки на максимуме; вектор качества связан с dq_score, как в продукте."""
    assessment = combine_risk(
        RiskBreakdown(rhythm=1.0, graph=1.0, context=1.0, user=1.0, data_quality=1.0 - dq_score),
        _WEIGHTS,
        dq_score=dq_score,
        eps_estimate=0.02,
        mandel_cap=2.5,
        eps_soft_cap=100_000,
        risk_class_thresholds=thresholds,
    )
    return assessment.score, assessment.risk_class


def test_scale_ceiling_is_one() -> None:
    """Вес вектора качества обналичивается: при полном наборе признаков балл доходит до 1.0."""
    best = max(_score(step / 20, _configured_thresholds())[0] for step in range(21))

    assert best == pytest.approx(_CEILING, abs=0.001)


def test_every_class_is_reachable() -> None:
    """Порог выше достижимого максимума означает класс, которого не бывает."""
    thresholds = _configured_thresholds()

    for name, value in thresholds.items():
        assert value <= _CEILING, f"порог {name}={value} выше достижимого максимума {_CEILING}"


def test_top_of_the_scale_is_critical() -> None:
    """Полный набор признаков — включая вектор качества — обязан давать верхний класс.

    Вектор качества максимален при `dq_score = 0`: данных не видно совсем. Раньше такой набор
    давал ровно ноль (итог умножался на `dq_score`), теперь это верх шкалы.
    """
    score, risk_class = _score(0.0, _configured_thresholds())

    assert score == pytest.approx(_CEILING, abs=0.001)
    assert risk_class == "CRITICAL"


def test_full_data_leaves_only_the_quality_weight_unused() -> None:
    """При идеальных данных недобор ровно на вес вектора качества, а не больше.

    Это цена того, что качество — измерение наравне с остальными: при полных данных его
    вектор равен нулю. 0.800 — прежний потолок всей шкалы, теперь это верх её «чистой» части.
    """
    score, risk_class = _score(1.0, _configured_thresholds())

    assert score == pytest.approx(1.0 - _WEIGHTS["data_quality"], abs=0.001)
    assert risk_class == "HIGH"


def test_thresholds_keep_the_original_shares_of_the_scale() -> None:
    """Пороги — исходные доли шкалы: 85% / 65% / 40% от достижимого максимума."""
    thresholds = _configured_thresholds()

    for name, share in _SHARES.items():
        assert thresholds[name] == pytest.approx(share * _CEILING, abs=0.005), name
