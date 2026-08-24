"""Шкала классов риска по контурам: расчёт один, пороги разные.

Достижимый максимум балла равен 0.800, а не 1.0: вектор качества данных и множитель качества
связаны обратно — вектор равен `1 - dq_score`, а итог умножается на `dq_score`. Поднять вектор
можно только ценой множителя, и вес 0.20 остаётся недостижимым. Пороги промышленной шкалы
(0.65 / 0.85) назначены как доли от 1.0, поэтому «критический» недостижим, а в SOC-контуре,
где промышленные векторы не поднимаются срабатываниями, недостижим и «высокий».

Здесь закреплено, что: потолок шкалы именно такой, шкала выбирается контуром, и выбор идёт
в один ключ, который читают и оценка события, и сборка инцидента.
"""

from __future__ import annotations

import pytest

from takt.domain.engines.risk_engine import RiskBreakdown, combine_risk
from takt.infrastructure.config.settings_helpers import apply_risk_scale

_WEIGHTS = {"rhythm": 0.22, "graph": 0.22, "context": 0.18, "user": 0.18, "data_quality": 0.20}
_INDUSTRIAL = {"critical": 0.85, "high": 0.65, "medium": 0.4}
_SOC = {"critical": 0.68, "high": 0.52, "medium": 0.32}


def _score(dq_score: float, thresholds: dict[str, float]) -> tuple[float, str]:
    """Все признаки на максимуме; вектор качества связан с множителем, как в продукте."""
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


def test_scale_ceiling_is_below_the_critical_threshold() -> None:
    """Потолок шкалы 0.800 — «критический» по промышленным порогам недостижим."""
    best = max(_score(step / 20, _INDUSTRIAL)[0] for step in range(21))

    assert best == pytest.approx(0.800, abs=0.001)
    assert best < _INDUSTRIAL["critical"], "порог critical назначен выше достижимого максимума"


def test_soc_thresholds_keep_the_same_shares_of_the_scale() -> None:
    """Доли шкалы те же, что в промышленном контуре, — пересчитаны на достижимые 0.800."""
    ceiling = 0.800

    assert _SOC["critical"] == pytest.approx(_INDUSTRIAL["critical"] * ceiling, abs=0.005)
    assert _SOC["high"] == pytest.approx(_INDUSTRIAL["high"] * ceiling, abs=0.005)
    assert _SOC["medium"] == pytest.approx(_INDUSTRIAL["medium"] * ceiling, abs=0.005)


def test_industrial_scale_is_left_untouched() -> None:
    """Контур по умолчанию — промышленный: шкала под сертификацией не меняется молча."""
    weights = {"risk_class_thresholds": dict(_INDUSTRIAL), "risk_class_thresholds_soc": dict(_SOC)}

    apply_risk_scale(weights)

    assert weights["risk_class_thresholds"] == _INDUSTRIAL


def test_soc_scale_replaces_the_thresholds_read_by_both_use_cases() -> None:
    """Подстановка идёт в один ключ: и оценка события, и сборка инцидента читают его."""
    weights = {
        "risk_scale": "soc",
        "risk_class_thresholds": dict(_INDUSTRIAL),
        "risk_class_thresholds_soc": dict(_SOC),
    }

    apply_risk_scale(weights)

    assert weights["risk_class_thresholds"] == _SOC


def test_env_overrides_the_configured_scale(monkeypatch: pytest.MonkeyPatch) -> None:
    """Стенд SOC переключается переменной окружения, не правкой конфигурации в репозитории."""
    monkeypatch.setenv("TAKT_RISK_SCALE", "soc")
    weights = {"risk_class_thresholds": dict(_INDUSTRIAL), "risk_class_thresholds_soc": dict(_SOC)}

    apply_risk_scale(weights)

    assert weights["risk_class_thresholds"] == _SOC


def test_unknown_scale_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Опечатка в контуре не должна тихо оставлять промышленную шкалу."""
    monkeypatch.setenv("TAKT_RISK_SCALE", "сок")

    with pytest.raises(ValueError, match="risk scale"):
        apply_risk_scale({"risk_class_thresholds": dict(_INDUSTRIAL)})


def test_soc_scale_requires_its_thresholds() -> None:
    """Без секции порогов SOC выбор контура — молчаливое сохранение промышленной шкалы."""
    with pytest.raises(ValueError, match="risk_class_thresholds_soc"):
        apply_risk_scale({"risk_scale": "soc", "risk_class_thresholds": dict(_INDUSTRIAL)})
