"""Объяснение оценки риска.

Правка от 2026-08-21: класс риска и сработавшие правила печатаются русскими названиями вместо
кодов (`класс высокий` вместо `класс HIGH`, «Серия неуспешных аутентификаций» вместо
`brute_force`). Объяснение читает человек, а не машина. Проверки ниже переписаны под новое
поведение осознанно, по команде владельца; состав объяснения и вычисления не менялись — см.
пометку о сверке с формулой изобретения в `xai.py`.
"""

from __future__ import annotations

from takt.domain.engines.risk_engine import RiskAssessment, RiskBreakdown
from takt.domain.engines.xai import XAIReport, build_xai
from takt.domain.invariants.catalog import invariant_titles_by_id


def test_build_xai_strings_include_scores_and_hits():
    assessment = RiskAssessment(
        score=0.73,
        risk_class="HIGH",
        breakdown=RiskBreakdown(
            rhythm=0.5,
            graph=0.6,
            context=0.4,
            user=0.55,
            data_quality=0.3,
        ),
    )
    out = build_xai(
        assessment,
        invariant_hits=["jump_server_bypass", "stale_data"],
        context_note="Фаза: NIGHT.",
    )
    titles = invariant_titles_by_id()
    assert isinstance(out, XAIReport)
    assert "0.73" in out.what
    assert "класс высокий" in out.what
    assert titles["jump_server_bypass"] in out.why_unusual
    assert titles["stale_data"] in out.why_unusual
    # Идентификаторы остаются ключами выбора рекомендации и контрфакта, но в текст не идут.
    assert "jump_server_bypass" not in out.why_unusual
    assert "Фаза: NIGHT." in out.why_unusual
    assert "ритм=0.50" in out.why_unusual
    assert len(out.recommendation) > 10
    assert len(out.counterfactual) > 10


def test_build_xai_no_hits_placeholder():
    assessment = RiskAssessment(
        score=0.12,
        risk_class="LOW",
        breakdown=RiskBreakdown(0.1, 0.1, 0.1, 0.1, 0.1),
    )
    out = build_xai(assessment, invariant_hits=[], context_note="Контекст ок.")
    assert "нет срабатываний инвариантов" in out.why_unusual
