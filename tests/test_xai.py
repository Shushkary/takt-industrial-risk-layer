from __future__ import annotations

from takt.domain.engines.risk_engine import RiskAssessment, RiskBreakdown
from takt.domain.engines.xai import XAIReport, build_xai


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
    assert isinstance(out, XAIReport)
    assert "0.73" in out.what
    assert "HIGH" in out.what
    assert "jump_server_bypass" in out.why_unusual
    assert "stale_data" in out.why_unusual
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
