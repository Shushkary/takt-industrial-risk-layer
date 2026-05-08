from __future__ import annotations

from dataclasses import dataclass

from takt.domain.engines.risk_engine import RiskAssessment


@dataclass(frozen=True, slots=True)
class XAIReport:
    what: str
    why_unusual: str
    recommendation: str
    counterfactual: str


def build_xai(
    assessment: RiskAssessment,
    *,
    invariant_hits: list[str],
    context_note: str,
) -> XAIReport:
    hits = ", ".join(invariant_hits) if invariant_hits else "нет срабатываний инвариантов"
    what = f"Агрегированный риск {assessment.score:.2f}, класс {assessment.risk_class}."
    why = (
        f"Вклады: ритм={assessment.breakdown.rhythm:.2f}, граф={assessment.breakdown.graph:.2f}, "
        f"контекст={assessment.breakdown.context:.2f}, пользователь={assessment.breakdown.user:.2f}, "
        f"DQ={assessment.breakdown.data_quality:.2f}. Инварианты: {hits}. {context_note}"
    )
    rec = "Назначить триаж оператору; проверить журналы источника и заявки Service Desk."
    cf = "Событие было бы типичным при действующем окне регламентных работ и известном jump-маршруте."
    return XAIReport(what=what, why_unusual=why, recommendation=rec, counterfactual=cf)
