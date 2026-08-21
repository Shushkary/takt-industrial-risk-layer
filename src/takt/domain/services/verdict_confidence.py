"""Обоснованность вывода по делу: одна величина, её разложение и маршрут добора контекста.

Зачем. Аналитик уже располагает всеми признаками достоверности — качеством данных,
доверием к источнику, обоснованием корреляции, полнотой организационного контекста, — но они
разложены по четырём разным местам карточки. В разговоре с руководителем или регулятором
назвать одно число он не может. Разрыв G-3 из ``docs/customer_value_map.md``.

Что считаем. Взвешенное среднее четырёх составляющих, каждая в диапазоне 0..1, плюс перечень
недостающего — что именно нужно добрать, чтобы снять неопределённость.

Ключевое правило: **перечень недостающего непуст ровно тогда, когда вердикт неопределённый**.
Неопределённость называется вслух и всегда сопровождается маршрутом добора; определённый
вердикт (легитимный или нелегитимный) маршрута не требует — он обоснован. Нехватка
наблюдаемости и слабая корреляция снижают показатель и объясняются в составляющих, но
маршрутом добора не являются: организационный документ они не заменяют и не требуют.

Пока маршрут добора непуст, обоснованность не может называться высокой, каким бы хорошим ни
было качество данных: без организационного контекста вывод о легитимности не следует из
данных вообще.

Расчёт детерминирован и не имеет ввода-вывода: значение попадает в карточку и в доказательный
пакет, поэтому повторный прогон на тех же данных обязан дать тот же результат
(``docs/product_boundary.md``, раздел «Детерминизм вердикта»).
"""

from __future__ import annotations

from dataclasses import dataclass

from takt.domain.entities.case import Case, VerdictCounterfactual
from takt.domain.services.forensic_verdict import case_forensic_verdict

GRADE_HIGH = "высокая"
GRADE_MEDIUM = "средняя"
GRADE_LOW = "низкая"

_HIGH_THRESHOLD = 0.75
_MEDIUM_THRESHOLD = 0.5

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "organizational_context": 0.40,
    "data_quality": 0.25,
    "source_trust": 0.20,
    "correlation": 0.15,
}
"""Вклад составляющих в итог.

Организационный контекст весит больше остальных, потому что именно он отделяет атаку от
согласованной работы: без него безупречные по качеству данные всё равно не дают вывода о
легитимности. Значения фиксированные и попадают в выдачу — показатель обязан быть проверяемым
без обращения к коду.
"""

_COMPONENT_TITLES: dict[str, str] = {
    "organizational_context": "Организационный контекст",
    "data_quality": "Качество данных",
    "source_trust": "Доверие к источникам",
    "correlation": "Обоснование корреляции",
}

# Вес обоснования привязки события к делу. Правило корреляции воспроизводимо; ручная привязка
# с указанным основанием проверяема по журналу; ручная привязка без основания — слабейшее звено.
_EVIDENCE_RULE = 1.0
_EVIDENCE_MANUAL_WITH_REASON = 0.9
_EVIDENCE_MANUAL_WITHOUT_REASON = 0.6

# Организационный контекст приложен, но неполон: вывод опирается на документ, который сам
# требует добора. Половина — не измеренная величина, а объявленная позиция шкалы.
_CONTEXT_PARTIAL = 0.5

_TRIAD_BY_VERDICT: dict[str, str] = {
    "легитимное": "LEG",
    "нелегитимное": "ILLEG",
    "неопределённое": "UNDET",
}


@dataclass(frozen=True, slots=True)
class ConfidenceComponent:
    """Одна составляющая показателя с объяснением, почему она не равна единице."""

    key: str
    title_ru: str
    value: float
    weight: float
    reasons: tuple[str, ...] = ()

    @property
    def contribution(self) -> float:
        return self.value * self.weight

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "title_ru": self.title_ru,
            "value": round(self.value, 4),
            "weight": self.weight,
            "contribution": round(self.contribution, 4),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class MissingContextItem:
    """Чего не хватает и где это взять."""

    kind: str
    text: str
    required_document: str | None = None
    sanctioning_party: str | None = None
    admissible_window: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "text": self.text,
            "required_document": self.required_document,
            "sanctioning_party": self.sanctioning_party,
            "admissible_window": self.admissible_window,
        }


@dataclass(frozen=True, slots=True)
class VerdictConfidence:
    """Обоснованность вывода: величина, оценка словом, разложение и маршрут добора."""

    verdict: str
    score: float
    grade: str
    components: tuple[ConfidenceComponent, ...]
    missing: tuple[MissingContextItem, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 4),
            "grade": self.grade,
            "components": [component.to_dict() for component in self.components],
            "missing": [item.to_dict() for item in self.missing],
        }


def verdict_confidence(case: Case) -> VerdictConfidence:
    """Свести признаки достоверности дела в один проверяемый показатель."""
    forensic = case_forensic_verdict(case)
    triad = _TRIAD_BY_VERDICT.get(forensic.value, "UNDET")

    counterfactual = _latest_counterfactual(case)
    missing = _missing_context(triad, counterfactual, case) if triad == "UNDET" else ()

    components = (
        _organizational_context_component(triad, case),
        _data_quality_component(case),
        _source_trust_component(case),
        _correlation_component(case),
    )
    score = sum(component.contribution for component in components)
    return VerdictConfidence(
        verdict=triad,
        score=_clamp(score),
        grade=_grade(score, has_missing=bool(missing)),
        components=components,
        missing=missing,
    )


def _grade(score: float, *, has_missing: bool) -> str:
    """Оценка словом. Пока маршрут добора непуст, «высокой» обоснованность не бывает."""
    if score >= _HIGH_THRESHOLD:
        return GRADE_MEDIUM if has_missing else GRADE_HIGH
    if score >= _MEDIUM_THRESHOLD:
        return GRADE_MEDIUM
    return GRADE_LOW


def _latest_counterfactual(case: Case) -> VerdictCounterfactual | None:
    """Контрфакт последнего приложенного наряда — источник перечня недостающего."""
    if not case.manual_permits:
        return None
    return VerdictCounterfactual.from_dict(case.manual_permits[-1].counterfactual_struct)


def _missing_context(
    triad: str,
    counterfactual: VerdictCounterfactual | None,
    case: Case,
) -> tuple[MissingContextItem, ...]:
    """Маршрут добора для неопределённого вердикта.

    Вызывается только при ``UNDET`` и обязан вернуть непустой перечень: неопределённость без
    указания, что именно добрать, оставляет клиента там же, где он был до ТАКТ.
    """
    if counterfactual is None:
        return (
            MissingContextItem(
                kind="document",
                text=(
                    "к делу не приложен организационный документ: наряд, заявка или окно работ"
                    f" по активу {case.primary_asset_id or 'дела'}"
                ),
            ),
        )

    items = [
        MissingContextItem(
            kind="document",
            text=condition,
            required_document=counterfactual.required_document,
            sanctioning_party=counterfactual.sanctioning_party,
            admissible_window=counterfactual.admissible_window,
        )
        for condition in counterfactual.unmet_conditions
        if condition.strip()
    ]
    if not items:
        # Наряд приложен, но сверка с делом невозможна: конкретных невыполненных условий нет,
        # а вердикт всё равно неопределённый. Маршрут добора — привязка документа к делу.
        items = [
            MissingContextItem(
                kind="document",
                text=(
                    "организационный документ не привязан к активу и операции дела —"
                    " сверка невозможна"
                ),
                required_document=counterfactual.required_document,
                sanctioning_party=counterfactual.sanctioning_party,
                admissible_window=counterfactual.admissible_window,
            )
        ]
    return tuple(sorted(items, key=lambda item: item.text))


def _organizational_context_component(triad: str, case: Case) -> ConfidenceComponent:
    """Полнота организационного контекста — та составляющая, что и определяет вердикт."""
    if triad in ("LEG", "ILLEG"):
        value = 1.0
        reasons: tuple[str, ...] = ()
    elif case.manual_permits:
        value = _CONTEXT_PARTIAL
        reasons = ("организационный документ приложен, но сверка с делом не завершена",)
    else:
        value = 0.0
        reasons = ("организационный документ к делу не приложен",)
    return _component("organizational_context", value, reasons)


def _data_quality_component(case: Case) -> ConfidenceComponent:
    reasons = [reason for reason in case.dq_reasons if reason.strip()]
    if case.dq_partial:
        reasons.append("наблюдаемость неполная (partial_observability)")
    return _component("data_quality", case.dq_score, tuple(sorted(reasons)))


def _source_trust_component(case: Case) -> ConfidenceComponent:
    """Доверие к источникам по слабейшему звену: вывод не крепче худшего из каналов."""
    if not case.observations:
        return _component("source_trust", 0.0, ("источники наблюдений в деле не зафиксированы",))
    weakest = min(case.observations, key=lambda observation: (observation.ingest_trust, observation.source))
    reasons: tuple[str, ...] = ()
    if weakest.ingest_trust < 1.0:
        reasons = (f"слабейший источник {weakest.source}: доверие {weakest.ingest_trust:.2f}",)
    return _component("source_trust", weakest.ingest_trust, reasons)


def _correlation_component(case: Case) -> ConfidenceComponent:
    """Доля событий дела, привязка которых обоснована, с поправкой на способ привязки."""
    event_ids = sorted(set(case.normalized_event_ids))
    if not event_ids:
        return _component("correlation", 0.0, ("к делу не привязано ни одного события",))

    weight_by_event: dict[str, float] = {}
    for evidence in case.correlation_evidence:
        if evidence.manual:
            weight = _EVIDENCE_MANUAL_WITH_REASON if evidence.reason.strip() else _EVIDENCE_MANUAL_WITHOUT_REASON
        else:
            weight = _EVIDENCE_RULE
        weight_by_event[evidence.event_id] = max(weight_by_event.get(evidence.event_id, 0.0), weight)

    unexplained = [event_id for event_id in event_ids if event_id not in weight_by_event]
    manual_without_reason = sorted(
        event_id
        for event_id, weight in weight_by_event.items()
        if weight == _EVIDENCE_MANUAL_WITHOUT_REASON
    )
    value = sum(weight_by_event.get(event_id, 0.0) for event_id in event_ids) / len(event_ids)

    reasons: list[str] = []
    if unexplained:
        reasons.append("привязка не обоснована для событий: " + ", ".join(unexplained))
    if manual_without_reason:
        reasons.append("ручная привязка без основания: " + ", ".join(manual_without_reason))
    return _component("correlation", value, tuple(reasons))


def _component(key: str, value: float, reasons: tuple[str, ...]) -> ConfidenceComponent:
    return ConfidenceComponent(
        key=key,
        title_ru=_COMPONENT_TITLES[key],
        value=_clamp(value),
        weight=CONFIDENCE_WEIGHTS[key],
        reasons=reasons,
    )


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))
