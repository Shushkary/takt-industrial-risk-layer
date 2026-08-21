"""Обоснованность вывода по делу: единый показатель и перечень недостающего.

Разрыв G-3 из [`docs/customer_value_map.md`](../docs/customer_value_map.md): на этапе
«подтверждение инцидента» клиент говорит «нет доверия к данным». Продукт уже считает всё
нужное — `dq_score`, `partial_observability`, доверие к источнику, обоснование корреляции, —
но по четырём разным местам, и назвать одну величину аналитик не может.

Здесь закреплены три свойства расчёта, на которых держится продуктовое обещание:

1. Полный контекст и `partial_observability` дают **разные** значения обоснованности.
2. Перечень недостающего непуст **ровно тогда**, когда вердикт неопределённый (`UNDET`).
   Это и есть «сказать неопределённость вслух»: `UNDET` без маршрута добора бесполезен,
   а определённый вердикт не должен изображать нехватку контекста.
3. Расчёт детерминирован — он попадает в карточку и в доказательный пакет, повторный прогон
   обязан дать то же значение (`docs/product_boundary.md`, «Детерминизм вердикта»).

Смежное: `tests/test_domain_ast_policy.py` (запрет недетерминизма в домене),
`tests/test_verdict_determinism_guard.py` (запрет сети и случайности в контуре вердикта).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from takt.domain.entities.case import (
    Case,
    CaseStatus,
    CorrelationEvidence,
    FormalVerdictRecord,
    ManualPermit,
    Observation,
    VerdictCounterfactual,
)
from takt.domain.services.verdict_confidence import (
    CONFIDENCE_WEIGHTS,
    GRADE_HIGH,
    GRADE_LOW,
    GRADE_MEDIUM,
    verdict_confidence,
)

_TRIAD = ("LEG", "ILLEG", "UNDET")
_GRADES = (GRADE_HIGH, GRADE_MEDIUM, GRADE_LOW)

_TS = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


def _permit(verdict: str, counterfactual: VerdictCounterfactual) -> ManualPermit:
    return ManualPermit(
        permit_id="p-1",
        case_id="c-1",
        work_order_number="НР-42",
        actor="analyst",
        created_at=_TS,
        asset_id="PLC-01",
        operation="WRITE_REGISTER",
        verdict=verdict,
        confidence=0.9,
        rationale="",
        counterfactual="",
        counterfactual_struct=counterfactual.to_dict(),
    )


def _case(**overrides: object) -> Case:
    base = Case(
        case_id="c-1",
        status=CaseStatus.TRIAGE,
        title="Запись в регистр ПЛК",
        risk_class="HIGH",
        risk_score=0.8,
        created_at=_TS,
        normalized_event_ids=["e-1", "e-2"],
        primary_asset_id="PLC-01",
        trigger_operation="WRITE_REGISTER",
        observations=[Observation(source="ndr", ingest_trust=0.9, event_ids=["e-1", "e-2"])],
        correlation_evidence=[
            CorrelationEvidence(event_id="e-1", fingerprint="f", rule="host_id"),
            CorrelationEvidence(event_id="e-2", fingerprint="f", rule="host_id"),
        ],
        dq_score=1.0,
        dq_partial=False,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _legitimate_case() -> Case:
    counterfactual = VerdictCounterfactual(
        verdict="legitimate",
        asset="PLC-01",
        operation="WRITE_REGISTER",
        sanctioning_party="Иванов",
        admissible_window="2026-08-21T08:00..2026-08-21T12:00",
        required_document="НР-42",
    )
    return _case(manual_permits=[_permit("legitimate", counterfactual)])


def _undetermined_case() -> Case:
    counterfactual = VerdictCounterfactual(
        verdict="undetermined",
        unmet_conditions=("утверждающий", "окно работ"),
        asset="PLC-01",
        operation="WRITE_REGISTER",
        required_document="НР-42",
    )
    return _case(manual_permits=[_permit("undetermined", counterfactual)])


def test_weights_sum_to_one() -> None:
    """Веса — часть объяснения показателя, их сумма обязана быть единицей."""
    assert round(sum(CONFIDENCE_WEIGHTS.values()), 9) == 1.0


def test_full_context_gives_high_grade_and_no_missing() -> None:
    result = verdict_confidence(_legitimate_case())

    assert result.verdict == "LEG"
    assert result.grade == GRADE_HIGH
    assert result.score > 0.9
    assert result.missing == ()


def test_partial_observability_lowers_score() -> None:
    """Приёмка G-3: полный контекст и деградированная наблюдаемость различимы по числу."""
    full = verdict_confidence(_legitimate_case())

    degraded_case = _legitimate_case()
    degraded_case.dq_score = 0.4
    degraded_case.dq_partial = True
    degraded_case.dq_reasons = ["источник scada не отдавал события в окне 09:00-09:15"]
    degraded = verdict_confidence(degraded_case)

    assert degraded.score < full.score
    # Нехватка наблюдаемости объясняется в составляющей, но маршрутом добора не является:
    # вердикт определён, добирать организационный документ не нужно.
    assert degraded.missing == ()
    dq_component = next(c for c in degraded.components if c.key == "data_quality")
    assert "scada" in " ".join(dq_component.reasons)


def test_low_source_trust_lowers_score() -> None:
    full = verdict_confidence(_legitimate_case())

    untrusted_case = _legitimate_case()
    untrusted_case.observations = [Observation(source="syslog", ingest_trust=0.2, event_ids=["e-1"])]

    assert verdict_confidence(untrusted_case).score < full.score


def test_event_without_correlation_evidence_lowers_score() -> None:
    full = verdict_confidence(_legitimate_case())

    unexplained_case = _legitimate_case()
    unexplained_case.normalized_event_ids = ["e-1", "e-2", "e-3"]

    result = verdict_confidence(unexplained_case)
    correlation = next(c for c in result.components if c.key == "correlation")

    assert result.score < full.score
    assert any("e-3" in reason for reason in correlation.reasons)


def test_undetermined_case_lists_missing_context() -> None:
    result = verdict_confidence(_undetermined_case())

    assert result.verdict == "UNDET"
    assert [item.text for item in result.missing] == ["окно работ", "утверждающий"]
    assert all(item.required_document == "НР-42" for item in result.missing)


def test_grade_is_capped_while_context_is_missing() -> None:
    """Пока маршрут добора непуст, обоснованность не может называться высокой."""
    case = _undetermined_case()
    case.dq_score = 1.0
    case.observations = [Observation(source="ndr", ingest_trust=1.0, event_ids=["e-1", "e-2"])]

    result = verdict_confidence(case)

    assert result.missing != ()
    assert result.grade == GRADE_MEDIUM


def test_case_without_organizational_document_reports_route() -> None:
    """Дело без наряда: неопределённость названа, и сказано, чего именно не хватает."""
    result = verdict_confidence(_case())

    assert result.verdict == "UNDET"
    assert len(result.missing) == 1
    assert result.missing[0].kind == "document"
    assert "организационн" in result.missing[0].text.lower()
    assert next(c for c in result.components if c.key == "organizational_context").value == 0.0


def test_undetermined_permit_without_explicit_conditions_still_has_route() -> None:
    """Наряд без привязки к активу: `unmet_conditions` пуст, но маршрут добора обязан быть."""
    counterfactual = VerdictCounterfactual(verdict="undetermined", required_document="НР-42")
    case = _case(manual_permits=[_permit("undetermined", counterfactual)])

    result = verdict_confidence(case)

    assert result.verdict == "UNDET"
    assert result.missing != ()


def test_illegitimate_verdict_has_no_missing_route() -> None:
    """Нелегитимное — вердикт определён: расхождение доказано, добирать нечего."""
    counterfactual = VerdictCounterfactual(
        verdict="illegitimate",
        mismatches=({"field": "asset", "expected": "PLC-01", "actual": "PLC-09"},),
        required_document="НР-42",
    )
    case = _case(manual_permits=[_permit("illegitimate", counterfactual)])

    result = verdict_confidence(case)

    assert result.verdict == "ILLEG"
    assert result.missing == ()
    assert next(c for c in result.components if c.key == "organizational_context").value == 1.0


def test_operator_confirmation_of_undetermined_keeps_route() -> None:
    """Оператор подтвердил неопределённость — маршрут добора не исчезает."""
    case = _undetermined_case()
    case.formal_verdict_records = [
        FormalVerdictRecord(
            ts=_TS,
            actor="analyst",
            prev="неопределённое",
            next="неопределённое",
            score=0.5,
            source="operator_confirmation",
            reason="контекст не найден",
        )
    ]

    result = verdict_confidence(case)

    assert result.verdict == "UNDET"
    assert result.missing != ()


def test_missing_route_is_non_empty_exactly_for_undetermined() -> None:
    """Ключевой инвариант: маршрут добора ⟺ неопределённый вердикт."""
    for case in (_legitimate_case(), _undetermined_case(), _case()):
        result = verdict_confidence(case)
        assert bool(result.missing) == (result.verdict == "UNDET")


def test_result_stays_inside_declared_vocabulary() -> None:
    """Значения уходят во внешние выгрузки — словарь вердиктов и оценок закрыт."""
    for case in (_legitimate_case(), _undetermined_case(), _case()):
        result = verdict_confidence(case)
        assert result.verdict in _TRIAD
        assert result.grade in _GRADES
        assert 0.0 <= result.score <= 1.0
        assert {c.key for c in result.components} == set(CONFIDENCE_WEIGHTS)


def test_result_is_deterministic_and_order_independent() -> None:
    """Показатель идёт в карточку и в пакет: повторный прогон обязан совпасть побитово."""
    case = _undetermined_case()
    case.dq_reasons = ["источник b", "источник a"]
    case.observations = [
        Observation(source="scada", ingest_trust=0.7, event_ids=["e-2"]),
        Observation(source="ndr", ingest_trust=0.9, event_ids=["e-1"]),
    ]

    first = verdict_confidence(case)

    shuffled = _undetermined_case()
    shuffled.dq_reasons = ["источник b", "источник a"]
    shuffled.observations = list(reversed(case.observations))
    shuffled.correlation_evidence = list(reversed(case.correlation_evidence))
    second = verdict_confidence(shuffled)

    assert first == second
    assert first.to_dict() == second.to_dict()
    # `replace` на frozen-датаклассе: структура остаётся сравнимой и не мутирует исходник.
    assert replace(first, score=first.score) == first
