"""Оценка сокращения ручных действий: что считается замером, а что расчётом.

Модуль `takt.application.use_cases.investigation_effort` сводит две разнородные величины, и тесты держат
границу между ними: число действий в ТАКТ берётся из журнала кейса, число действий текущего
процесса — из модели с явными коэффициентами. Время не моделируется вовсе: коэффициента
«секунд на действие» никто не измерял, а `docs/product_boundary.md` запрещает цифры
производительности без ссылки на замер.

Методика парного прогона — `docs/pt_techlab/baseline_methodology.md`.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from takt.application.use_cases.investigation_effort import (
    AnalystSession,
    ManualProcessModel,
    analyst_session_from_audit,
    evaluate_effort,
    reduction_percent,
)

_T0 = datetime(2026, 8, 17, 7, 0, tzinfo=UTC)


def _line(offset_min: int, text: str, actor: str = "") -> str:
    moment = _T0.replace(minute=offset_min).isoformat(timespec="seconds")
    return f"{moment} | {text}" + (f" | actor={actor}" if actor else "")


def test_only_lines_with_actor_count_as_manual_actions() -> None:
    """Автоматические записи конвейера не считаются ручными действиями."""
    session = analyst_session_from_audit(
        [
            _line(0, "case created by AssessRiskUseCase"),
            _line(1, "merged burst fingerprint ws-17|C2_SUSPECT"),
            _line(2, "finding appended", actor="analyst.01"),
            _line(5, "status -> CONFIRMED", actor="analyst.01"),
        ]
    )
    assert session.actions == 2
    assert session.seconds == pytest.approx(180.0)


def test_session_without_manual_actions_has_no_interval() -> None:
    session = analyst_session_from_audit([_line(0, "case created by AssessRiskUseCase")])
    assert session.actions == 0
    assert session.seconds is None


def test_malformed_timestamp_does_not_break_counting() -> None:
    """Запись без разбираемого времени всё равно считается действием."""
    session = analyst_session_from_audit(["не-дата | finding appended | actor=analyst.01"])
    assert session.actions == 1
    assert session.seconds is None


def test_manual_model_breakdown_is_derived_from_case_composition() -> None:
    """Модель опирается на состав кейса, а не на константу."""
    breakdown = ManualProcessModel().actions(sources=4, entities=6, events=41)
    assert breakdown == {
        "открыть консоли источников": 4,
        "поиск сущностей по системам": 24,
        "перенос идентификаторов между системами": 18,
        "фиксация событий в заметке": 41,
        "сведение итога": 1,
    }
    assert sum(breakdown.values()) == 88


def test_single_source_needs_no_identifier_transfer() -> None:
    breakdown = ManualProcessModel().actions(sources=1, entities=5, events=3)
    assert breakdown["перенос идентификаторов между системами"] == 0


def test_time_is_absent_until_observed() -> None:
    """Без наблюдённых значений время текущего процесса не появляется ниоткуда."""
    result = evaluate_effort(
        sources=4,
        entities=6,
        events=41,
        session=AnalystSession(actions=10, started_at=_T0, finished_at=_T0.replace(minute=9)),
    )
    assert result["current_seconds"] is None
    assert result["reduction_time_percent"] is None
    # Время самой сессии в ТАКТ измерено и сохраняется.
    assert result["takt_seconds"] == pytest.approx(540.0)


def test_observed_values_replace_the_model() -> None:
    """Наблюдение имеет приоритет над расчётом и помечается как замер."""
    result = evaluate_effort(
        sources=4,
        entities=6,
        events=41,
        session=AnalystSession(actions=10),
        observed={"current_actions": 52, "takt_actions": 14, "current_seconds": 2400, "takt_seconds": 900},
    )
    assert result["current_actions"] == 52
    assert result["current_actions_measured"] is True
    assert result["takt_actions"] == 14
    assert result["takt_actions_measured"] is False
    assert result["reduction_actions_percent"] == pytest.approx((52 - 14) / 52 * 100)
    assert result["reduction_time_percent"] == pytest.approx((2400 - 900) / 2400 * 100)


def test_reduction_is_undefined_without_baseline() -> None:
    assert reduction_percent(0, 0) is None
    assert reduction_percent(10, 10) == pytest.approx(0.0)
    assert reduction_percent(10, 12) == pytest.approx(-20.0)


def test_model_coefficients_are_overridable() -> None:
    """Коэффициенты модели заменяются наблюдением за процессом заказчика."""
    model = ManualProcessModel(note_event=0)
    breakdown = model.actions(sources=4, entities=6, events=41)
    assert breakdown["фиксация событий в заметке"] == 0
    assert sum(breakdown.values()) == 47
