"""Русский словарь обозначений: полнота и граница перевода.

Аналитик и руководитель читают слова, а не коды. Словарь один
([`vocabulary.py`](../src/takt/domain/vocabulary.py)) и отдаётся интерфейсу через
`GET /catalog/vocabulary`: параллельный словарь в АРМ разошёлся бы с продуктом при первом же
добавлении статуса или источника, и разошёлся бы молча.

Главное, что здесь закреплено, — **граница перевода**. Переводятся обозначения, которые придумал
продукт. Значения из данных источника (операция, протокол, идентификаторы) остаются как есть:
это материал доказательства, и перевод исказил бы то, что зафиксировано в журнале.
"""

from __future__ import annotations

import pytest

from takt.domain.entities.case import CaseStatus
from takt.domain.entities.event import ArtifactType, EventSource
from takt.domain.services.verdict_confidence import GRADE_HIGH, GRADE_LOW, GRADE_MEDIUM
from takt.domain.vocabulary import (
    ARTIFACT_TYPE_RU,
    CASE_STATUS_RU,
    CHAIN_STEP_KIND_RU,
    CONFIDENCE_GRADE_RU,
    CORRELATION_RULE_RU,
    DQ_REASON_RU,
    EVENT_SOURCE_RU,
    GRAPH_EDGE_KIND_RU,
    LEDGER_ISSUE_RU,
    RISK_CLASS_RU,
    TYPICALITY_RU,
    VERDICT_RU,
    events_ru,
    risk_class_ru,
    vocabulary,
)

_LATIN = set("abcdefghijklmnopqrstuvwxyz")


@pytest.mark.parametrize("status", list(CaseStatus))
def test_every_case_status_has_a_russian_name(status: CaseStatus) -> None:
    """Новый статус без названия показался бы пользователю кодом."""
    assert CASE_STATUS_RU.get(status.value), status.value


@pytest.mark.parametrize("source", list(EventSource))
def test_every_event_source_has_a_russian_name(source: EventSource) -> None:
    assert EVENT_SOURCE_RU.get(source.value), source.value


@pytest.mark.parametrize("artifact", list(ArtifactType))
def test_every_artifact_type_has_a_russian_name(artifact: ArtifactType) -> None:
    assert ARTIFACT_TYPE_RU.get(artifact.value), artifact.value


def test_risk_classes_cover_the_engine_scale() -> None:
    from takt.domain.engines.risk_engine import _RISK_CLASS_RANK

    assert set(RISK_CLASS_RU) == set(_RISK_CLASS_RANK)


def test_verdict_triad_is_complete() -> None:
    assert set(VERDICT_RU) == {"LEG", "ILLEG", "UNDET"}


def test_every_work_phase_has_a_russian_name() -> None:
    """Фаза попадает в текст объяснения, который читает аналитик."""
    from takt.domain.engines.phase_time_tagger import WorkPhase

    from takt.domain.vocabulary import WORK_PHASE_RU

    assert set(WORK_PHASE_RU) == {phase.value for phase in WorkPhase}


def test_explanation_text_has_no_machine_designations() -> None:
    """Объяснение читает человек: ни кода фазы, ни питоновского True/False в нём быть не должно."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-xai",
            },
        ).json()["case_id"]
        summary = client.get(f"/cases/{case_id}").json()["xai_summary"]

    assert "NIGHT" not in summary and "WORK_SHIFT" not in summary and "WEEKEND" not in summary
    assert "True" not in summary and "False" not in summary
    assert "окно ТО: " in summary
    # Класс риска в объяснении — словом, а не кодом.
    assert "класс LOW" not in summary and "класс HIGH" not in summary
    assert "класс " in summary


def test_explanation_names_invariants_not_identifiers() -> None:
    """Сработавшие правила в объяснении называются, а не перечисляются кодами."""
    from takt.domain.engines.risk_engine import RiskAssessment, RiskBreakdown
    from takt.domain.engines.xai import build_xai

    assessment = RiskAssessment(
        score=0.8,
        risk_class="HIGH",
        breakdown=RiskBreakdown(rhythm=0.5, graph=0.5, context=0.5, user=0.5, data_quality=0.5),
    )
    report = build_xai(assessment, invariant_hits=["brute_force"], context_note="Фаза: ночь")

    assert "класс высокий" in report.what
    assert "brute_force" not in report.why_unusual
    assert "Серия неуспешных аутентификаций" in report.why_unusual


def test_unknown_invariant_id_stays_visible_in_the_explanation() -> None:
    """Устаревшее название хуже идентификатора: по коду правило хотя бы найдётся."""
    from takt.domain.engines.xai import _invariant_title

    assert _invariant_title("no_such_rule") == "no_such_rule"


def test_confidence_grades_match_the_service() -> None:
    """Оценки обоснованности объявлены в одном месте с расчётом."""
    assert set(CONFIDENCE_GRADE_RU) == {GRADE_HIGH, GRADE_MEDIUM, GRADE_LOW}


@pytest.mark.parametrize(
    "table",
    [
        CASE_STATUS_RU,
        EVENT_SOURCE_RU,
        VERDICT_RU,
        RISK_CLASS_RU,
        CORRELATION_RULE_RU,
        CHAIN_STEP_KIND_RU,
        GRAPH_EDGE_KIND_RU,
        TYPICALITY_RU,
        DQ_REASON_RU,
        LEDGER_ISSUE_RU,
    ],
    ids=[
        "status",
        "source",
        "verdict",
        "risk_class",
        "correlation_rule",
        "chain_step_kind",
        "graph_edge_kind",
        "typicality",
        "dq_reason",
        "ledger_issue",
    ],
)
def test_names_are_actually_russian(table: dict[str, str]) -> None:
    """Латиница в названии означает недопереведённое обозначение."""
    for code, name in table.items():
        letters = set(name.lower()) & _LATIN
        assert not letters, f"{code}: {name} содержит латиницу {sorted(letters)}"


def test_artifact_names_may_keep_proper_nouns() -> None:
    """Исключение: имя собственное протокола не переводится — «служба Kerberos» остаётся."""
    assert ARTIFACT_TYPE_RU["spn"] == "служба Kerberos"


def test_unknown_code_is_returned_as_is() -> None:
    """Догадка вместо перевода хуже кода: пользователь увидел бы выдуманное слово."""
    assert risk_class_ru("WHATEVER") == "WHATEVER"
    assert risk_class_ru("") == ""


def test_risk_class_lookup_is_case_insensitive() -> None:
    assert risk_class_ru("high") == "высокий"


def test_vocabulary_bundles_every_table() -> None:
    payload = vocabulary()

    assert set(payload) == {
        "risk_class",
        "case_status",
        "verdict",
        "event_source",
        "entity_type",
        "artifact_type",
        "correlation_rule",
        "chain_step_kind",
        "graph_edge_kind",
        "typicality",
        "dq_reason",
        "ledger_issue",
    }
    assert payload["case_status"][CaseStatus.CONFIRMED.value] == "подтверждено"


def test_vocabulary_is_a_copy_not_the_live_table() -> None:
    """Словарь уходит наружу: правка ответа не должна менять продукт."""
    payload = vocabulary()
    payload["risk_class"]["LOW"] = "испорчено"

    assert RISK_CLASS_RU["LOW"] == "низкий"


def test_api_serves_the_vocabulary() -> None:
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        payload = client.get("/catalog/vocabulary").json()

    assert payload["risk_class"]["HIGH"] == "высокий"
    assert payload["event_source"]["auth_logs"] == "журналы аутентификации"


def test_generated_case_title_is_russian() -> None:
    """Заголовок дела — наш текст, и он попадает в сводку руководителю и в выгрузки."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-title",
            },
        ).json()["case_id"]
        title = client.get(f"/cases/{case_id}").json()["title"]

    assert title.startswith("Риск ")
    assert "Risk" not in title
    # Операция — значение из данных источника: она остаётся как есть, иначе доказательство
    # разойдётся с журналом.
    assert "WRITE_REGISTER" in title


@pytest.mark.parametrize(
    "table",
    [
        "correlation_rule",
        "chain_step_kind",
        "graph_edge_kind",
        "typicality",
        "dq_reason",
        "ledger_issue",
    ],
)
def test_new_tables_are_published_to_the_interface(table: str) -> None:
    """Таблица, которой нет в ответе `/catalog/vocabulary`, вынудит АРМ завести свою."""
    assert table in vocabulary(), table


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 событий"),
        (1, "1 событие"),
        (2, "2 события"),
        (4, "4 события"),
        (5, "5 событий"),
        (11, "11 событий"),
        (14, "14 событий"),
        (21, "21 событие"),
        (25, "25 событий"),
        (41, "41 событие"),
        (102, "102 события"),
        (111, "111 событий"),
    ],
)
def test_events_ru_agrees_with_the_numeral(count: int, expected: str) -> None:
    """«Собрано 41 событий» в сводке кейса — небрежность там, где продукт объясняет вывод."""
    assert events_ru(count) == expected
