"""Петля обучения по вердикту: накопление разметки без вмешательства в контур вердикта.

Разрыв G-2 из [`docs/customer_value_map.md`](../docs/customer_value_map.md), **безрисковый
вариант**. Клиент размечает дела статусами (`CONFIRMED` / `FALSE_POSITIVE` /
`EXPECTED_BEHAVIOR`), продукт сводит разметку по инвариантам и **предлагает** изменение. Ничего
не применяется автоматически.

Почему именно так. Автоматический пересчёт весов сделал бы вердикт зависящим от накопленной
истории: повторный прогон того же дела на той же версии кода дал бы другой результат, и
доказательный пакет перестал бы быть воспроизводимым (`docs/product_boundary.md`, «Детерминизм
вердикта»). Ценность разметки при этом не теряется — теряется только автоматизм, которого
заказчик и не просил: он просил, чтобы система переставала повторять ложные срабатывания, а
решение об изменении правила остаётся за человеком.

Ниже закреплены четыре свойства, на которых держится безрисковость:

1. Отчёт **не меняет** ни одного дела.
2. Предложение всегда помечено как неприменённое, и применить его из продукта нельзя.
3. При малой выборке предложения нет — иначе шум выдавался бы за знание.
4. Расчёт детерминирован и не зависит от порядка дел.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.services.invariant_feedback import (
    MIN_SAMPLE_FOR_PROPOSAL,
    PROPOSAL_KEEP,
    PROPOSAL_INSUFFICIENT_DATA,
    PROPOSAL_REVIEW_RULE,
    invariant_feedback,
)

_TS = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


def _case(case_id: str, status: CaseStatus, hits: list[str]) -> Case:
    return Case(
        case_id=case_id,
        status=status,
        title="дело",
        risk_class="HIGH",
        risk_score=0.7,
        created_at=_TS,
        invariant_hits=hits,
    )


def _marked(invariant: str, *, confirmed: int, false_positive: int, expected: int = 0) -> list[Case]:
    cases: list[Case] = []
    index = 0
    for status, count in (
        (CaseStatus.CONFIRMED, confirmed),
        (CaseStatus.FALSE_POSITIVE, false_positive),
        (CaseStatus.EXPECTED_BEHAVIOR, expected),
    ):
        for _ in range(count):
            index += 1
            cases.append(_case(f"c-{index}", status, [invariant]))
    return cases


def test_report_counts_the_markup_by_invariant() -> None:
    report = invariant_feedback(_marked("brute_force", confirmed=7, false_positive=2, expected=1))

    row = report.rows[0]
    assert row.invariant_id == "brute_force"
    assert (row.confirmed, row.false_positive, row.expected_behavior) == (7, 2, 1)
    assert row.marked_cases == 10
    assert round(row.precision, 4) == 0.7


def test_open_cases_are_not_markup() -> None:
    """Неразобранное дело — не разметка: аналитик ещё не сказал, атака это или нет."""
    cases = _marked("brute_force", confirmed=3, false_positive=1)
    cases += [_case("open-1", CaseStatus.NEW, ["brute_force"]), _case("open-2", CaseStatus.TRIAGE, ["brute_force"])]

    report = invariant_feedback(cases)

    assert report.rows[0].marked_cases == 4
    assert report.reviewed_cases == 4


def test_expected_behavior_is_counted_apart_from_false_positive() -> None:
    """«Штатное действие» и «ложное срабатывание» — разные причины, и правятся по-разному.

    Ложное срабатывание — дефект правила. Штатное действие означает, что правило сработало
    верно, а не хватило организационного контекста: это повод добирать контекст, а не менять
    предикат. Слив их в одну кучу привёл бы к ослаблению работающего правила.
    """
    report = invariant_feedback(_marked("out_of_shift_access", confirmed=2, false_positive=1, expected=5))

    row = report.rows[0]
    assert row.false_positive == 1
    assert row.expected_behavior == 5
    assert "контекст" in row.comment.lower()


def test_low_precision_proposes_a_rule_review() -> None:
    report = invariant_feedback(_marked("reconnaissance", confirmed=1, false_positive=9))

    row = report.rows[0]
    assert row.proposal == PROPOSAL_REVIEW_RULE
    assert row.applied is False


def test_high_precision_proposes_no_change() -> None:
    report = invariant_feedback(_marked("log_wiping", confirmed=9, false_positive=1))

    assert report.rows[0].proposal == PROPOSAL_KEEP


def test_small_sample_yields_no_proposal() -> None:
    """Шум не выдаётся за знание: два дела не основание менять правило."""
    report = invariant_feedback(_marked("c2_external_dns", confirmed=0, false_positive=2))

    row = report.rows[0]
    assert row.marked_cases < MIN_SAMPLE_FOR_PROPOSAL
    assert row.proposal == PROPOSAL_INSUFFICIENT_DATA


def test_nothing_is_ever_applied_automatically() -> None:
    """Ключевое свойство безрискового варианта: предложение остаётся предложением."""
    report = invariant_feedback(_marked("brute_force", confirmed=1, false_positive=9))

    assert all(row.applied is False for row in report.rows)
    assert report.applied_changes == 0


def test_report_does_not_mutate_the_cases() -> None:
    """Отчёт — чтение. Изменив дело, он изменил бы доказательный материал."""
    cases = _marked("brute_force", confirmed=3, false_positive=2)
    before = [(case.status, list(case.invariant_hits), list(case.audit_log)) for case in cases]

    invariant_feedback(cases)

    after = [(case.status, list(case.invariant_hits), list(case.audit_log)) for case in cases]
    assert before == after


def test_report_is_deterministic_and_order_independent() -> None:
    cases = _marked("brute_force", confirmed=4, false_positive=3) + _marked(
        "log_wiping", confirmed=6, false_positive=1
    )

    first = invariant_feedback(cases)
    second = invariant_feedback(list(reversed(cases)))

    assert first == second
    assert [row.invariant_id for row in first.rows] == ["brute_force", "log_wiping"]


def test_rows_are_sorted_by_invariant_id() -> None:
    """Отчёт читают глазами и кладут в git — порядок обязан быть каноническим."""
    cases = _marked("zzz_rule", confirmed=5, false_positive=1) + _marked("aaa_rule", confirmed=5, false_positive=1)

    report = invariant_feedback(cases)

    assert [row.invariant_id for row in report.rows] == ["aaa_rule", "zzz_rule"]


def test_weights_version_is_carried_into_the_report() -> None:
    """Предложение осмысленно только вместе с версией конфигурации, против которой считалось."""
    report = invariant_feedback(_marked("brute_force", confirmed=5, false_positive=5), weights_version="2026.08.1")

    assert report.weights_version == "2026.08.1"


def test_empty_markup_gives_an_empty_report_not_a_guess() -> None:
    report = invariant_feedback([])

    assert report.rows == ()
    assert report.reviewed_cases == 0


def test_report_dict_is_json_ready() -> None:
    report = invariant_feedback(_marked("brute_force", confirmed=5, false_positive=5))

    payload = report.to_dict()

    assert payload["applied_changes"] == 0
    assert payload["rows"][0]["invariant_id"] == "brute_force"
    assert replace(report, weights_version="x").to_dict()["weights_version"] == "x"


def test_api_serves_the_feedback_report() -> None:
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-feedback",
            },
        ).json()["case_id"]
        client.post(f"/cases/{case_id}/decision", json={"status": "FALSE_POSITIVE", "reason": "ложное"})

        report = client.get("/analytics/invariant-feedback")
        assert report.status_code == 200
        payload = report.json()
        assert payload["applied_changes"] == 0
        assert payload["reviewed_cases"] >= 1


def test_api_has_no_endpoint_that_applies_a_proposal() -> None:
    """Безрисковость проверяется контрактом, а не обещанием в документации."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        paths = client.get("/openapi.json").json()["paths"]

    suspicious = [path for path in paths if "invariant-feedback" in path and path.rstrip("/").endswith("apply")]
    assert not suspicious, suspicious
    for path, operations in paths.items():
        if "invariant-feedback" in path:
            assert set(operations) == {"get"}, (path, sorted(operations))
