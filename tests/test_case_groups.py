"""Группировка очереди: 284 почти одинаковых дела сводятся в строки.

Дедупликация продукта работает по `burst_fingerprint`, а в него входит корзина времени:
одинаковые срабатывания на одном активе, попавшие в разные минуты, остаются разными делами.
На демонстрационном датасете из-за этого 263 дела «низкий: ALLOWED» — ровно та усталость от
однотипных срабатываний, от которой продукт и продаётся.

Здесь закреплены три свойства группировки: она сводит однотипное, она **ничего не меняет** в
делах, и она подчиняется тем же фильтрам, что список дел.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from takt.application.use_cases.cases_query_service import CasesListQuery, CasesQueryService
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.memory import InMemoryCaseStore
from takt.interface_adapters.api.main import create_app

_T0 = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)


def _case(case_id: str, *, asset: str, operation: str, risk: str, score: float, minute: int) -> Case:
    return Case(
        case_id=case_id,
        status=CaseStatus.NEW,
        title=f"Риск: {operation}",
        risk_class=risk,
        risk_score=score,
        created_at=_T0.replace(minute=minute),
        primary_asset_id=asset,
        trigger_operation=operation,
        # Отпечаток продукта включает корзину времени — именно поэтому одинаковые
        # срабатывания в разные минуты не сводятся между собой.
        burst_fingerprint=f"{asset}|{operation}|{minute}",
        normalized_event_ids=[f"{case_id}-e1"],
    )


@pytest.fixture()
def store() -> InMemoryCaseStore:
    repo = InMemoryCaseStore()
    for index in range(5):
        repo.save(_case(f"low-{index}", asset="ws-10", operation="ALLOWED", risk="LOW", score=0.28, minute=index))
    repo.save(_case("mid-0", asset="ws-17", operation="C2_SUSPECT", risk="MEDIUM", score=0.47, minute=7))
    repo.save(_case("mid-1", asset="ws-17", operation="C2_SUSPECT", risk="MEDIUM", score=0.42, minute=8))
    repo.save(_case("other", asset="plc-02", operation="POLL", risk="LOW", score=0.30, minute=9))
    return repo


@pytest.fixture()
def service(store: InMemoryCaseStore) -> CasesQueryService:
    return CasesQueryService(store)


def test_identical_alerts_collapse_into_one_row(service: CasesQueryService) -> None:
    """Пять дел «ws-10 / ALLOWED» — одна строка очереди, а не пять."""
    result = service.group_cases(CasesListQuery())
    groups = {group.key: group for group in result.items}

    assert groups["ws-10|ALLOWED|LOW"].cases == 5
    assert groups["ws-10|ALLOWED|LOW"].events == 5
    assert result.total_groups == 3
    assert result.total_cases == 8


def test_time_bucket_is_not_part_of_the_group_key(service: CasesQueryService) -> None:
    """Иначе группировка повторила бы дедупликацию продукта и ничего не свела бы."""
    result = service.group_cases(CasesListQuery())
    keys = [group.key for group in result.items]

    assert all("|" in key for key in keys)
    for key in keys:
        assert key.count("|") == 2, key


def test_risk_class_keeps_heavier_cases_in_their_own_row(service: CasesQueryService, store: InMemoryCaseStore) -> None:
    """Слить разные классы значило бы спрятать более тяжёлое дело за более лёгким."""
    heavy = _case("heavy", asset="ws-10", operation="ALLOWED", risk="MEDIUM", score=0.55, minute=11)
    store.save(heavy)

    keys = {group.key for group in service.group_cases(CasesListQuery()).items}

    assert "ws-10|ALLOWED|LOW" in keys
    assert "ws-10|ALLOWED|MEDIUM" in keys


def test_group_points_at_the_heaviest_case_in_it(service: CasesQueryService) -> None:
    """Из строки очереди аналитик открывает представителя группы, а не случайное дело."""
    groups = {group.key: group for group in service.group_cases(CasesListQuery()).items}
    medium = groups["ws-17|C2_SUSPECT|MEDIUM"]

    assert medium.top_case_id == "mid-0"
    assert medium.max_risk_score == pytest.approx(0.47)


def test_heaviest_group_comes_first_and_order_is_repeatable(service: CasesQueryService) -> None:
    first = service.group_cases(CasesListQuery()).items
    second = service.group_cases(CasesListQuery()).items

    assert [group.key for group in first] == [group.key for group in second]
    assert first[0].key == "ws-17|C2_SUSPECT|MEDIUM"


def test_grouping_obeys_the_same_filters_as_the_list(service: CasesQueryService) -> None:
    """Отбор и группировка не должны расходиться: иначе счётчики покажут разное."""
    result = service.group_cases(CasesListQuery(risk_classes="MEDIUM"))

    assert [group.key for group in result.items] == ["ws-17|C2_SUSPECT|MEDIUM"]
    assert result.total_cases == 2


def test_grouping_changes_nothing_in_the_cases(service: CasesQueryService, store: InMemoryCaseStore) -> None:
    """Группировка — способ показа, а не сборки: слитых дел после неё быть не должно."""
    before = {case.case_id: (case.status, list(case.normalized_event_ids)) for case in store.list_all()}

    service.group_cases(CasesListQuery())

    after = {case.case_id: (case.status, list(case.normalized_event_ids)) for case in store.list_all()}
    assert after == before


def test_endpoint_reports_both_counters() -> None:
    """Аналитику нужны обе величины: сколько строк он видит и сколько дел за ними стоит."""
    with TestClient(create_app()) as client:
        client.post(
            "/assess",
            json={"observed_at": "2026-04-30T21:00:00+00:00", "operation": "POLL", "asset_id": "plc-1"},
        )
        response = client.get("/cases/groups")

    assert response.status_code == 200
    assert response.headers["X-Total-Count"] == "1"
    assert response.headers["X-Total-Cases"] == "1"
    body = response.json()
    assert body[0]["cases"] == 1
    assert body[0]["by_status"]


def test_second_cut_answers_which_rule_is_noisy(service: CasesQueryService, store: InMemoryCaseStore) -> None:
    """Разрез по активу отвечает «какой узел шумит», по операции — «какое правило шумит».

    Второй вопрос и есть тот, ради которого поток однотипных срабатываний разбирают: правило
    правят один раз, а срабатывания по нему приходят тысячами.
    """
    store.save(_case("low-other-asset", asset="ws-99", operation="ALLOWED", risk="LOW", score=0.28, minute=12))

    by_asset = {g.key: g for g in service.group_cases(CasesListQuery(), group_by="asset").items}
    by_operation = {g.key: g for g in service.group_cases(CasesListQuery(), group_by="operation").items}

    assert by_asset["ws-10|ALLOWED|LOW"].cases == 5
    assert by_asset["ws-99|ALLOWED|LOW"].cases == 1
    assert by_operation["|ALLOWED|LOW"].cases == 6
    assert by_operation["|ALLOWED|LOW"].assets == 2


def test_group_of_many_assets_does_not_claim_a_single_one(service: CasesQueryService, store: InMemoryCaseStore) -> None:
    """Показать актив представителя значило бы приписать всей группе один узел."""
    store.save(_case("low-other-asset", asset="ws-99", operation="ALLOWED", risk="LOW", score=0.28, minute=12))

    group = {g.key: g for g in service.group_cases(CasesListQuery(), group_by="operation").items}["|ALLOWED|LOW"]

    assert group.primary_asset_id == ""
    assert group.assets == 2


def test_unknown_cut_is_refused(service: CasesQueryService) -> None:
    """Молча отдать разрез по умолчанию значило бы показать не то, о чём спросили."""
    with pytest.raises(ValueError, match="group_by"):
        service.group_cases(CasesListQuery(), group_by="whatever")


def test_endpoint_refuses_an_unknown_cut() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/cases/groups?group_by=whatever").status_code == 400
