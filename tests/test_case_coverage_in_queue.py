"""Покрытие исходного дела собранным инцидентом — признак очереди.

Замечание, с которого начата работа (аудит «След смены», находка 02): по активу
`audit-ws-249` в очереди стояли два дела — исходное `43476419` со статусом «новое» и
собранный `AUTO-01bb08f6c9c2`, подтверждённый аналитиком. Событие в них было одно и то же:
собранный ссылается на исходное через `related_cases`, но обратной ссылки у исходного нет, и в
очереди оно выглядело нетронутым. Аналитик открывал и разбирал одно событие второй раз.

Считает покрытие продукт, а не браузер: по загруженной сотне строк очереди оно вышло бы
неполным. Исходное дело при этом не закрывается и статуса не меняет — решение остаётся за
аналитиком, признак только называет, где события уже разобраны.
"""

from __future__ import annotations

from datetime import UTC, datetime

from takt.application.use_cases.cases_query_service import CasesListQuery, CasesQueryService
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.vocabulary import vocabulary
from takt.infrastructure.stores.memory import InMemoryCaseStore

NOW = datetime(2026, 9, 7, 10, 0, tzinfo=UTC)


def _case(
    case_id: str,
    *events: str,
    status: CaseStatus = CaseStatus.NEW,
    related: tuple[str, ...] = (),
) -> Case:
    return Case(
        case_id=case_id,
        status=status,
        title=case_id,
        risk_class="HIGH",
        risk_score=0.7,
        created_at=NOW,
        normalized_event_ids=list(events),
        related_cases=list(related),
    )


def _service(*cases: Case) -> CasesQueryService:
    repo = InMemoryCaseStore()
    for case in cases:
        repo.save(case)
    return CasesQueryService(repo)


def _coverage(service: CasesQueryService, case_id: str):
    return service.list_cases(CasesListQuery()).coverage.get(case_id)


def test_source_case_is_marked_as_covered_by_the_assembled_incident() -> None:
    """То самое наблюдение: одно событие, две записи очереди, признака покрытия не было."""
    service = _service(
        _case("43476419", "e1"),
        _case("AUTO-01bb08", "e1", "e2", status=CaseStatus.CONFIRMED, related=("43476419",)),
    )

    covered = _coverage(service, "43476419")

    assert covered is not None, "исходное дело осталось без признака покрытия"
    assert covered.case_id == "AUTO-01bb08"
    # Статус собранного важен читающему: разобран он или ещё ждёт очереди.
    assert covered.status == CaseStatus.CONFIRMED.value
    assert covered.full is True
    assert (covered.covered_events, covered.total_events) == (1, 1)


def test_partial_coverage_is_not_reported_as_full() -> None:
    """Пересборка меняет состав в обе стороны: часть событий в новый инцидент не входит.

    Объявить такое дело разобранным целиком значило бы спрятать неразобранный остаток.
    """
    service = _service(
        _case("src", "e1", "e2", "e3"),
        _case("AUTO-1", "e1", "e2", "e9", status=CaseStatus.TRIAGE, related=("src",)),
    )

    covered = _coverage(service, "src")

    assert covered is not None
    assert covered.full is False
    assert (covered.covered_events, covered.total_events) == (2, 3)


def test_case_without_a_shared_event_is_not_marked() -> None:
    """Ссылка без общего события покрытием не является: состав считается, а не декларируется."""
    service = _service(
        _case("src", "e1"),
        _case("AUTO-1", "e7", status=CaseStatus.TRIAGE, related=("src",)),
    )

    assert _coverage(service, "src") is None


def test_a_merged_case_does_not_cover_anything() -> None:
    """Объединённое дело само поглощено другим и работой аналитика не является.

    Ручное объединение проставляет ссылку в обе стороны, и без этой проверки поглощённое дело
    объявляло бы покрытым то, во что его влили.
    """
    service = _service(
        _case("target", "e1", "e2"),
        _case("source", "e1", status=CaseStatus.MERGED, related=("target",)),
    )

    assert _coverage(service, "target") is None


def test_a_split_off_case_does_not_cover_its_source() -> None:
    """После ручного разделения половина ссылается на источник, но разобран не он.

    Состав отделённой части целиком лежит внутри исходного дела — покрытием это не считается.
    """
    service = _service(
        _case("src", "e1", "e2", "e3"),
        _case("part", "e1", status=CaseStatus.NEW, related=("src",)),
    )

    assert _coverage(service, "src") is None


def test_the_largest_coverage_wins_and_ties_are_deterministic() -> None:
    """Повторный прогон на тех же данных обязан дать тот же ответ."""
    service = _service(
        _case("src", "e1", "e2"),
        _case("AUTO-b", "e1", "e2", "e3", status=CaseStatus.TRIAGE, related=("src",)),
        _case("AUTO-a", "e1", "e2", "e4", status=CaseStatus.TRIAGE, related=("src",)),
    )

    first = _coverage(service, "src")
    second = _coverage(service, "src")

    assert first is not None and first.case_id == "AUTO-a"
    assert second == first


def test_coverage_is_counted_over_the_whole_store_not_the_filtered_page() -> None:
    """Собранный инцидент мог не пройти отбор очереди — разобранным исходное дело не перестало."""
    service = _service(
        _case("src", "e1"),
        _case("AUTO-1", "e1", "e2", status=CaseStatus.CONFIRMED, related=("src",)),
    )

    result = service.list_cases(CasesListQuery(status="NEW"))

    assert [case.case_id for case in result.items] == ["src"]
    assert result.coverage["src"].case_id == "AUTO-1"


def test_the_source_case_keeps_its_status() -> None:
    """Признак — это показ, а не решение: исходное дело не закрывается автоматически."""
    service = _service(
        _case("src", "e1"),
        _case("AUTO-1", "e1", "e2", status=CaseStatus.CONFIRMED, related=("src",)),
    )

    result = service.list_cases(CasesListQuery())
    source = next(case for case in result.items if case.case_id == "src")

    assert source.status is CaseStatus.NEW


def test_group_row_names_how_many_of_its_cases_are_already_covered() -> None:
    """Сведённая строка складывала дело конвейера и собранный инцидент: два вместо одного."""
    service = _service(
        _case("src", "e1"),
        _case("AUTO-1", "e1", "e2", status=CaseStatus.CONFIRMED, related=("src",)),
    )

    groups = service.group_cases(CasesListQuery(), group_by="asset").items

    assert len(groups) == 1, "дела разошлись по группам, проверка не о том"
    assert groups[0].cases == 2
    assert groups[0].covered_cases == 1


def test_the_api_publishes_the_coverage_of_a_queue_row() -> None:
    """Признак нужен в сводке очереди: считать покрытие в браузере запрещено."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    app = create_app()
    repo = app.state.repo
    repo.save(_case("src-api", "ev-1"))
    repo.save(_case("AUTO-api", "ev-1", "ev-2", status=CaseStatus.CONFIRMED, related=("src-api",)))

    with TestClient(app) as client:
        rows = client.get("/cases", params={"case_id_prefix": "src-api"}).json()

    assert len(rows) == 1
    row = rows[0]
    assert row["covered_by_case_id"] == "AUTO-api"
    assert row["covered_by_status"] == CaseStatus.CONFIRMED.value
    assert row["coverage"] == "full"
    assert row["covered_events"] == 1


def test_coverage_names_are_published_to_the_interface() -> None:
    """Обозначение без русского названия вынудит АРМ завести свой словарь."""
    table = vocabulary()["case_coverage"]

    assert set(table) == {"full", "partial"}
    assert all(name and name != code for code, name in table.items())
