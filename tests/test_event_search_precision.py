"""Точность единого поиска событий: полнота кандидатов и пара тип/значение артефакта.

Замечание, с которого начата работа (аудит «След смены», разрыв D02): при 51 подходящем
событии, первые 50 из которых уже в деле, окно возвращало 0 кандидатов и теряло `p-0` —
страница читалась до исключения событий дела. В отдельной пробе поиск `domain=target-hash`
вернул 51 событие, хотя `target-hash` имеет тип `hash`: тип и значение проверялись двумя
независимыми LIKE по одному JSON и могли относиться к разным артефактам одного события.

Обе ошибки молчаливые и разнонаправленные: аналитик либо завершает поиск с ложным выводом об
отсутствии события, либо принимает неподходящее совпадение за индикатор. Поэтому проверяется
не «поиск что-то вернул», а полнота выдачи и связанность пары внутри одного артефакта.

Контракт:

- события дела исключаются на сервере **до** среза страницы, и `total` считает кандидатов, а
  не всё совпавшее;
- `artifact_type` и `artifact_value` относятся к одному артефакту; несвязанная пара даёт 0;
- значение артефакта — точное совпадение (это индикатор), подстрочный поиск остаётся у
  параметра `text` (это содержимое события).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.interface_adapters.api.main import create_app

START = datetime(2026, 9, 8, 9, 0, tzinfo=UTC)


def _event(event_id: str, *, minute: int = 0, host: str = "ws-17", artifacts: tuple[EventArtifact, ...] = ()) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=START + timedelta(minutes=minute),
        source=EventSource.EDR,
        protocol="test",
        operation="OBSERVED",
        payload_size=10,
        payload={"message": f"событие {event_id}"},
        entities=EventEntities(host_id=host),
        artifacts=artifacts,
        ingest_trust=1.0,
    )


def _case(case_id: str, event_ids: list[str]) -> Case:
    return Case(
        case_id=case_id,
        status=CaseStatus.TRIAGE,
        title=case_id,
        risk_class="MEDIUM",
        risk_score=0.5,
        created_at=START,
        normalized_event_ids=event_ids,
    )


# --- полнота кандидатов ----------------------------------------------------


def test_events_of_the_case_are_excluded_before_the_page_is_cut(tmp_path) -> None:
    """То самое воспроизведение: 51 подходящее, первые 50 в деле, кандидат один.

    Свежайшие события идут первыми, поэтому единственный кандидат `p-0` — самый старый — на
    первую страницу не попадал вовсе, и окно отвечало «событий вне этого инцидента не нашлось».
    """
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index in range(51):
            store.add_recent_event(_event(f"p-{index}", minute=index), max_events=1000)
        in_case = [f"p-{index}" for index in range(1, 51)]

        events, total = store.search_events(host_id="ws-17", limit=50, exclude_event_ids=in_case)

        assert total == 1, "total обязан считать кандидатов, а не всё совпавшее"
        assert [event.event_id for event in events] == ["p-0"]
    finally:
        store.close()


def test_search_api_excludes_the_case_by_id(tmp_path) -> None:
    """Исключение считает продукт: перечислять полсотни идентификаторов в запросе окну нечем."""
    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    try:
        for index in range(51):
            store.add_recent_event(_event(f"p-{index}", minute=index), max_events=1000)
        app.state.repo.save(_case("c-1", [f"p-{index}" for index in range(1, 51)]))

        with TestClient(app) as client:
            response = client.get(
                "/events/search", params={"host_id": "ws-17", "limit": 50, "exclude_case_id": "c-1"}
            )

        assert response.headers["X-Total-Count"] == "1"
        assert [item["event_id"] for item in response.json()] == ["p-0"]
    finally:
        app.state.recent_event_store = original
        store.close()


def test_unknown_case_in_the_exclusion_does_not_silently_widen_the_answer(tmp_path) -> None:
    """Опечатка в идентификаторе дела не должна возвращать события этого дела как кандидатов."""
    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    try:
        store.add_recent_event(_event("p-0"), max_events=1000)

        with TestClient(app) as client:
            response = client.get(
                "/events/search", params={"host_id": "ws-17", "exclude_case_id": "нет-такого"}
            )

        assert response.status_code == 404
    finally:
        app.state.recent_event_store = original
        store.close()


# --- пара тип/значение артефакта -------------------------------------------


def test_type_and_value_must_belong_to_one_artifact(tmp_path) -> None:
    """То самое воспроизведение: domain=target-hash находило событие с hash target-hash."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(
            _event(
                "mixed",
                artifacts=(
                    EventArtifact(ArtifactType.HASH, "target-hash"),
                    EventArtifact(ArtifactType.DOMAIN, "evil.example"),
                ),
            ),
            max_events=1000,
        )

        wrong, wrong_total = store.search_events(artifact_type="domain", artifact_value="target-hash", limit=100)
        right, right_total = store.search_events(artifact_type="hash", artifact_value="target-hash", limit=100)

        assert (wrong, wrong_total) == ([], 0), "несвязанная пара тип/значение обязана давать 0"
        assert ([event.event_id for event in right], right_total) == (["mixed"], 1)
    finally:
        store.close()


def test_artifact_value_is_an_exact_match_not_a_substring(tmp_path) -> None:
    """Индикатор — точное значение; подстрока принадлежит текстовому поиску по содержимому."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(
            _event("full", artifacts=(EventArtifact(ArtifactType.DOMAIN, "evil.example"),)), max_events=1000
        )

        partial, partial_total = store.search_events(artifact_value="evil", limit=100)
        exact, exact_total = store.search_events(artifact_value="evil.example", limit=100)

        assert (partial, partial_total) == ([], 0)
        assert ([event.event_id for event in exact], exact_total) == (["full"], 1)
    finally:
        store.close()


def test_text_search_still_matches_a_substring_of_the_payload(tmp_path) -> None:
    """Разделение точного и текстового поиска не должно отнимать текстовый."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event("p-0"), max_events=1000)

        events, total = store.search_events(text="событие p-0", limit=100)

        assert ([event.event_id for event in events], total) == (["p-0"], 1)
    finally:
        store.close()


def test_artifact_type_alone_does_not_match_a_neighbouring_type(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(
            _event("only-hash", artifacts=(EventArtifact(ArtifactType.HASH, "abc"),)), max_events=1000
        )

        events, total = store.search_events(artifact_type="domain", limit=100)

        assert (events, total) == ([], 0)
    finally:
        store.close()
