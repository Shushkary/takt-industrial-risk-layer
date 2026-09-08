"""Частота сущности и доступность её истории за пределом одного запроса.

Замечание, с которого начата работа (аудит «След смены», разрыв D06): 51 событие за 50 секунд
давало статус `typical` — «часто: 3 и более событий». Порог назван честно, но короткая вспышка
и устойчивое поведение за длительный период при таком счётчике неотличимы. Отдельно: за предел
100 событий карточка не переходила вовсе, и контрольное 101-е событие вместе со связанным с ним
делом оставалось недостижимым.

Поведенческой нормы по периоду здесь не вводится: период и достаточность истории для суждения
о типичности — предмет согласования с заказчиком. Вводится другое — **видимость границ**:
сколько событий, за какой промежуток, в скольких часовых корзинах они наблюдались, и вспышка
ли это. Одно от другого читающий должен отличать сам, а не получать вывод, которого продукт
не делал.

Навигация: история доступна страницами, связанные дела считаются по всей истории, а не по
загруженной её части.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore

START = datetime(2026, 9, 8, 9, 0, tzinfo=UTC)


def _event(event_id: str, *, seconds: int = 0, hours: int = 0, host: str = "ws-17") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=START + timedelta(hours=hours, seconds=seconds),
        source=EventSource.EDR,
        protocol="test",
        operation="OBSERVED",
        payload_size=1,
        payload={},
        entities=EventEntities(host_id=host),
        ingest_trust=1.0,
    )


# --- частота ---------------------------------------------------------------


def test_a_burst_is_not_reported_as_steady_behaviour(tmp_path) -> None:
    """То самое воспроизведение: 51 событие за 50 секунд читалось как «часто»."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index in range(51):
            store.add_recent_event(_event(f"p-{index}", seconds=index), max_events=1000)

        card = store.entity_card("host", "ws-17")

        assert card is not None
        assert card["typicality"]["status"] == "burst"
        assert card["typicality"]["active_hours"] == 1
    finally:
        store.close()


def test_events_spread_over_hours_stay_typical(tmp_path) -> None:
    """Правку нельзя свести к «всё стало вспышкой»: разнесённая активность остаётся частой."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index in range(6):
            store.add_recent_event(_event(f"p-{index}", hours=index), max_events=1000)

        card = store.entity_card("host", "ws-17")

        assert card is not None
        assert card["typicality"]["status"] == "typical"
        assert card["typicality"]["active_hours"] == 6
    finally:
        store.close()


def test_the_card_names_the_span_it_covers(tmp_path) -> None:
    """Периоды видны: без них счётчик ничего не говорит о поведении."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event("p-0"), max_events=1000)
        store.add_recent_event(_event("p-1", hours=3), max_events=1000)

        card = store.entity_card("host", "ws-17")

        assert card is not None
        assert card["typicality"]["span_seconds"] == 3 * 3600
    finally:
        store.close()


def test_a_single_event_stays_first_seen(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event("p-0"), max_events=1000)

        card = store.entity_card("host", "ws-17")

        assert card is not None and card["typicality"]["status"] == "first_seen"
    finally:
        store.close()


# --- навигация -------------------------------------------------------------


def test_history_beyond_the_request_limit_is_reachable(tmp_path) -> None:
    """Контрольное 101-е событие было недостижимо: карточка за предел не переходила."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index in range(101):
            store.add_recent_event(_event(f"p-{index}", seconds=index), max_events=1000)

        first = store.entity_card("host", "ws-17", event_limit=100)
        second = store.entity_card("host", "ws-17", event_limit=100, event_offset=100)

        assert first is not None and second is not None
        assert len(first["environment"]) == 100
        assert [item["event_id"] for item in second["environment"]] == ["p-0"]
        assert second["environment_total"] == 101
        assert second["environment_offset"] == 100
    finally:
        store.close()


def test_related_cases_are_counted_over_the_whole_history(tmp_path) -> None:
    """Связанные дела считались по загруженной части истории и тоже были неполны."""
    from fastapi.testclient import TestClient

    from takt.domain.entities.case import Case, CaseStatus
    from takt.interface_adapters.api.main import create_app

    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    try:
        for index in range(101):
            store.add_recent_event(_event(f"p-{index}", seconds=index), max_events=1000)
        # Дело собрано вокруг самого старого события — того, что не попадало на первую страницу.
        app.state.repo.save(Case(
            case_id="c-old", status=CaseStatus.NEW, title="старое", risk_class="LOW",
            risk_score=0.2, created_at=START, normalized_event_ids=["p-0"],
        ))

        with TestClient(app) as client:
            card = client.get("/entities/host/ws-17/card", params={"event_limit": 100}).json()

        assert "c-old" in card["related_cases"]
    finally:
        app.state.recent_event_store = original
        store.close()
