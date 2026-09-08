"""Идентичность процесса: что считается одним процессом, а что — разными.

Замечание, с которого начата работа (аудит «След смены», разрыв D04): два узла с одинаковым
`process_id` попали в одну карточку процесса — 52 события на `host-a` и `host-b` в одной
истории. Условие не выдуманное: SIEM-адаптер берёт `subject.process.guid`, а при его
отсутствии откатывается на `subject.process.id`, то есть на PID. PID уникален в пределах узла
и переиспользуется после завершения процесса; общий на два узла он не значит ничего.

Контракт идентичности:

- **GUID** уникален глобально: он и есть ключ, и один процесс из разных источников сходится
  в одну карточку;
- **PID** сам по себе ключом не является: ключ составной — узел и PID. Совпадение PID на
  разных узлах разводит истории;
- **узел неизвестен** — идентичность неопределена: такой процесс не сливается ни с одним
  другим, и карточка обязана это назвать, а не выдавать неопределённость за факт.

Чего этот контракт не умеет и не должен изображать: различить повторные запуски с одним PID
на одном узле. Для этого нужен идентификатор или время запуска процесса в схеме источника —
поле согласуется с заказчиком, и до согласования карточка честно помечает такую идентичность
как «в пределах узла».
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.domain.services.process_identity import process_entity_key, process_identity_kind
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore

START = datetime(2026, 9, 8, 9, 0, tzinfo=UTC)
GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"


def _event(event_id: str, *, host: str | None, pid: str, minute: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=START + timedelta(minutes=minute),
        source=EventSource.EDR,
        protocol="test",
        operation="OBSERVED",
        payload_size=10,
        payload={},
        entities=EventEntities(host_id=host, process_id=pid),
        ingest_trust=1.0,
    )


# --- ключ ------------------------------------------------------------------


def test_guid_is_the_key_itself() -> None:
    """Один GUID из разных источников — один процесс: он глобально уникален."""
    assert process_entity_key(GUID, "host-a") == process_entity_key(GUID, "host-b") == GUID
    assert process_identity_kind(GUID, "host-a") == "guid"


def test_pid_is_scoped_to_its_host() -> None:
    """То самое воспроизведение: один PID на двух узлах — два разных процесса."""
    assert process_entity_key("4242", "host-a") != process_entity_key("4242", "host-b")
    assert process_identity_kind("4242", "host-a") == "host_pid"


def test_pid_without_a_host_is_undetermined_and_joins_nothing() -> None:
    """Неизвестный узел — неопределённая идентичность, а не молчаливое слияние."""
    key = process_entity_key("4242", None)

    assert key != process_entity_key("4242", "host-a")
    assert key != process_entity_key("4243", None)
    assert process_identity_kind("4242", None) == "undetermined"


def test_an_empty_process_gives_no_key() -> None:
    assert process_entity_key("", "host-a") == ""
    assert process_entity_key(None, "host-a") == ""


def test_the_key_is_stable_across_calls() -> None:
    """Ключ входит в ссылки карточек: он обязан быть воспроизводимым."""
    assert process_entity_key("4242", "host-a") == process_entity_key("4242", "host-a")


# --- хранилище -------------------------------------------------------------


def test_same_pid_on_two_hosts_gives_two_cards(tmp_path) -> None:
    """52 события на двух узлах сходились в одну историю процесса."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index in range(26):
            store.add_recent_event(_event(f"a-{index}", host="host-a", pid="4242", minute=index), max_events=1000)
            store.add_recent_event(_event(f"b-{index}", host="host-b", pid="4242", minute=index), max_events=1000)

        card_a = store.entity_card("process", process_entity_key("4242", "host-a"))
        card_b = store.entity_card("process", process_entity_key("4242", "host-b"))

        assert card_a is not None and card_b is not None
        assert (card_a["event_count"], card_b["event_count"]) == (26, 26)
        assert all(event.entities.host_id == "host-a" for event in _environment(store, card_a))
        assert all(event.entities.host_id == "host-b" for event in _environment(store, card_b))
    finally:
        store.close()


def _environment(store: SqliteRecentEventStore, card: dict):
    return store.events_by_ids([item["event_id"] for item in card["environment"]])


def test_card_names_how_the_identity_was_derived(tmp_path) -> None:
    """Читающий должен видеть, чем процесс опознан: иначе «в пределах узла» выдаётся за факт."""
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event("a-1", host="host-a", pid="4242"), max_events=1000)
        store.add_recent_event(_event("g-1", host="host-a", pid=GUID), max_events=1000)

        by_pid = store.entity_card("process", process_entity_key("4242", "host-a"))
        by_guid = store.entity_card("process", GUID)

        assert by_pid is not None and by_guid is not None
        assert by_pid["identity"] == "host_pid"
        assert by_pid["display_id"] == "4242", "показывать аналитику надо PID, а не внутренний ключ"
        assert by_guid["identity"] == "guid"
        assert by_guid["display_id"] == GUID
    finally:
        store.close()


def test_a_guid_seen_from_two_sources_stays_one_process(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        first = _event("edr-1", host="host-a", pid=GUID)
        second = NormalizedEvent(
            event_id="siem-1",
            observed_at=START + timedelta(minutes=1),
            source=EventSource.SIEM,
            protocol="test",
            operation="OBSERVED",
            payload_size=10,
            payload={},
            entities=EventEntities(host_id="host-b", process_id=GUID),
            ingest_trust=1.0,
        )
        store.add_recent_event(first, max_events=1000)
        store.add_recent_event(second, max_events=1000)

        card = store.entity_card("process", GUID)

        assert card is not None
        assert card["event_count"] == 2
        assert set(card["sources"]) == {"edr", "siem"}
    finally:
        store.close()


def test_existing_events_are_migrated_to_process_keys(tmp_path) -> None:
    """Старые записи заведены по одному PID: ссылки обязаны пережить смену ключа.

    База пишется прежним способом — без ключа процесса, — после чего открывается заново.
    """
    path = tmp_path / "events.sqlite3"
    store = SqliteRecentEventStore(path)
    try:
        store.add_recent_event(_event("a-1", host="host-a", pid="4242"), max_events=1000)
        store.add_recent_event(_event("b-1", host="host-b", pid="4242"), max_events=1000)
    finally:
        store.close()

    # Состояние до миграции: один ключ на два узла и колонка ключа не заполнена.
    import sqlite3

    raw = sqlite3.connect(path)
    raw.execute("UPDATE events SET process_key = NULL")
    raw.execute("DELETE FROM entity_registry WHERE entity_type = 'process'")
    raw.execute("DELETE FROM entity_activity WHERE entity_type = 'process'")
    raw.execute(
        "INSERT INTO entity_registry (entity_type, entity_id, first_seen, last_seen, sources_json, event_count)"
        " VALUES ('process', '4242', '2026-09-08 09:00:00', '2026-09-08 09:00:00', '[\"edr\"]', 2)"
    )
    raw.execute("PRAGMA user_version = 0")
    raw.commit()
    raw.close()

    migrated = SqliteRecentEventStore(path)
    try:
        card_a = migrated.entity_card("process", process_entity_key("4242", "host-a"))
        card_b = migrated.entity_card("process", process_entity_key("4242", "host-b"))

        assert card_a is not None and card_b is not None
        assert (card_a["event_count"], card_b["event_count"]) == (1, 1)
        assert migrated.entity_card("process", "4242") is None, "прежняя общая карточка осталась"
    finally:
        migrated.close()
