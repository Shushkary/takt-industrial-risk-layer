from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.interface_adapters.api.main import create_app


def _event(index: int, source: EventSource) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"event-{index}",
        observed_at=datetime(2026, 6, 1, 9, tzinfo=UTC) + timedelta(hours=index),
        source=source, protocol="test", operation="LOGIN", payload_size=1, payload={},
        entities=EventEntities(
            host_id="ws-17", user_id="ivanov", process_id="proc-1", parent_process_id="parent-1"
        ),
    )


def test_registry_materializes_host_user_and_process_with_history(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        for index, source in enumerate((EventSource.EDR, EventSource.SIEM, EventSource.NDR)):
            store.add_recent_event(_event(index, source), max_events=64)

        host = store.entity_card("host", "ws-17")
        user = store.entity_card("user", "ivanov")
        process = store.entity_card("process", "proc-1")
        assert host is not None and host["typicality"]["status"] == "typical"
        assert host["sources"] == ["edr", "ndr", "siem"]
        assert host["environment_total"] == 3
        assert user is not None and user["event_count"] == 3
        assert process is not None and process["attributes"]["parent_process_id"] == "parent-1"
    finally:
        store.close()


def test_first_seen_and_missing_history_are_explicit(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event(0, EventSource.EDR), max_events=64)
        card = store.entity_card("host", "ws-17")
        assert card is not None and card["typicality"]["status"] == "first_seen"
        assert store.entity_card("host", "unknown") is None
    finally:
        store.close()


def test_entity_card_api_returns_cross_source_environment(tmp_path) -> None:
    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    for index, source in enumerate((EventSource.EDR, EventSource.SIEM, EventSource.NDR)):
        store.add_recent_event(_event(index, source), max_events=64)
    try:
        with TestClient(app) as client:
            response = client.get("/entities/host/ws-17/card")
            assert response.status_code == 200
            body = response.json()
            assert body["typicality"]["status"] == "typical"
            assert {event["source"] for event in body["environment"]} == {"edr", "siem", "ndr"}
    finally:
        app.state.recent_event_store = original
        store.close()


def test_case_workspace_graph_edges_reference_node_ids() -> None:
    """Граф ТЗ п. 5.4: рёбра обязаны соединяться с узлами, иначе интерфейс не построит связи."""
    from datetime import UTC, datetime

    from takt.domain.entities.event import (
        ArtifactType,
        EventArtifact,
        EventEntities,
        EventSource,
        NormalizedEvent,
    )
    from takt.interface_adapters.api.routers.workspace import _case_graph

    events = [
        NormalizedEvent(
            event_id="edr-1", observed_at=datetime(2026, 6, 1, 9, 0, tzinfo=UTC), source=EventSource.EDR,
            protocol="endpoint", operation="PROCESS_START", payload_size=1, payload={},
            entities=EventEntities(host_id="ews-01", user_id="ivanov", process_id="p-2",
                                   parent_process_id="p-1", dst_address="10.10.2.20"),
            artifacts=(EventArtifact(ArtifactType.HASH, "abc"),),
        ),
        NormalizedEvent(
            event_id="ot-1", observed_at=datetime(2026, 6, 1, 9, 1, tzinfo=UTC), source=EventSource.OT,
            protocol="IEC104", operation="WRITE_SETPOINT", payload_size=1, payload={},
            entities=EventEntities(host_id="ews-01", src_address="10.10.2.20", dst_address="10.10.2.21"),
            artifacts=(),
        ),
    ]
    graph = _case_graph(events)

    node_ids = {node["id"] for node in graph["nodes"]}
    assert node_ids, "граф без узлов бесполезен для расследования"
    for node in graph["nodes"]:
        assert node["id"] == f"{node['type']}:{node['value']}"
    assert graph["edges"], "у связанных событий обязаны быть рёбра"
    for edge in graph["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        assert edge["source"] != edge["target"]

    # один адрес — один узел: 10.10.2.20 в одном событии назначение, в другом источник
    address_values = [node["value"] for node in graph["nodes"] if node["type"] == "address"]
    assert sorted(address_values) == ["10.10.2.20", "10.10.2.21"]
    assert "hash:abc" in node_ids
