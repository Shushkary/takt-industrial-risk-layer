from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.interface_adapters.api.main import create_app


def _event(event_id: str, source: EventSource, *, host: str, address: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=datetime(2026, 6, 1, 9, 0, tzinfo=UTC),
        source=source,
        protocol="test",
        operation="OBSERVED",
        payload_size=10,
        payload={"message": f"indicator for {host}"},
        entities=EventEntities(host_id=host, dst_address=address),
        artifacts=(EventArtifact(ArtifactType.DOMAIN, "evil.example"),),
        ingest_trust=0.75,
    )


def test_persistent_search_unifies_sources_and_survives_ring_trim(tmp_path) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    try:
        store.add_recent_event(_event("edr-1", EventSource.EDR, host="ws-17", address="10.2.3.4"), max_events=1)
        store.add_recent_event(_event("siem-1", EventSource.SIEM, host="ws-17", address="10.2.3.4"), max_events=1)

        assert len(store.list_recent_events(limit=64)) == 1
        events, total = store.search_events(host_id="ws-17", limit=100)
        assert total == 2
        assert {event.source for event in events} == {EventSource.EDR, EventSource.SIEM}
        assert store.event_counts_by_source() == {"edr": 1, "siem": 1}
    finally:
        store.close()


def test_events_search_api_returns_total_and_catalog_counts(tmp_path) -> None:
    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    store.add_recent_event(_event("ndr-1", EventSource.NDR, host="ws-17", address="10.2.3.4"), max_events=64)
    try:
        with TestClient(app) as client:
            response = client.get("/events/search", params={"host_id": "ws-17"})
            assert response.status_code == 200
            assert response.headers["X-Total-Count"] == "1"
            assert response.json()[0]["entities"]["host_id"] == "ws-17"

            catalog = {item["id"]: item for item in client.get("/catalog/event-sources").json()}
            assert catalog["ndr"]["source_class"] == "ndr"
            assert catalog["ndr"]["event_count"] == 1
    finally:
        app.state.recent_event_store = original
        store.close()
