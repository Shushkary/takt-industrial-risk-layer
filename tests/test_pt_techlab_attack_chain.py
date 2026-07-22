from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import ArtifactType, EventArtifact, EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.interface_adapters.api.main import create_app


def _events() -> list[NormalizedEvent]:
    base = datetime(2026, 6, 1, 9, tzinfo=UTC)
    return [
        NormalizedEvent(
            "e1", base, EventSource.EDR, "endpoint", "PROCESS_START", 1, {},
            entities=EventEntities(host_id="ws-17", user_id="ivanov", process_id="p1"),
            artifacts=(EventArtifact(ArtifactType.FILE, "dropper.exe"),),
        ),
        NormalizedEvent(
            "e2", base + timedelta(seconds=10), EventSource.EDR, "endpoint", "PROCESS_START", 1, {},
            entities=EventEntities(host_id="ws-17", process_id="p2", parent_process_id="p1"),
            artifacts=(EventArtifact(ArtifactType.HASH, "abc"),),
        ),
        NormalizedEvent(
            "e3", base + timedelta(seconds=20), EventSource.NDR, "tcp", "CONNECT", 1, {},
            entities=EventEntities(host_id="ws-17", src_address="10.1.1.17", dst_address="10.2.2.20"),
        ),
    ]


def test_reconstruction_finds_entry_process_and_forward_network_move() -> None:
    result = reconstruct_attack_chain(list(reversed(_events())))
    assert result["entry_point"] == "p1"
    assert [step["kind"] for step in result["steps"]] == ["process_spawn", "process_spawn", "network_move"]
    assert result["steps"][1]["from_entity"] == "p1"
    assert result["current_state"] == "10.2.2.20"
    assert {(item["type"], item["value"]) for item in result["artifacts"]} == {
        ("file", "dropper.exe"), ("hash", "abc")
    }


def test_attack_chain_endpoint_uses_persistent_case_events(tmp_path) -> None:
    app = create_app()
    store = SqliteRecentEventStore(tmp_path / "events.sqlite3")
    original = app.state.recent_event_store
    app.state.recent_event_store = store
    for event in _events():
        store.add_recent_event(event, max_events=64)
    app.state.repo.save(Case(
        case_id="chain-1", status=CaseStatus.NEW, title="chain", risk_class="HIGH", risk_score=0.8,
        created_at=datetime(2026, 6, 1, 9, tzinfo=UTC),
        normalized_event_ids=["e1", "e2", "e3"], burst_fingerprint="chain",
    ))
    try:
        with TestClient(app) as client:
            response = client.get("/cases/chain-1/attack-chain")
            assert response.status_code == 200
            assert response.json()["entry_point"] == "p1"
            assert len(response.json()["steps"]) == 3
            workspace = client.get("/cases/chain-1/workspace")
            assert workspace.status_code == 200
            assert len(workspace.json()["events"]) == 3
            assert workspace.json()["graph"]["edges"]
            assert workspace.json()["attack_chain"]["entry_point"] == "p1"
    finally:
        app.state.recent_event_store = original
        store.close()
