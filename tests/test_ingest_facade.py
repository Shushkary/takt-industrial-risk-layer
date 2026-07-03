from __future__ import annotations

from types import SimpleNamespace

from takt.application.use_cases.ingest_facade import IngestAssessmentFacade
from takt.domain.entities.event import EventSource
from takt.infrastructure.importers.csv_events import raw_row_to_normalized


def test_prepared_event_ingest_body_preserves_raw_payload_and_note() -> None:
    facade = IngestAssessmentFacade(
        process=None,  # type: ignore[arg-type]
        repo=None,  # type: ignore[arg-type]
        event_window=[],
        event_window_max=100,
        graph_edges=[],
        polling_intervals_us=[],
        raw_row_to_normalized=raw_row_to_normalized,
    )
    raw_payload = b'{"source":"network_events","operation":"WRITE_COIL"}'
    body = SimpleNamespace(
        observed_at="2026-05-05T10:00:00+00:00",
        protocol="modbus",
        operation="WRITE_COIL",
        asset_id="plc-1",
        operator_id="operator-1",
        payload_size=42,
        payload={"type_id": "5"},
        event_id="event-1",
    )

    prepared = facade.prepared_event_ingest_body(
        body,
        raw_payload=raw_payload,
        source=EventSource.NETWORK,
        note="events_batch_ingest",
    )

    assert prepared.raw_payload == raw_payload
    assert prepared.source is EventSource.NETWORK
    assert prepared.note == "events_batch_ingest"
    assert prepared.event.event_id == "event-1"
    assert prepared.event.payload["asset_id"] == "plc-1"
    assert prepared.event.operation == "WRITE_COIL"
