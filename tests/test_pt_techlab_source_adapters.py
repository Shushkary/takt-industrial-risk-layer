from __future__ import annotations

from pathlib import Path

import pytest

from takt.domain.entities.event import ArtifactType, EventSource
from takt.infrastructure.importers.soc_csv import (
    CsvEventSourceReader,
    map_edr,
    map_ndr,
    map_ot,
    map_siem,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pt_techlab"


@pytest.mark.parametrize(
    ("name", "mapper", "source", "host", "artifact"),
    [
        ("edr.csv", map_edr, EventSource.EDR, "ws-17", ArtifactType.HASH),
        ("siem.csv", map_siem, EventSource.SIEM, "ws-17", ArtifactType.DOMAIN),
        ("ndr.csv", map_ndr, EventSource.NDR, "ws-17", ArtifactType.DOMAIN),
        ("ot.csv", map_ot, EventSource.OT, "plc-01", ArtifactType.PROCESS),
    ],
)
def test_real_contract_row_maps_to_soc_event(name, mapper, source, host, artifact) -> None:
    events = list(CsvEventSourceReader(FIXTURES / name, mapper, ingest_trust=0.8))
    assert len(events) == 2
    event = events[0]
    assert event.source is source
    assert event.entities is not None and event.entities.host_id == host
    assert event.artifacts[0].type is artifact
    assert event.ingest_trust == 0.8
    assert event.payload["incident_id"] == "INC-001"


def test_ot_row_without_operator_keeps_user_empty() -> None:
    """Колонка operator_id опциональна: выгрузка без неё должна грузиться как раньше."""
    event = map_ot(
        {"event_id": "ot-1", "timestamp": "2026-06-01T09:00:00Z", "asset_id": "plc-01",
         "src_address": "10.10.2.5", "dst_address": "10.10.2.20", "protocol": "IEC104",
         "operation": "poll", "tag": "boiler.pressure", "payload_size": "64"},
        1.0,
    )
    assert event.entities is not None and event.entities.user_id is None
    assert event.operator_id == ""


def test_ot_row_with_operator_populates_user_for_correlation() -> None:
    """operator_id из контракта попадает в user_id — иначе правило user_destination слепо к OT."""
    event = map_ot(
        {"event_id": "ot-2", "timestamp": "2026-06-01T09:01:00Z", "asset_id": "plc-01",
         "operator_id": "ivanov", "src_address": "10.10.1.17", "dst_address": "10.10.2.20",
         "protocol": "IEC104", "operation": "write_setpoint", "tag": "boiler.pressure",
         "payload_size": "64"},
        1.0,
    )
    assert event.entities is not None
    assert event.entities.user_id == "ivanov"
    assert event.entities.dst_address == "10.10.2.20"
    assert event.operator_id == "ivanov"
