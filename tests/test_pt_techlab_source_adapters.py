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
