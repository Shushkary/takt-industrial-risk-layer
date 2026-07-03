from __future__ import annotations

import pytest
from fastapi import HTTPException

from takt.domain.entities.event import EventSource
from takt.interface_adapters.api.event_sources import coerce_event_source


def test_coerce_event_source_defaults_to_plc_polling() -> None:
    assert coerce_event_source(None) is EventSource.PLC_POLLING
    assert coerce_event_source("") is EventSource.PLC_POLLING


def test_coerce_event_source_accepts_known_value() -> None:
    assert coerce_event_source("network_events") is EventSource.NETWORK


def test_coerce_event_source_rejects_unknown_value() -> None:
    with pytest.raises(HTTPException) as exc:
        coerce_event_source("not-a-source")

    assert exc.value.status_code == 400
    assert "invalid source" in str(exc.value.detail)
