from __future__ import annotations

from takt.domain.entities.event import EventSource


def test_event_source_values_are_unique_strs():
    vals = [m.value for m in EventSource]
    assert len(vals) == len(set(vals))
    assert all(isinstance(v, str) and v for v in vals)


def test_event_source_expected_mvp_set():
    assert {m.value for m in EventSource} >= {
        "auth_logs",
        "network_events",
        "plc_polling",
        "service_desk",
        "unknown",
    }
