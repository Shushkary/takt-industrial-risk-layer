from datetime import UTC
from pathlib import Path

import pytest

from takt.domain.entities.event import EventSource, RawEvent
from takt.infrastructure.importers.csv_events import (
    iter_raw_events,
    load_normalized_from_csv,
    raw_row_to_normalized,
)


def test_csv_loader():
    p = Path(__file__).resolve().parents[1] / "config" / "demo" / "plc_polling_demo.csv"
    events = load_normalized_from_csv(p, source=EventSource.PLC_POLLING)
    assert len(events) == 2
    assert events[0].protocol == "TCP"


def test_raw_row_z_suffix_timestamp_utc():
    row = {
        "timestamp": "2026-01-15T10:30:00Z",
        "protocol": "TCP",
        "op": "read",
        "payload_size": "8",
    }
    ev = raw_row_to_normalized(row, source=EventSource.PLC_POLLING)
    assert ev.observed_at.tzinfo == UTC
    assert ev.observed_at.hour == 10
    assert ev.operation == "READ"


def test_raw_row_time_column_and_naive_local_becomes_utc():
    row = {
        "time": "2026-02-01T08:15:00",
        "proto": "UDP",
        "action": "ping",
        "payload_size": "0",
    }
    ev = raw_row_to_normalized(row, source=EventSource.NETWORK)
    assert ev.protocol == "UDP"
    assert ev.operation == "PING"
    assert ev.observed_at.tzinfo == UTC


def test_raw_row_missing_timestamp_raises():
    with pytest.raises(ValueError, match="timestamp"):
        raw_row_to_normalized({"protocol": "TCP"}, source=EventSource.PLC_POLLING)


def test_raw_row_non_int_payload_size_uses_fallback_length():
    row = {
        "ts": "2026-03-01T00:00:00+00:00",
        "protocol": "M",
        "operation": "X",
        "payload_size": "nope",
    }
    ev = raw_row_to_normalized(row, source=EventSource.AUTH_LOGS)
    assert ev.payload_size == len(str(row))


def test_raw_row_respects_explicit_event_id():
    row = {
        "timestamp": "2026-04-01T00:00:00+00:00",
        "protocol": "T",
        "operation": "O",
        "payload_size": "1",
    }
    ev = raw_row_to_normalized(row, source=EventSource.PLC_POLLING, event_id="my-id")
    assert ev.event_id == "my-id"


def test_iter_raw_events_skips_rows_without_timestamp(tmp_path: Path) -> None:
    p = tmp_path / "ev.csv"
    p.write_text(
        "timestamp,op,note\n"
        "2026-05-01T00:00:00+00:00,POLL,ok\n"
        ",BAD,skip\n"
        "2026-05-01T00:00:01+00:00,POLL,ok2\n",
        encoding="utf-8",
    )
    rows = list(iter_raw_events(p, source=EventSource.PLC_POLLING))
    assert len(rows) == 2
    assert isinstance(rows[0], RawEvent)
    assert rows[0].source == EventSource.PLC_POLLING
    assert rows[0].received_at.tzinfo == UTC
    assert rows[0].payload["note"] == "ok"
    assert rows[1].payload["note"] == "ok2"
