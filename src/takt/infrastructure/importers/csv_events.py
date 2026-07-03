from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from takt.domain.entities.event import EventSource, NormalizedEvent, RawEvent


def _parse_ts(value: str) -> datetime:
    val = value.strip()
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    dt = datetime.fromisoformat(val)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def raw_row_to_normalized(
    row: dict[str, str],
    *,
    source: EventSource,
    event_id: str | None = None,
) -> NormalizedEvent:
    """Универсальный маппинг полей demo CSV (auth / plc)."""
    ts_raw = row.get("timestamp") or row.get("ts") or row.get("time")
    if not ts_raw:
        raise ValueError("row missing timestamp")
    observed = _parse_ts(ts_raw)
    protocol = row.get("protocol") or row.get("proto") or "unknown"
    operation = (
        row.get("operation")
        or row.get("event_type")
        or row.get("action")
        or row.get("op")
        or "UNKNOWN"
    )
    payload = dict(row)
    operator_id = (
        row.get("operator_id")
        or row.get("operator")
        or row.get("actor")
        or row.get("username")
        or row.get("user")
        or ""
    )
    ps = row.get("payload_size") or row.get("length") or "0"
    try:
        payload_size = int(ps)
    except ValueError:
        payload_size = len(str(row))
    return NormalizedEvent(
        event_id=event_id or str(uuid4()),
        observed_at=observed,
        source=source,
        protocol=str(protocol),
        operation=str(operation).upper(),
        payload_size=payload_size,
        payload=payload,
        operator_id=str(operator_id).strip(),
    )


def load_normalized_from_csv(
    path: str | Path, *, source: EventSource
) -> list[NormalizedEvent]:
    p = Path(path)
    out: list[NormalizedEvent] = []
    with p.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out.append(raw_row_to_normalized(row, source=source))
    return out


def iter_raw_events(path: str | Path, *, source: EventSource):
    p = Path(path)
    with p.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_raw = row.get("timestamp") or row.get("ts") or row.get("time")
            if not ts_raw:
                continue
            yield RawEvent(
                source=source,
                received_at=_parse_ts(ts_raw),
                payload=dict(row),
            )
