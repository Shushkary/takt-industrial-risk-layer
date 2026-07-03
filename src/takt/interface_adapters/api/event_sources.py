from __future__ import annotations

from fastapi import HTTPException

from takt.domain.entities.event import EventSource


def coerce_event_source(raw: str | None) -> EventSource:
    if raw is None or raw == "":
        return EventSource.PLC_POLLING
    try:
        return EventSource(raw)
    except ValueError as exc:
        allowed = ", ".join(source.value for source in EventSource)
        raise HTTPException(status_code=400, detail=f"invalid source; use one of: {allowed}") from exc
