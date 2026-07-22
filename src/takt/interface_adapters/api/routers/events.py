from __future__ import annotations

from datetime import datetime

from fastapi import Query, Response

from takt.domain.entities.event import NormalizedEvent
from takt.interface_adapters.api.dependencies import ApiContext


def _event_dict(event: NormalizedEvent) -> dict:
    entities = event.entities
    return {
        "event_id": event.event_id,
        "observed_at": event.observed_at.isoformat(),
        "source": event.source.value,
        "protocol": event.protocol,
        "operation": event.operation,
        "payload_size": event.payload_size,
        "payload": dict(event.payload),
        "operator_id": event.operator_id,
        "entities": ({name: getattr(entities, name) for name in entities.__slots__} if entities else None),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
        "ingest_trust": event.ingest_trust,
    }


def register_event_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/events/search", tags=["Events"])
    def search_events(
        response: Response,
        source: str | None = None,
        observed_from: datetime | None = None,
        observed_to: datetime | None = None,
        host_id: str | None = None,
        user_id: str | None = None,
        process_id: str | None = None,
        address: str | None = None,
        artifact_type: str | None = None,
        artifact_value: str | None = None,
        text: str | None = None,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
    ):
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            response.headers["X-Total-Count"] = "0"
            return []
        events, total = store.search_events(
            source=source, observed_from=observed_from, observed_to=observed_to,
            host_id=host_id, user_id=user_id, process_id=process_id, address=address,
            artifact_type=artifact_type, artifact_value=artifact_value, text=text,
            offset=offset, limit=limit,
        )
        response.headers["X-Total-Count"] = str(total)
        return [_event_dict(event) for event in events]
