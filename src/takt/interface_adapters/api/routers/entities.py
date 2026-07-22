from __future__ import annotations

from fastapi import HTTPException, Query

from takt.interface_adapters.api.dependencies import ApiContext


def register_entity_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/entities/{entity_type}/{entity_id}/card", tags=["Entities"])
    def entity_card(entity_type: str, entity_id: str, event_limit: int = Query(default=100, ge=1, le=1000)):
        if entity_type not in {"host", "user", "process"}:
            raise HTTPException(status_code=400, detail="entity_type must be host, user or process")
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            raise HTTPException(status_code=404, detail="entity history is unavailable")
        card = store.entity_card(entity_type, entity_id, event_limit=event_limit)
        if card is None:
            raise HTTPException(status_code=404, detail="entity not found")
        event_ids = {event["event_id"] for event in card["environment"]}
        card["related_cases"] = [
            case.case_id for case in ctx.repo.list_all() if event_ids.intersection(case.normalized_event_ids)
        ]
        return card
