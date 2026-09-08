from __future__ import annotations

from fastapi import HTTPException, Query

from takt.interface_adapters.api.dependencies import ApiContext


def register_entity_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/entities/{entity_type}/{entity_id}/card", tags=["Entities"])
    def entity_card(
        entity_type: str,
        entity_id: str,
        event_limit: int = Query(default=100, ge=1, le=1000),
        event_offset: int = Query(
            default=0, ge=0,
            description="Смещение страницы истории: за пределом одного запроса она достаётся страницами",
        ),
    ):
        if entity_type not in {"host", "user", "process"}:
            raise HTTPException(status_code=400, detail="entity_type must be host, user or process")
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            raise HTTPException(status_code=404, detail="entity history is unavailable")
        card = store.entity_card(entity_type, entity_id, event_limit=event_limit, event_offset=event_offset)
        if card is None:
            raise HTTPException(status_code=404, detail="entity not found")
        # Связанные дела считаются по всей истории сущности, а не по показанной её странице:
        # дело, собранное вокруг события за пределом страницы, иначе выпадало из карточки.
        card["related_cases"] = _related_cases(entity_type, entity_id)
        return card

    def _related_cases(entity_type: str, entity_id: str) -> list[str]:
        column = {"host": "host_id", "user": "user_id", "process": "process_key"}[entity_type]
        store = app.state.recent_event_store
        found: list[str] = []
        seen: set[str] = set()
        offset = 0
        page = 1000
        history: set[str] = set()
        while True:
            events, total = store.search_events(limit=page, offset=offset, **{column: entity_id})
            history.update(event.event_id for event in events)
            offset += len(events)
            if not events or offset >= total:
                break
        for case in ctx.repo.list_all():
            if case.case_id in seen:
                continue
            if history.intersection(case.normalized_event_ids):
                seen.add(case.case_id)
                found.append(case.case_id)
        return found
