from __future__ import annotations

from fastapi import HTTPException

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.interface_adapters.api.dependencies import ApiContext, require


def _workspace_event(event) -> dict:
    entities = event.entities
    return {
        "event_id": event.event_id, "observed_at": event.observed_at.isoformat(),
        "source": event.source.value, "operation": event.operation, "protocol": event.protocol,
        "entities": ({name: getattr(entities, name) for name in entities.__slots__} if entities else None),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
    }


def _case_graph(events) -> dict:
    nodes: dict[tuple[str, str], dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    for event in events:
        entities = event.entities
        if entities is None:
            continue
        values = {
            "host": entities.host_id, "user": entities.user_id, "process": entities.process_id,
            "address": entities.src_address, "destination": entities.dst_address,
        }
        for kind, value in values.items():
            if value:
                nodes[(kind, value)] = {"id": f"{kind}:{value}", "type": kind, "value": value}
        relations = [
            (entities.user_id, entities.process_id, "initiated"),
            (entities.parent_process_id, entities.process_id, "spawned"),
            (entities.host_id, entities.process_id, "runs"),
            (entities.src_address, entities.dst_address, "network"),
        ]
        for source, target, kind in relations:
            if source and target:
                edges[(source, target, kind)] = {
                    "source": source, "target": target, "type": kind, "event_id": event.event_id,
                }
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def register_workspace_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/cases/{case_id}/workspace", tags=["Cases"])
    def workspace(case_id: str):
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id}")
        store = getattr(app.state, "recent_event_store", None)
        events = store.events_by_ids(case.normalized_event_ids) if store is not None else []
        ordered = sorted(events, key=lambda item: (item.observed_at, item.event_id))
        return {
            "case": require(ctx.case_to_detail, "case_to_detail")(case).model_dump(),
            "events": [_workspace_event(event) for event in ordered],
            "timeline": [
                {
                    "id": event.event_id, "at": event.observed_at.isoformat(),
                    "kind": "event", "source": event.source.value, "label": event.operation,
                } for event in ordered
            ] + [
                {"id": f"audit-{index}", "at": line.split(" | ", 1)[0], "kind": "analyst_action", "label": line}
                for index, line in enumerate(case.audit_log)
            ],
            "graph": _case_graph(ordered),
            "findings": [
                {"finding_id": item.finding_id, "text": item.text, "author": item.author}
                for item in case.findings
            ],
            "artifacts": [
                {"type": item.type, "value": item.value, "source": item.source}
                for item in case.artifacts
            ],
            "attack_chain": reconstruct_attack_chain(ordered),
        }
