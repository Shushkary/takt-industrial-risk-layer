from __future__ import annotations

from fastapi import HTTPException

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.interface_adapters.api.dependencies import ApiContext


def _workspace_event(event) -> dict:
    entities = event.entities
    return {
        "event_id": event.event_id, "observed_at": event.observed_at.isoformat(),
        "source": event.source.value, "operation": event.operation, "protocol": event.protocol,
        "entities": ({name: getattr(entities, name) for name in entities.__slots__} if entities else None),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
    }


def _case_graph(events) -> dict:
    """
    Граф связей расследования (ТЗ п. 5.4).

    `source`/`target` рёбер — это `id` узлов (`kind:value`), а не голые значения:
    иначе рёбра невозможно соединить с узлами на стороне интерфейса. Адрес всегда
    получает вид `address`, независимо от того, был он источником или назначением,
    поэтому один адрес — один узел, а не два.
    """
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def node_id(kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        nodes.setdefault(key, {"id": key, "type": kind, "value": value})
        return key

    for event in events:
        entities = event.entities
        if entities is None:
            continue
        host = node_id("host", entities.host_id) if entities.host_id else ""
        user = node_id("user", entities.user_id) if entities.user_id else ""
        process = node_id("process", entities.process_id) if entities.process_id else ""
        parent = node_id("process", entities.parent_process_id) if entities.parent_process_id else ""
        src = node_id("address", entities.src_address) if entities.src_address else ""
        dst = node_id("address", entities.dst_address) if entities.dst_address else ""
        for item in event.artifacts:
            node_id(item.type.value, item.value)

        relations = [
            (user, process, "initiated"),
            (parent, process, "spawned"),
            (host, process, "runs"),
            (host, user, "acted_on"),
            (src, dst, "network"),
            (host, dst, "connects"),
        ]
        relations.extend((host, node_id(item.type.value, item.value), "observed") for item in event.artifacts if host)
        for source, target, kind in relations:
            if source and target and source != target:
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
            "case": ctx.case_to_detail(case).model_dump(),
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
