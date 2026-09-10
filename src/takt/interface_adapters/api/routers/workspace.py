from __future__ import annotations

from fastapi import HTTPException

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.application.use_cases.response_package import build_response_package
from takt.domain.services.process_identity import process_entity_key
from takt.interface_adapters.api.dependencies import ApiContext, require


def _workspace_event(event) -> dict:
    entities = event.entities
    return {
        "event_id": event.event_id, "observed_at": event.observed_at.isoformat(),
        "source": event.source.value, "operation": event.operation, "protocol": event.protocol,
        "entities": ({name: getattr(entities, name) for name in entities.__slots__} if entities else None),
        # Ключ процесса как сущности: один PID на двух узлах — два разных процесса, и карточку
        # надо открывать по ключу, а не по значению из источника. Показывается по-прежнему PID.
        "process_key": process_entity_key(
            entities.process_id if entities else None, entities.host_id if entities else None
        ),
        "artifacts": [{"type": item.type.value, "value": item.value} for item in event.artifacts],
    }


def _expanded_hosts(case, events) -> list[str]:
    """Узлы, добранные расширением до узла.

    Они попали в дело по узлу, а не по признаку атаки, поэтому в пакете идут отдельной
    группой и по умолчанию не отмечены.
    """
    expanded = {
        item.event_id for item in case.correlation_evidence if getattr(item, "rule", "") == "host-expansion"
    }
    hosts: list[str] = []
    for event in events:
        if event.event_id not in expanded:
            continue
        host = (event.entities.host_id if event.entities else "") or ""
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _case_graph(events) -> dict:
    """Сущности дела и связи между ними по его же событиям.

    Связь появляется только там, где событие называет обе стороны. Адрес источника к узлу
    не подтягивается намеренно: в событии рабочей станции `src_address` — часто адрес
    самого узла, и связь «адрес обратился к узлу» оказалась бы утверждением о том, что узел
    обращался к себе. В доказательный материал такое попадать не должно.
    """
    nodes: dict[tuple[str, str], dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    for event in events:
        entities = event.entities
        if entities is None:
            continue
        values = {
            "host": entities.host_id, "user": entities.user_id, "process": entities.process_id,
            "address": entities.src_address, "destination": entities.dst_address,
            # Родительский процесс — такая же сущность дела: связь «породил» указывает на
            # него, и без вершины она вела бы в пустоту. Рисунок такую связь просто терял.
            "parent": entities.parent_process_id,
        }
        for kind, value in values.items():
            if value:
                nodes[(kind, value)] = {"id": f"{kind}:{value}", "type": kind, "value": value}
        relations = [
            (entities.user_id, entities.process_id, "initiated"),
            (entities.parent_process_id, entities.process_id, "spawned"),
            (entities.host_id, entities.process_id, "runs"),
            (entities.src_address, entities.dst_address, "network"),
            # Учётная запись на узле. Все четыре связи выше требуют процесса или пары
            # адресов, поэтому событие промышленного источника — запись в регистр ПЛК от
            # учётной записи, без процесса — не давало ни одной связи: узел `plc-line-3`
            # висел на графе отдельной точкой, хотя событие прямо называет, кто на нём
            # действовал. Замер на демонстрационном деле: висячих вершин было две
            # (`plc-line-3`, `jump-01`), с этой связью — ни одной.
            (entities.user_id, entities.host_id, "acts_on"),
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
            # Состав пакета считает продукт, а не браузер: раньше окно собирало его из
            # артефактов пивота и знало три типа, поэтому хеш, домен и файл до пакета не
            # доходили, а дело, собранное не пивотом, оставляло панель пустой.
            "response_package": _response_package(case, ordered),
        }

    def _response_package(case, ordered) -> dict:
        package = build_response_package(case, ordered, expanded_hosts=_expanded_hosts(case, ordered))
        return {
            "version": package.version,
            "boundary_note": package.boundary_note,
            "candidates": [
                {
                    "type": item.type, "value": item.value, "action": item.action,
                    "host_id": item.host_id, "host_known": item.host_known,
                    "origin": item.origin, "event_ids": list(item.event_ids),
                    "source": item.source, "verification_status": item.verification_status,
                    "group": item.group, "selected_by_default": item.selected_by_default,
                }
                for item in package.candidates
            ],
        }
