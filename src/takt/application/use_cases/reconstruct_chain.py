from __future__ import annotations

from dataclasses import dataclass

from takt.domain.entities.event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class AttackChainStep:
    order: int
    kind: str
    event_id: str
    observed_at: str
    source: str
    from_entity: str
    to_entity: str
    operation: str


def reconstruct_attack_chain(events: list[NormalizedEvent]) -> dict:
    ordered = sorted(events, key=lambda event: (event.observed_at, event.event_id))
    process_ids = {
        event.entities.process_id for event in ordered if event.entities and event.entities.process_id
    }
    steps: list[AttackChainStep] = []
    entry_point = ""
    artifact_rows: dict[tuple[str, str], dict[str, str]] = {}
    for event in ordered:
        entities = event.entities
        if entities is not None and entities.process_id:
            parent = entities.parent_process_id or ""
            if not entry_point and (not parent or parent not in process_ids):
                entry_point = parent or entities.process_id
            steps.append(AttackChainStep(
                order=0, kind="process_spawn", event_id=event.event_id,
                observed_at=event.observed_at.isoformat(), source=event.source.value,
                from_entity=parent or entities.user_id or entities.host_id or "unknown",
                to_entity=entities.process_id, operation=event.operation,
            ))
        if entities is not None and entities.src_address and entities.dst_address:
            entry_point = entry_point or entities.src_address
            steps.append(AttackChainStep(
                order=0, kind="network_move", event_id=event.event_id,
                observed_at=event.observed_at.isoformat(), source=event.source.value,
                from_entity=entities.src_address, to_entity=entities.dst_address,
                operation=event.operation,
            ))
        for artifact in event.artifacts:
            artifact_rows[(artifact.type.value, artifact.value)] = {
                "type": artifact.type.value, "value": artifact.value, "event_id": event.event_id,
            }
    numbered = [
        {
            "order": index, "kind": step.kind, "event_id": step.event_id,
            "observed_at": step.observed_at, "source": step.source,
            "from_entity": step.from_entity, "to_entity": step.to_entity,
            "operation": step.operation,
        }
        for index, step in enumerate(steps, start=1)
    ]
    return {
        "entry_point": entry_point or (ordered[0].event_id if ordered else ""),
        "steps": numbered,
        "current_state": numbered[-1]["to_entity"] if numbered else "",
        "artifacts": list(artifact_rows.values()),
    }
