from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GraphEdge:
    src: str
    dst: str
    kind: str


def detect_jump_server_bypass(edges: list[GraphEdge], jump_host: str, plc_hosts: frozenset[str]) -> bool:
    """Прямое обращение к ПЛК/критическому узлу, минуя jump-сервер."""
    for e in edges:
        if e.dst in plc_hosts and e.src != jump_host:
            return True
    return False
