from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GraphEdge:
    src: str
    dst: str
    kind: str


@dataclass(frozen=True, slots=True)
class CausalMeshSnapshot:
    """Снимок причинно-следственной сети (Causal Mesh)."""

    edges: tuple[GraphEdge, ...]
    known_hosts: frozenset[str]
    new_edges: tuple[GraphEdge, ...] = ()
    lateral_movement_edges: tuple[GraphEdge, ...] = ()
    jump_server_bypass: bool = False


def detect_jump_server_bypass(edges: list[GraphEdge], jump_host: str, plc_hosts: frozenset[str]) -> bool:
    """Прямое обращение к ПЛК/критическому узлу, минуя jump-сервер."""
    for e in edges:
        if e.dst in plc_hosts and e.src != jump_host:
            return True
    return False


def detect_new_edges(
    edges: list[GraphEdge],
    known_hosts: frozenset[str],
) -> list[GraphEdge]:
    """New Edge: связь с узлом, отсутствующим в реестре (air-gap сегмент)."""
    return [e for e in edges if e.dst not in known_hosts and e.src not in known_hosts]


def detect_lateral_movement(
    edges: list[GraphEdge],
    *,
    admin_hosts: frozenset[str],
    plc_hosts: frozenset[str],
) -> list[GraphEdge]:
    """Lateral Movement: цепочка переходов между хостами, минуя admin/jump."""
    result: list[GraphEdge] = []
    for e in edges:
        if e.src in admin_hosts or e.dst in admin_hosts:
            continue
        if e.src in plc_hosts and e.dst in plc_hosts:
            result.append(e)
        elif e.src not in plc_hosts and e.dst not in plc_hosts and e.src != e.dst:
            result.append(e)
    return result


def build_causal_mesh(
    edges: list[GraphEdge],
    *,
    known_hosts: frozenset[str],
    jump_host: str,
    plc_hosts: frozenset[str],
    admin_hosts: frozenset[str] = frozenset(),
) -> CausalMeshSnapshot:
    """Построение причинно-следственной сети (Causal Mesh) с детекцией аномалий."""
    new_edges = detect_new_edges(edges, known_hosts)
    lateral = detect_lateral_movement(edges, admin_hosts=admin_hosts, plc_hosts=plc_hosts)
    bypass = detect_jump_server_bypass(edges, jump_host, plc_hosts)
    return CausalMeshSnapshot(
        edges=tuple(edges),
        known_hosts=known_hosts,
        new_edges=tuple(new_edges),
        lateral_movement_edges=tuple(lateral),
        jump_server_bypass=bypass,
    )
