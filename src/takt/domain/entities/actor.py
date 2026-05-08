from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from takt.domain.entities.event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class Actor:
    """Субъект действия (учётка, сервис, псевдоним)."""

    actor_id: str
    display_name: str
    attributes: Mapping[str, str]

    @staticmethod
    def from_event(ev: NormalizedEvent) -> Actor:
        uid = ev.payload.get("actor_id") or ev.payload.get("username") or "unknown"
        name = str(ev.payload.get("display_name") or uid)
        return Actor(actor_id=str(uid), display_name=name, attributes=dict(ev.payload))
