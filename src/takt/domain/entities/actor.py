from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

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


@dataclass(slots=True)
class UserAccount:
    user_id: str
    first_seen: datetime
    last_seen: datetime
    sources: set[str] = field(default_factory=set)
    event_count: int = 0
