from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Asset:
    """Объект КИИ / узел топологии."""

    asset_id: str
    segment: str
    is_air_gapped: bool
    metadata: dict[str, str]


@dataclass(slots=True)
class Host:
    host_id: str
    first_seen: datetime
    last_seen: datetime
    sources: set[str] = field(default_factory=set)
    event_count: int = 0
