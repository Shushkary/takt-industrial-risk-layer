from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class Process:
    process_id: str
    first_seen: datetime
    last_seen: datetime
    sources: set[str] = field(default_factory=set)
    event_count: int = 0
    parent_process_ids: set[str] = field(default_factory=set)
