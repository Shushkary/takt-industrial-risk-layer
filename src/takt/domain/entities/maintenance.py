from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    window_id: str
    title: str
    starts_at: datetime
    ends_at: datetime
    asset_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class ServiceTicket:
    ticket_id: str
    title: str
    maintenance_window: MaintenanceWindow
