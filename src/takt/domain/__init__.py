"""L1 Domain — сущности (без внешних зависимостей)."""

from takt.domain.entities.actor import Actor
from takt.domain.entities.asset import Asset
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import NormalizedEvent, RawEvent
from takt.domain.entities.maintenance import MaintenanceWindow, ServiceTicket

__all__ = [
    "Actor",
    "Asset",
    "Case",
    "CaseStatus",
    "NormalizedEvent",
    "RawEvent",
    "MaintenanceWindow",
    "ServiceTicket",
]
