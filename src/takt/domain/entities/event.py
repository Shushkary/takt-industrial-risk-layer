from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping


class EventSource(StrEnum):
    AUTH_LOGS = "auth_logs"
    NETWORK = "network_events"
    PLC_POLLING = "plc_polling"
    SERVICE_DESK = "service_desk"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RawEvent:
    """Сырое событие до нормализации."""

    source: EventSource
    received_at: datetime
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Единая модель события L1."""

    event_id: str
    observed_at: datetime
    source: EventSource
    protocol: str
    operation: str
    payload_size: int
    payload: Mapping[str, Any]
