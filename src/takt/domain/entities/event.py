from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class EventSource(StrEnum):
    EDR = "edr"
    SIEM = "siem"
    NDR = "ndr"
    OT = "ot"
    AUTH_LOGS = "auth_logs"
    NETWORK = "network_events"
    PLC_POLLING = "plc_polling"
    SERVICE_DESK = "service_desk"
    UNKNOWN = "unknown"


class ArtifactType(StrEnum):
    HOST = "host"
    FILE = "file"
    HASH = "hash"
    PROCESS = "process"
    ACCOUNT = "account"
    ADDRESS = "address"
    URL = "url"
    DOMAIN = "domain"


@dataclass(frozen=True, slots=True)
class EventEntities:
    host_id: str | None = None
    user_id: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    src_address: str | None = None
    dst_address: str | None = None


@dataclass(frozen=True, slots=True)
class EventArtifact:
    type: ArtifactType
    value: str


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
    operator_id: str = ""
    entities: EventEntities | None = None
    artifacts: tuple[EventArtifact, ...] = ()
    ingest_trust: float = 1.0
