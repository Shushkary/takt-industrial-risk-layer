"""Реализации портов по умолчанию (без зависимости application → infrastructure)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


class _UtcClock(SystemClockPort):
    __slots__ = ()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)


class _UuidShortCaseIds(IdProviderPort):
    __slots__ = ()

    def new_case_id_short(self) -> str:
        return str(uuid4())[:8]


default_clock: SystemClockPort = _UtcClock()
default_id_provider: IdProviderPort = _UuidShortCaseIds()
