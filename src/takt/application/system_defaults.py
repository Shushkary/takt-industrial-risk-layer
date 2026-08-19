"""Реализации портов по умолчанию (без зависимости application → infrastructure)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from takt.domain.ports.hasher import HasherPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


class _UtcClock(SystemClockPort):
    __slots__ = ()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)


class _UuidShortCaseIds(IdProviderPort):
    __slots__ = ()

    def new_case_id_short(self) -> str:
        return str(uuid4())[:8]


class _Sha256Hasher(HasherPort):
    """SHA256 из стандартной библиотеки: детерминированная реализация без зависимости от L4."""

    __slots__ = ()

    def hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


default_clock: SystemClockPort = _UtcClock()
default_id_provider: IdProviderPort = _UuidShortCaseIds()
default_hasher: HasherPort = _Sha256Hasher()
