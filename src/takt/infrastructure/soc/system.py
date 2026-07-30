"""Инфраструктурные реализации портов домена ``Clock`` и ``IdGenerator``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


class SystemClock:
    """Системные часы UTC (реализация порта ``Clock``)."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """Фиксированные часы для тестов/детерминированных сценариев."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


class UuidIdGenerator:
    """Генератор коротких идентификаторов на базе uuid4 (реализация ``IdGenerator``)."""

    def __init__(self, length: int = 12) -> None:
        self._length = length

    def generate(self) -> str:
        return uuid.uuid4().hex[: self._length]
