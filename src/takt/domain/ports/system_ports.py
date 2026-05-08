"""Порты времени и идентификаторов (инъекция из L2/L3; реализации — в application по умолчанию)."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class SystemClockPort(Protocol):
    """Текущее время UTC (для сценариев, где нельзя опереться только на **observed_at** события)."""

    def now_utc(self) -> datetime: ...


@runtime_checkable
class IdProviderPort(Protocol):
    """Короткий идентификатор карточки (как **case_id** в **AssessRiskUseCase**)."""

    def new_case_id_short(self) -> str: ...
