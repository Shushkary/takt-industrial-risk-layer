from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from zoneinfo import ZoneInfo

# ZoneInfo — данные о зонах в stdlib; для домена допустим как чистая таблица смещений


class WorkPhase(StrEnum):
    WORK_SHIFT = "WORK_SHIFT"
    NIGHT = "NIGHT"
    WEEKEND = "WEEKEND"


@dataclass(frozen=True, slots=True)
class PhaseLabel:
    phase: WorkPhase
    local_hour: int


def tag_phase(ts: datetime, tz: ZoneInfo | None = None) -> PhaseLabel:
    """Фаза суток / смены (UTC или переданная зона)."""
    local = ts.astimezone(tz) if tz else ts
    h = local.hour
    if local.weekday() >= 5:
        return PhaseLabel(phase=WorkPhase.WEEKEND, local_hour=h)
    if 8 <= h < 20:
        return PhaseLabel(phase=WorkPhase.WORK_SHIFT, local_hour=h)
    return PhaseLabel(phase=WorkPhase.NIGHT, local_hour=h)


def phase_dissonance_admin_activity(label: PhaseLabel) -> bool:
    """Админская активность вне дневной смены — повышение контекстного риска."""
    return label.phase in (WorkPhase.NIGHT, WorkPhase.WEEKEND)
