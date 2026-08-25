from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket


@dataclass(frozen=True, slots=True)
class ContextMatch:
    context_score: float
    in_maintenance_window: bool
    dissonance: bool


def match_event_to_ticket(
    ev: NormalizedEvent,
    tickets: list[ServiceTicket],
    *,
    now: datetime,
) -> ContextMatch:
    """Сопоставление события с окнами заявок (упрощённо по asset_id в payload)."""
    asset = str(ev.payload.get("asset_id") or ev.payload.get("plc_id") or "")
    in_win = False
    for t in tickets:
        mw = t.maintenance_window
        if asset and asset in mw.asset_ids and mw.starts_at <= now <= mw.ends_at:
            in_win = True
            break
    critical = ev.operation.upper() in {"ADMIN_LOGIN", "WRITE_COIL", "REMOTE_SESSION"}
    dissonance = critical and not in_win
    score = 0.85 if in_win else (0.35 if dissonance else 0.55)
    return ContextMatch(
        context_score=score,
        in_maintenance_window=in_win,
        dissonance=dissonance,
    )
