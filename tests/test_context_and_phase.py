from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.entities.maintenance import MaintenanceWindow, ServiceTicket
from takt.domain.engines.context_matcher import match_event_to_ticket
from takt.domain.engines.phase_time_tagger import (
    WorkPhase,
    phase_dissonance_admin_activity,
    tag_phase,
)


def _event(*, op: str, asset: str = "plc-1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e1",
        observed_at=datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation=op,
        payload_size=1,
        payload={"asset_id": asset},
    )


def test_context_no_tickets_non_critical_neutral_score():
    m = match_event_to_ticket(_event(op="PING"), [], now=datetime.now(timezone.utc))
    assert m.in_maintenance_window is False
    assert m.dissonance is False
    assert m.context_score == pytest.approx(0.55)


def test_context_critical_without_ticket_is_dissonance():
    now = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
    m = match_event_to_ticket(_event(op="ADMIN_LOGIN"), [], now=now)
    assert m.dissonance is True
    assert m.context_score == pytest.approx(0.35)


def test_context_critical_inside_maintenance_window():
    now = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
    mw = MaintenanceWindow(
        window_id="w1",
        title="TO",
        starts_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=2),
        asset_ids=frozenset({"plc-1"}),
    )
    t = ServiceTicket(ticket_id="SD-1", title="t", maintenance_window=mw)
    m = match_event_to_ticket(_event(op="ADMIN_LOGIN", asset="plc-1"), [t], now=now)
    assert m.in_maintenance_window is True
    assert m.dissonance is False
    assert m.context_score == pytest.approx(0.85)


def test_context_wrong_asset_still_dissonant_for_critical():
    now = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
    mw = MaintenanceWindow(
        window_id="w1",
        title="TO",
        starts_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=2),
        asset_ids=frozenset({"other-plc"}),
    )
    t = ServiceTicket(ticket_id="SD-1", title="t", maintenance_window=mw)
    m = match_event_to_ticket(_event(op="WRITE_COIL", asset="plc-1"), [t], now=now)
    assert m.in_maintenance_window is False
    assert m.dissonance is True


def test_context_matches_plc_id_when_asset_id_absent():
    now = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
    ev = NormalizedEvent(
        event_id="e-plc",
        observed_at=now,
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="ADMIN_LOGIN",
        payload_size=1,
        payload={"plc_id": "plc-99"},
    )
    mw = MaintenanceWindow(
        window_id="w2",
        title="TO",
        starts_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        asset_ids=frozenset({"plc-99"}),
    )
    t = ServiceTicket(ticket_id="SD-2", title="t", maintenance_window=mw)
    m = match_event_to_ticket(ev, [t], now=now)
    assert m.in_maintenance_window is True
    assert m.dissonance is False


def test_context_remote_session_is_critical():
    now = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
    m = match_event_to_ticket(_event(op="REMOTE_SESSION"), [], now=now)
    assert m.dissonance is True
    assert m.context_score == pytest.approx(0.35)


def test_tag_phase_work_shift_weekday_utc():
    ts = datetime(2026, 5, 6, 10, 30, tzinfo=timezone.utc)
    label = tag_phase(ts)
    assert label.phase == WorkPhase.WORK_SHIFT
    assert label.local_hour == 10
    assert phase_dissonance_admin_activity(label) is False


def test_tag_phase_night_weekday_utc():
    ts = datetime(2026, 5, 6, 22, 0, tzinfo=timezone.utc)
    label = tag_phase(ts)
    assert label.phase == WorkPhase.NIGHT
    assert phase_dissonance_admin_activity(label) is True


def test_tag_phase_weekend():
    ts = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
    assert ts.weekday() == 5
    label = tag_phase(ts)
    assert label.phase == WorkPhase.WEEKEND
    assert phase_dissonance_admin_activity(label) is True


def test_tag_phase_respects_explicit_zone():
    ts = datetime(2026, 5, 6, 21, 0, tzinfo=timezone.utc)
    label_msk = tag_phase(ts, tz=ZoneInfo("Europe/Moscow"))
    assert label_msk.local_hour == 0
    assert label_msk.phase == WorkPhase.NIGHT


def test_tag_phase_work_shift_hour_boundaries_weekday():
    # 8 <= hour < 20 -> WORK_SHIFT; иначе NIGHT (будни).
    assert tag_phase(datetime(2026, 5, 6, 7, 59, tzinfo=timezone.utc)).phase == WorkPhase.NIGHT
    assert tag_phase(datetime(2026, 5, 6, 8, 0, tzinfo=timezone.utc)).phase == WorkPhase.WORK_SHIFT
    assert tag_phase(datetime(2026, 5, 6, 19, 59, tzinfo=timezone.utc)).phase == WorkPhase.WORK_SHIFT
    assert tag_phase(datetime(2026, 5, 6, 20, 0, tzinfo=timezone.utc)).phase == WorkPhase.NIGHT
