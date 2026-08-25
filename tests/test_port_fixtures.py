from __future__ import annotations

from datetime import UTC, datetime

from takt.application.port_fixtures import FrozenClock, SequentialIdProvider


def test_frozen_clock_returns_same_instant() -> None:
    t = datetime(2025, 6, 1, 8, 30, tzinfo=UTC)
    c = FrozenClock(at=t)
    assert c.now_utc() is t
    assert c.now_utc() is t


def test_sequential_id_provider_increments() -> None:
    p = SequentialIdProvider(prefix="t")
    assert p.new_case_id_short() == "t00001"
    assert p.new_case_id_short() == "t00002"
