from __future__ import annotations

from takt.infrastructure.stores.memory import InMemoryExpectedBehavior


def test_in_memory_expected_behavior_normalizes_and_checks_pair():
    b = InMemoryExpectedBehavior()
    b.mark_expected(" PLC-Edge ", " read ")
    assert b.is_expected("plc-edge", "READ")
    assert not b.is_expected("plc-edge", "WRITE")


def test_in_memory_expected_is_expected_false_for_empty_asset():
    b = InMemoryExpectedBehavior()
    b.mark_expected("a", "POLL")
    assert not b.is_expected("", "POLL")


def test_in_memory_mark_expected_empty_asset_is_noop():
    b = InMemoryExpectedBehavior()
    b.mark_expected("", "READ")
    b.mark_expected("   ", "READ")
    b.mark_expected("plc-a", "   ")
    assert not b.is_expected("any", "READ")
    assert not b.is_expected("   ", "READ")
    assert not b.is_expected("plc-a", "")
