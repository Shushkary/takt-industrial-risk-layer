from __future__ import annotations

from pathlib import Path

import pytest

from takt.infrastructure.stores.sqlite_store import SqliteExpectedBehavior


def test_sqlite_expected_behavior_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "eb.db"
    s = SqliteExpectedBehavior(db)
    assert not s.is_expected("PLC-99", "READ")
    s.mark_expected(" PLC-99 ", " read ")
    assert s.is_expected("plc-99", "READ")
    s.close()

    s2 = SqliteExpectedBehavior(db)
    assert s2.is_expected("PLC-99", "READ")
    s2.close()


def test_sqlite_expected_behavior_close_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "eb2.db"
    s = SqliteExpectedBehavior(db)
    s.close()
    s.close()
    assert db.is_file()


def test_sqlite_expected_behavior_skips_empty_asset_or_operation(
    tmp_path: Path,
) -> None:
    db = tmp_path / "eb-empty.db"
    s = SqliteExpectedBehavior(db)
    try:
        s.mark_expected("", "READ")
        s.mark_expected("   ", "READ")
        s.mark_expected("PLC-A", "")
        s.mark_expected("PLC-A", "   ")
        assert not s.is_expected("PLC-A", "READ")
        assert not s.is_expected("", "READ")
        assert not s.is_expected("   ", "READ")
    finally:
        s.close()


def test_sqlite_expected_behavior_raises_after_close(tmp_path: Path) -> None:
    s = SqliteExpectedBehavior(tmp_path / "eb-closed.db")
    s.close()
    with pytest.raises(RuntimeError, match="closed"):
        s.mark_expected("a", "READ")
    with pytest.raises(RuntimeError, match="closed"):
        s.is_expected("a", "READ")
