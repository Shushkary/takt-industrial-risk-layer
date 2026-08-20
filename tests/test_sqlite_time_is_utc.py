"""Время в SQLite хранится в UTC, а не в зоне машины.

`dt_to_sql` вызывал `astimezone()` без аргумента — запись шла в локальной зоне сервера.
Событие, принятое в UTC, возвращалось в интерфейс со смещением машины, и цепочка инцидента
читалась не в тех сутках. Хуже другое: `observed_at` — текстовая колонка, выборки событий
сортируются по ней лексикографически, и записи с разными смещениями упорядочивались по
написанию, а не по моменту времени.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from takt.domain.entities.event import EventSource
from takt.infrastructure.importers.csv_events import raw_row_to_normalized
from takt.infrastructure.stores.sqlite_connection import dt_from_sql, dt_to_sql
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore


def test_aware_datetime_is_written_in_utc() -> None:
    moment = datetime(2026, 8, 17, 6, 0, tzinfo=timezone(timedelta(hours=-7)))
    written = dt_to_sql(moment)
    assert written.endswith("+00:00"), written
    assert dt_from_sql(written) == moment


def test_same_instant_has_one_representation() -> None:
    """Один момент времени пишется одинаково, из какой бы зоны он ни пришёл."""
    utc = datetime(2026, 8, 17, 13, 0, tzinfo=UTC)
    same_moment_elsewhere = utc.astimezone(timezone(timedelta(hours=3)))
    assert dt_to_sql(utc) == dt_to_sql(same_moment_elsewhere)


def test_text_order_matches_chronological_order(tmp_path: Path) -> None:
    """Сортировка по текстовой колонке совпадает с порядком моментов времени."""
    store = SqliteRecentEventStore(tmp_path / "events.db")
    try:
        moments = [
            datetime(2026, 8, 17, 6, 0, tzinfo=timezone(timedelta(hours=-7))),  # 13:00 UTC
            datetime(2026, 8, 17, 9, 0, tzinfo=UTC),
            datetime(2026, 8, 17, 20, 0, tzinfo=timezone(timedelta(hours=3))),  # 17:00 UTC
        ]
        for index, moment in enumerate(moments):
            event = raw_row_to_normalized(
                {"timestamp": moment.isoformat(), "operation": "ALLOWED", "asset_id": "ws-1"},
                source=EventSource.NETWORK,
                event_id=f"e-{index}",
            )
            store.add_recent_event(event, max_events=64)

        found, total = store.search_events(host_id="ws-1", limit=10)
        assert total == 3
        # search_events отдаёт от новых к старым: 17:00, 13:00, 09:00 UTC.
        assert [event.event_id for event in found] == ["e-2", "e-0", "e-1"]
        assert [event.observed_at for event in found] == sorted(
            (event.observed_at for event in found), reverse=True
        )
    finally:
        store.close()


def test_naive_datetime_is_left_as_is() -> None:
    """Наивное время не получает выдуманную зону — поведение не меняется."""
    naive = datetime(2026, 8, 17, 6, 0)
    assert dt_to_sql(naive) == "2026-08-17T06:00:00"
