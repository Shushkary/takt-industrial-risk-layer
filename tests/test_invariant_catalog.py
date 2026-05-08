from __future__ import annotations

from takt.domain.invariants.catalog import (
    INVARIANT_RECORDS,
    InvariantId,
    InvariantRecord,
    all_invariant_records,
    invariant_titles_by_id,
)


def test_invariant_records_cover_each_enum_member():
    enum_values = {m.value for m in InvariantId}
    record_ids = {r.id for r in INVARIANT_RECORDS}
    assert enum_values == record_ids


def test_no_duplicate_invariant_record_ids():
    ids = [r.id for r in INVARIANT_RECORDS]
    assert len(ids) == len(set(ids))


def test_all_invariant_records_is_tuple_of_records():
    rows = all_invariant_records()
    assert isinstance(rows, tuple)
    assert len(rows) == len(InvariantId)
    assert all(isinstance(r, InvariantRecord) for r in rows)


def test_invariant_titles_by_id_maps_all_ids():
    titles = invariant_titles_by_id()
    assert len(titles) == len(INVARIANT_RECORDS)
    for r in INVARIANT_RECORDS:
        assert titles[r.id] == r.title_ru


def test_enum_and_records_same_count():
    assert len(INVARIANT_RECORDS) == len(InvariantId)
