"""Property-тесты неизменяемой сущности ``NormalizedEvent`` (L1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from takt.domain.soc.normalized_event import (
    ALLOWED_SOURCE_CLASSES,
    NormalizedEvent,
)
from takt.infrastructure.security.sha256_hasher import Sha256HasherAdapter

_HASHER = Sha256HasherAdapter()

_utc_dt = st.datetimes(
    min_value=datetime(2001, 1, 1),
    max_value=datetime(2035, 1, 1),
).map(lambda d: d.replace(tzinfo=UTC))

_opt_str = st.one_of(st.none(), st.text(min_size=1, max_size=20))


def _make(**overrides) -> NormalizedEvent:
    base = dict(
        source_class="edr",
        host_id="HOST-1",
        user_id="u1",
        process="p.exe",
        address="10.0.0.1",
        artifact="a1",
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        raw_ref="ref-1",
    )
    base.update(overrides)
    return NormalizedEvent(hasher=_HASHER, **base)


@settings(max_examples=150)
@given(
    source_class=st.sampled_from(sorted(ALLOWED_SOURCE_CLASSES)),
    ts=_utc_dt,
    raw_ref=st.text(min_size=1, max_size=30).filter(lambda s: s.strip() != ""),
)
def test_content_hash_is_deterministic_and_stable(source_class: str, ts: datetime, raw_ref: str) -> None:
    e1 = _make(source_class=source_class, ts=ts, raw_ref=raw_ref)
    e2 = _make(source_class=source_class, ts=ts, raw_ref=raw_ref)
    assert e1.content_hash == e2.content_hash
    assert len(e1.content_hash) == 64  # sha256 hex


@settings(max_examples=100)
@given(raw_ref_a=st.text(min_size=1, max_size=20).filter(lambda s: s.strip()),
       raw_ref_b=st.text(min_size=1, max_size=20).filter(lambda s: s.strip()))
def test_raw_ref_not_part_of_hash(raw_ref_a: str, raw_ref_b: str) -> None:
    # raw_ref не входит в content_hash → идемпотентность по содержанию.
    e1 = _make(raw_ref=raw_ref_a)
    e2 = _make(raw_ref=raw_ref_b)
    assert e1.content_hash == e2.content_hash


def test_naive_ts_rejected() -> None:
    with pytest.raises(ValueError):
        _make(ts=datetime(2026, 1, 1))  # без tzinfo


def test_non_utc_ts_rejected() -> None:
    with pytest.raises(ValueError):
        _make(ts=datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=3))))


def test_blank_raw_ref_rejected() -> None:
    with pytest.raises(ValueError):
        _make(raw_ref="   ")


def test_invalid_source_class_rejected() -> None:
    with pytest.raises(ValueError):
        _make(source_class="unknown")


def test_frozen_immutability() -> None:
    e = _make()
    with pytest.raises((AttributeError, TypeError)):
        e.source_class = "siem"  # type: ignore[misc]


def test_shared_entities_skips_none() -> None:
    e = _make(user_id=None, process=None, address=None, artifact=None)
    assert e.shared_entities() == {"host_id": "HOST-1"}
