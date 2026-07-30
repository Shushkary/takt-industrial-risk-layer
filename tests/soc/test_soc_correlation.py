"""Тесты детерминированной корреляции (DSU + TTL-окно)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.domain.soc.correlation import CorrelationEngine
from takt.domain.soc.normalized_event import NormalizedEvent

_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _ev(ref: str, *, host: str | None = None, user: str | None = None, offset_s: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        source_class="edr",
        host_id=host,
        user_id=user,
        process=None,
        address=None,
        artifact=None,
        ts=_T0 + timedelta(seconds=offset_s),
        raw_ref=ref,
        content_hash="0" * 64,  # хеш не важен для корреляции (связывание по сущностям)
    )


def test_shared_host_creates_edge() -> None:
    eng = CorrelationEngine(ttl_seconds=3600)
    assert eng.ingest(_ev("a", host="H1")) == []
    edges = eng.ingest(_ev("b", host="H1"))
    assert len(edges) == 1
    assert edges[0].shared_entity == "host_id:H1"
    assert sorted([edges[0].event_a_ref, edges[0].event_b_ref]) == ["a", "b"]
    assert eng.component_of("a") == ["a", "b"]


def test_no_edge_without_shared_entity() -> None:
    eng = CorrelationEngine(ttl_seconds=3600)
    eng.ingest(_ev("a", host="H1"))
    assert eng.ingest(_ev("b", host="H2")) == []
    assert eng.groups() == [["a"], ["b"]]


def test_transitive_grouping() -> None:
    eng = CorrelationEngine(ttl_seconds=3600)
    eng.ingest(_ev("a", host="H1"))
    eng.ingest(_ev("b", host="H1", user="U1"))
    eng.ingest(_ev("c", user="U1"))
    # a-b по host, b-c по user → один кластер {a,b,c}.
    assert eng.component_of("a") == ["a", "b", "c"]


def test_determinism_same_sequence_same_result() -> None:
    def run() -> list[list[str]]:
        eng = CorrelationEngine(ttl_seconds=3600)
        for ref, host, user in [("a", "H1", None), ("b", "H1", "U1"), ("c", None, "U1"), ("d", "H9", None)]:
            eng.ingest(_ev(ref, host=host, user=user))
        return eng.groups()

    assert run() == run()


def test_ttl_eviction_by_event_time() -> None:
    eng = CorrelationEngine(ttl_seconds=60)
    eng.ingest(_ev("a", host="H1", offset_s=0))
    # Событие b на 120 с позже: a выпадает из окна TTL=60 c до корреляции.
    edges = eng.ingest(_ev("b", host="H1", offset_s=120))
    assert edges == []
    assert "a" not in eng.active_refs()
    assert eng.component_of("b") == ["b"]


def test_duplicate_ref_is_idempotent() -> None:
    eng = CorrelationEngine(ttl_seconds=3600)
    eng.ingest(_ev("a", host="H1"))
    assert eng.ingest(_ev("a", host="H1")) == []  # тот же ref — не коррелируем повторно
