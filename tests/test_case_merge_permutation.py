"""Коммутативность слияния группы кейсов (Спринт 2, property-стиль на конечном множестве перестановок)."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import permutations

from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation
from takt.domain.services.case_merge import merge_open_cases_group_v070


def _mk(cid: str, *, score: float, eid: str, inv: str) -> Case:
    t0 = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    return Case(
        case_id=cid,
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=score,
        created_at=t0,
        normalized_event_ids=[eid],
        burst_fingerprint=f"legacy|{cid}",
        primary_asset_id="plc-x",
        trigger_operation="READ",
        invariant_hits=[inv],
        invariant_hit_records=[
            InvariantHitRecord(
                invariant_id=inv,
                event_ref=eid,
                ts=t0,
                score_contribution=score,
                dq_score=1.0,
                dq_partial=False,
                dq_reasons=[],
            )
        ],
        observations=[Observation(source=f"src-{cid}", ingest_trust=1.0, event_ids=[eid])],
        last_event_source=f"src-{cid}",
    )


def _norm(c: Case) -> dict:
    return {
        "risk_score": c.risk_score,
        "risk_class": c.risk_class,
        "hits": sorted(c.invariant_hits),
        "eids": list(c.normalized_event_ids),
        "fp": c.burst_fingerprint,
        "rec_keys": sorted({(r.invariant_id, r.event_ref) for r in c.invariant_hit_records}),
        "obs_srcs": sorted({o.source for o in c.observations}),
    }


def test_merge_open_cases_group_commutes_over_permutations() -> None:
    group = [
        _mk("a", score=0.1, eid="e1", inv="h1"),
        _mk("b", score=0.3, eid="e2", inv="h2"),
        _mk("c", score=0.2, eid="e3", inv="h1"),
    ]
    first, dead0 = merge_open_cases_group_v070(group, bucket_sec=300)
    ref = _norm(first)
    assert sorted(dead0) == ["b", "c"]
    assert first.case_id == "a"

    for perm in permutations(group):
        merged, dead = merge_open_cases_group_v070(list(perm), bucket_sec=300)
        assert sorted(dead) == ["b", "c"]
        assert merged.case_id == "a"
        assert _norm(merged) == ref
