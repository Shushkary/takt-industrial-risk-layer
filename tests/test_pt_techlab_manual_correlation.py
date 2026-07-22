from __future__ import annotations

from datetime import UTC, datetime

from takt.application.use_cases.manual_correlation import ManualCorrelationCommand, ManualCorrelationUseCase
from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation
from takt.infrastructure.stores.memory import InMemoryCaseStore
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

NOW = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)


def _case(case_id: str, *events: str) -> Case:
    records = [InvariantHitRecord("inv", event_id, NOW, 0.6, 1.0, False, []) for event_id in events]
    return Case(
        case_id=case_id, status=CaseStatus.NEW, title=case_id, risk_class="MEDIUM",
        risk_score=0.6, created_at=NOW, normalized_event_ids=list(events),
        burst_fingerprint=f"fp-{case_id}", invariant_hits=["inv"], invariant_hit_records=records,
        observations=[Observation(source="edr", ingest_trust=1.0, event_ids=list(events))],
    )


def test_attach_and_detach_are_audited_and_idempotent() -> None:
    repo = InMemoryCaseStore()
    repo.save(_case("c1", "e1"))
    use_case = ManualCorrelationUseCase(repo)
    attach = ManualCorrelationCommand("c1", "analyst link", "alice", "req-1", event_id="e2")
    detached = ManualCorrelationCommand("c1", "false positive", "alice", "req-2", event_id="e1")

    assert use_case.attach(attach, clock=NOW).normalized_event_ids == ["e1", "e2"]
    assert use_case.attach(attach, clock=NOW).normalized_event_ids == ["e1", "e2"]
    result = use_case.detach(detached, clock=NOW)
    assert result.normalized_event_ids == ["e2"]
    assert result.risk_score == 0.0
    assert result.correlation_evidence[-1].manual is True
    assert "false positive" in result.audit_log[-1]


def test_merge_and_split_are_idempotent_by_request_id() -> None:
    repo = InMemoryCaseStore()
    repo.save(_case("c1", "e1"))
    repo.save(_case("c2", "e2", "e3"))
    use_case = ManualCorrelationUseCase(repo)
    merged_cmd = ManualCorrelationCommand("c1", "same incident", "alice", "merge-1", source_case_id="c2")

    merged = use_case.merge(merged_cmd, clock=NOW)
    repeated = use_case.merge(merged_cmd, clock=NOW)
    assert merged.normalized_event_ids == ["e1", "e2", "e3"]
    assert repeated.normalized_event_ids == merged.normalized_event_ids

    split_cmd = ManualCorrelationCommand("c1", "separate activity", "alice", "split-1", event_ids=("e3",))
    new_case = use_case.split(split_cmd, clock=NOW)
    assert new_case.normalized_event_ids == ["e3"]
    assert repo.get("c1").normalized_event_ids == ["e1", "e2"]  # type: ignore[union-attr]


def test_sqlite_manual_action_is_in_hash_chain_audit(tmp_path) -> None:
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        repo.save(_case("c1", "e1"))
        result = ManualCorrelationUseCase(repo).detach(
            ManualCorrelationCommand("c1", "confirmed noise", "alice", "detach-1", event_id="e1"),
            clock=NOW,
        )
        assert result.normalized_event_ids == []
        assert repo.verify_audit_ledger("c1")["ok"] is True
        assert repo.verify_operation_ledger()["ok"] is True
    finally:
        repo.close()
