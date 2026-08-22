from __future__ import annotations

from datetime import UTC, datetime

from takt.application.use_cases.manual_correlation import ManualCorrelationCommand, ManualCorrelationUseCase
from takt.domain.entities.case import (
    Case,
    CaseStatus,
    CorrelationEvidence,
    InvariantHitRecord,
    Observation,
)
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


def test_merge_carries_the_reason_each_event_was_selected() -> None:
    """Объединение не должно стирать основание отбора у перенесённых событий.

    Прецедент: merge переносил идентификаторы событий, наблюдения, срабатывания инвариантов и
    отпечатки корреляции, но не `correlation_evidence`. Механизм оставался записанным в
    исходном кейсе, а на вкладке цепочки все события из влитого кейса выглядели как
    «основание не записано» — при том что оно было.
    """
    repo = InMemoryCaseStore()
    source = _case("c2", "e2")
    source.correlation_evidence = [
        CorrelationEvidence(event_id="e2", fingerprint="corr:host_user_5m:9f2c", rule="host_user_5m"),
        CorrelationEvidence(
            event_id="", fingerprint="", rule="manual_split", manual=True,
            reason="раньше отделяли", request_id="old-split",
        ),
    ]
    repo.save(_case("c1", "e1"))
    repo.save(source)

    merged = ManualCorrelationUseCase(repo).merge(
        ManualCorrelationCommand("c1", "same incident", "alice", "merge-1", source_case_id="c2"),
        clock=NOW,
    )

    carried = [item for item in merged.correlation_evidence if item.event_id == "e2"]
    assert len(carried) == 1
    assert carried[0].rule == "host_user_5m"
    assert carried[0].reason.startswith("перенесено при объединении из кейса c2")
    # Запись уровня кейса описывает операцию над исходным кейсом и в чужую историю не едет.
    assert all(item.rule != "manual_split" for item in merged.correlation_evidence)


def test_merge_keeps_the_targets_own_reason_for_a_shared_event() -> None:
    """Событие, бывшее в обоих кейсах, объясняется тем, как оно попало в целевой."""
    repo = InMemoryCaseStore()
    target = _case("c1", "e1", "e2")
    target.correlation_evidence = [
        CorrelationEvidence(event_id="e2", fingerprint="", rule="pivot", reason="совпал user:smirnov")
    ]
    source = _case("c2", "e2")
    source.correlation_evidence = [
        CorrelationEvidence(event_id="e2", fingerprint="", rule="host-expansion", reason="добрано по узлу")
    ]
    repo.save(target)
    repo.save(source)

    merged = ManualCorrelationUseCase(repo).merge(
        ManualCorrelationCommand("c1", "same incident", "alice", "merge-2", source_case_id="c2"),
        clock=NOW,
    )

    for_event = [item for item in merged.correlation_evidence if item.event_id == "e2"]
    assert [item.rule for item in for_event] == ["pivot"]


def test_carried_evidence_does_not_block_later_commands_on_the_target() -> None:
    """Идентификатор запроса — ключ идемпотентности команды к кейсу, а не свойство события.

    Если перенести его вместе с записью, целевой кейс счёл бы применённой команду, которой в
    нём не было, и молча её пропустил.
    """
    repo = InMemoryCaseStore()
    source = _case("c2", "e2")
    source.correlation_evidence = [
        CorrelationEvidence(
            event_id="e2", fingerprint="", rule="manual_attach", manual=True,
            reason="аналитик связал", request_id="req-7",
        )
    ]
    repo.save(_case("c1", "e1"))
    repo.save(source)
    use_case = ManualCorrelationUseCase(repo)

    merged = use_case.merge(
        ManualCorrelationCommand("c1", "same incident", "alice", "merge-3", source_case_id="c2"),
        clock=NOW,
    )
    assert all(item.request_id != "req-7" for item in merged.correlation_evidence)

    attached = use_case.attach(
        ManualCorrelationCommand("c1", "новая связь", "alice", "req-7", event_id="e9"), clock=NOW
    )
    assert "e9" in attached.normalized_event_ids


def test_split_carries_the_reason_into_the_new_case() -> None:
    """Отделённое событие не должно терять основание: кейс новый, а отбор был тот же."""
    repo = InMemoryCaseStore()
    source = _case("c1", "e1", "e2")
    source.correlation_evidence = [
        CorrelationEvidence(event_id="e1", fingerprint="", rule="pivot", reason="совпал user:smirnov"),
        CorrelationEvidence(event_id="e2", fingerprint="", rule="host-expansion", reason="добрано по узлу"),
    ]
    repo.save(source)

    new_case = ManualCorrelationUseCase(repo).split(
        ManualCorrelationCommand("c1", "separate activity", "alice", "split-2", event_ids=("e2",)),
        clock=NOW,
    )

    carried = [item for item in new_case.correlation_evidence if item.event_id == "e2"]
    assert len(carried) == 1
    assert carried[0].rule == "host-expansion"
    assert carried[0].reason.startswith("перенесено при разделении из кейса c1")
    # Чужих событий в новом кейсе нет — их записи туда не едут.
    assert all(item.event_id != "e1" for item in new_case.correlation_evidence)
    assert new_case.correlation_evidence[-1].rule == "manual_split"


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
