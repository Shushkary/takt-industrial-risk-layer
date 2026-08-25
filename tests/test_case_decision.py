from __future__ import annotations

from datetime import UTC, datetime

import pytest

from takt.application.use_cases.case_decision import SubmitCaseDecisionUseCase
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.memory import InMemoryCaseStore, InMemoryExpectedBehavior


def test_submit_case_decision_unknown_case():
    uc = SubmitCaseDecisionUseCase(InMemoryCaseStore(), InMemoryExpectedBehavior())
    with pytest.raises(ValueError, match="unknown"):
        uc.execute("nope", CaseStatus.TRIAGE, datetime.now(UTC))


def test_submit_case_decision_expected_behavior_marks_baseline():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    c = Case(
        case_id="c-1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="MEDIUM",
        risk_score=0.55,
        created_at=ts,
        primary_asset_id="PLC-UPPER",
        trigger_operation="read",
        normalized_event_ids=["e1"],
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-1", CaseStatus.EXPECTED_BEHAVIOR, ts)
    refreshed = repo.get("c-1")
    assert refreshed is not None
    assert refreshed.status == CaseStatus.EXPECTED_BEHAVIOR
    assert baseline.is_expected("plc-upper", "READ")
    assert any("baseline updated" in line for line in refreshed.audit_log)


def test_submit_case_decision_expected_behavior_skips_baseline_without_asset():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    c = Case(
        case_id="c-2",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=ts,
        primary_asset_id="",
        trigger_operation="POLL",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-2", CaseStatus.EXPECTED_BEHAVIOR, ts)
    # No baseline entry when primary_asset_id is empty.
    assert not baseline.is_expected("", "POLL")


def test_submit_case_decision_invalid_transition():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    c = Case(
        case_id="c-term",
        status=CaseStatus.CONFIRMED,
        title="t",
        risk_class="HIGH",
        risk_score=0.9,
        created_at=ts,
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    with pytest.raises(ValueError, match="недопустимый переход статуса"):
        uc.execute("c-term", CaseStatus.TRIAGE, ts)


def test_submit_case_decision_confirmed_does_not_mark_baseline():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    c = Case(
        case_id="c-3",
        status=CaseStatus.NEW,
        title="t",
        risk_class="MEDIUM",
        risk_score=0.5,
        created_at=ts,
        primary_asset_id="plc-a",
        trigger_operation="WRITE",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-3", CaseStatus.CONFIRMED, ts)
    assert not baseline.is_expected("plc-a", "WRITE")
    assert repo.get("c-3") is not None
    assert repo.get("c-3").status == CaseStatus.CONFIRMED


def test_submit_case_decision_false_positive_audit_and_no_baseline():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 2, 11, 0, tzinfo=UTC)
    c = Case(
        case_id="c-fp",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=ts,
        primary_asset_id="plc-fp",
        trigger_operation="POLL",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-fp", CaseStatus.FALSE_POSITIVE, ts, actor="analyst-1", reason="duplicate event")
    r = repo.get("c-fp")
    assert r is not None
    assert r.status == CaseStatus.FALSE_POSITIVE
    assert any("status -> false_positive" in line.lower() for line in r.audit_log)
    assert r.decision_records[-1].actor == "analyst-1"
    assert r.decision_records[-1].prev_status == "NEW"
    assert r.decision_records[-1].next_status == "FALSE_POSITIVE"
    assert r.decision_records[-1].reason == "duplicate event"
    assert not baseline.is_expected("plc-fp", "POLL")


def test_submit_case_decision_new_to_triage():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)
    c = Case(
        case_id="c-tr",
        status=CaseStatus.NEW,
        title="t",
        risk_class="MEDIUM",
        risk_score=0.45,
        created_at=ts,
        primary_asset_id="plc-tr",
        trigger_operation="READ",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-tr", CaseStatus.TRIAGE, ts)
    r = repo.get("c-tr")
    assert r is not None
    assert r.status == CaseStatus.TRIAGE
    assert any("status -> triage" in line.lower() for line in r.audit_log)


def test_submit_case_decision_expected_behavior_from_triage_marks_baseline():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    ts = datetime(2026, 6, 3, 8, 0, tzinfo=UTC)
    c = Case(
        case_id="c-tb",
        status=CaseStatus.TRIAGE,
        title="t",
        risk_class="LOW",
        risk_score=0.3,
        created_at=ts,
        primary_asset_id="plc-tb",
        trigger_operation="POLL",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-tb", CaseStatus.EXPECTED_BEHAVIOR, ts)
    r = repo.get("c-tb")
    assert r is not None
    assert r.status == CaseStatus.EXPECTED_BEHAVIOR
    assert baseline.is_expected("plc-tb", "POLL")


def test_submit_case_decision_expected_then_triage_keeps_baseline():
    repo = InMemoryCaseStore()
    baseline = InMemoryExpectedBehavior()
    t1 = datetime(2026, 6, 4, 9, 0, tzinfo=UTC)
    t2 = datetime(2026, 6, 4, 10, 0, tzinfo=UTC)
    c = Case(
        case_id="c-reopen",
        status=CaseStatus.NEW,
        title="t",
        risk_class="MEDIUM",
        risk_score=0.5,
        created_at=t1,
        primary_asset_id="plc-re",
        trigger_operation="READ",
    )
    repo.save(c)
    uc = SubmitCaseDecisionUseCase(repo, baseline)
    uc.execute("c-reopen", CaseStatus.EXPECTED_BEHAVIOR, t1)
    uc.execute("c-reopen", CaseStatus.TRIAGE, t2)
    final = repo.get("c-reopen")
    assert final is not None
    assert final.status == CaseStatus.TRIAGE
    assert baseline.is_expected("plc-re", "READ")
