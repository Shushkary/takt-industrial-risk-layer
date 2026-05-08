from __future__ import annotations

from datetime import datetime, timezone

import pytest

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.services.case_lifecycle import can_transition, transition_case


def test_valid_triage():
    ts = datetime.now(timezone.utc)
    c = Case(
        case_id="1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=ts,
    )
    assert can_transition(c.status, CaseStatus.TRIAGE)
    transition_case(c, CaseStatus.TRIAGE)
    assert c.status == CaseStatus.TRIAGE


def test_invalid_transition():
    ts = datetime.now(timezone.utc)
    c = Case(
        case_id="1",
        status=CaseStatus.FALSE_POSITIVE,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=ts,
    )
    with pytest.raises(ValueError):
        transition_case(c, CaseStatus.CONFIRMED)


def test_new_to_expected_behavior_and_reopen_to_triage():
    ts = datetime.now(timezone.utc)
    c = Case(
        case_id="1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=ts,
    )
    transition_case(c, CaseStatus.EXPECTED_BEHAVIOR)
    assert c.status == CaseStatus.EXPECTED_BEHAVIOR
    transition_case(c, CaseStatus.TRIAGE)
    assert c.status == CaseStatus.TRIAGE


def test_terminal_confirmed_rejects_any_transition():
    ts = datetime.now(timezone.utc)
    c = Case(
        case_id="1",
        status=CaseStatus.CONFIRMED,
        title="t",
        risk_class="HIGH",
        risk_score=0.9,
        created_at=ts,
    )
    assert can_transition(c.status, CaseStatus.TRIAGE) is False
    with pytest.raises(ValueError):
        transition_case(c, CaseStatus.TRIAGE)


def test_case_append_audit_line_format():
    ts = datetime(2026, 8, 15, 14, 5, 9, tzinfo=timezone.utc)
    c = Case(
        case_id="a",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=ts,
    )
    c.append_audit("ошибка сегмента", ts)
    assert len(c.audit_log) == 1
    assert c.audit_log[0].startswith("2026-08-15T14:05:09+00:00 | ")

