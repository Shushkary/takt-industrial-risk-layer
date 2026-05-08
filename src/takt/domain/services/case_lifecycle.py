from __future__ import annotations

from takt.domain.entities.case import Case, CaseStatus

_ALLOWED: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.NEW: frozenset(
        {
            CaseStatus.TRIAGE,
            CaseStatus.CONFIRMED,
            CaseStatus.FALSE_POSITIVE,
            CaseStatus.EXPECTED_BEHAVIOR,
        }
    ),
    CaseStatus.TRIAGE: frozenset(
        {
            CaseStatus.CONFIRMED,
            CaseStatus.FALSE_POSITIVE,
            CaseStatus.EXPECTED_BEHAVIOR,
        }
    ),
    CaseStatus.CONFIRMED: frozenset(),
    CaseStatus.FALSE_POSITIVE: frozenset(),
    CaseStatus.EXPECTED_BEHAVIOR: frozenset(
        {CaseStatus.TRIAGE}
    ),  # повторная проверка
}


def can_transition(current: CaseStatus, target: CaseStatus) -> bool:
    return target in _ALLOWED.get(current, frozenset())


def transition_case(case: Case, target: CaseStatus) -> Case:
    if not can_transition(case.status, target):
        raise ValueError(f"invalid transition {case.status!s} -> {target!s}")
    case.status = target
    return case
