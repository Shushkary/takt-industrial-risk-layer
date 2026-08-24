from __future__ import annotations

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.vocabulary import case_status_ru

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


def allowed_transitions(current: CaseStatus) -> tuple[CaseStatus, ...]:
    """Статусы, доступные из текущего; пустой кортеж — конечный статус.

    Отдаётся наружу (в карточке дела), чтобы интерфейс предлагал только то, что пройдёт:
    иначе аналитик узнаёт о тупике, только нажав «Сохранить» и получив отказ.
    """
    return tuple(sorted(_ALLOWED.get(current, frozenset()), key=lambda status: status.value))


def transition_case(case: Case, target: CaseStatus) -> Case:
    if not can_transition(case.status, target):
        # Сообщение уходит пользователю в `detail` ответа API, поэтому оно на языке продукта.
        raise ValueError(
            f"недопустимый переход статуса: «{case_status_ru(case.status.value)}» → "
            f"«{case_status_ru(target.value)}»"
        )
    case.status = target
    return case
