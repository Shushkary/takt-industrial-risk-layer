"""Разметка аналитика, сведённая по инвариантам: что предложить человеку изменить.

Разрыв G-2 из ``docs/customer_value_map.md``, безрисковый вариант. Заказчик размечает дела
статусами, продукт показывает, какие правила дают ложные срабатывания, и **предлагает**
изменение. Применяет его человек, правя ``config/invariants/*.yaml`` или
``config/risk_weights.yaml``.

Почему не автоматически. Автоматический пересчёт сделал бы вердикт зависящим от накопленной
истории: повторный прогон того же дела на той же версии кода дал бы другой результат, и
доказательный пакет перестал бы быть воспроизводимым (``docs/product_boundary.md``, раздел
«Детерминизм вердикта»). Заказчик просил не автоматизма, а чтобы система перестала повторять
ложные срабатывания — для этого достаточно свести разметку и назвать правило по имени.

Три статуса разметки различаются по смыслу и правятся по-разному:

- ``CONFIRMED`` — инцидент подтверждён, правило сработало верно;
- ``FALSE_POSITIVE`` — ложное срабатывание, дефект правила;
- ``EXPECTED_BEHAVIOR`` — штатное действие: правило сработало верно, но не хватило
  организационного контекста. Это повод добирать контекст, а не ослаблять предикат.

Слив последних двух в одну кучу привёл бы к ослаблению работающего правила, поэтому они
считаются раздельно.

Модуль чистый: читает дела, ничего не меняет, ввода-вывода нет.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from takt.domain.entities.case import Case, CaseStatus

PROPOSAL_KEEP = "оставить без изменений"
PROPOSAL_REVIEW_RULE = "пересмотреть правило"
PROPOSAL_COLLECT_CONTEXT = "добирать организационный контекст"
PROPOSAL_INSUFFICIENT_DATA = "недостаточно разметки"

MIN_SAMPLE_FOR_PROPOSAL = 5
"""Ниже этого числа размеченных дел предложение не выдаётся.

Два дела — не основание менять правило. Порог объявлен явно и попадает в отчёт, чтобы
предложение можно было оспорить, не заглядывая в код.
"""

LOW_PRECISION_THRESHOLD = 0.5
"""Доля подтверждений, ниже которой правило выносится на пересмотр."""

HIGH_EXPECTED_SHARE = 0.5
"""Доля «штатного действия», выше которой проблема не в правиле, а в нехватке контекста."""

# Разметкой считаются только терминальные статусы: аналитик сказал, чем дело оказалось.
_MARKUP_STATUSES = frozenset(
    {CaseStatus.CONFIRMED, CaseStatus.FALSE_POSITIVE, CaseStatus.EXPECTED_BEHAVIOR}
)


@dataclass(frozen=True, slots=True)
class InvariantFeedbackRow:
    """Сводка разметки по одному инварианту и предложение по нему."""

    invariant_id: str
    confirmed: int
    false_positive: int
    expected_behavior: int
    precision: float
    proposal: str
    comment: str
    applied: bool = False

    @property
    def marked_cases(self) -> int:
        return self.confirmed + self.false_positive + self.expected_behavior

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "expected_behavior": self.expected_behavior,
            "marked_cases": self.marked_cases,
            "precision": round(self.precision, 4),
            "proposal": self.proposal,
            "comment": self.comment,
            "applied": self.applied,
        }


@dataclass(frozen=True, slots=True)
class InvariantFeedbackReport:
    """Отчёт целиком. ``applied_changes`` всегда ноль — продукт ничего не применяет сам."""

    rows: tuple[InvariantFeedbackRow, ...]
    reviewed_cases: int
    weights_version: str = ""
    min_sample_for_proposal: int = MIN_SAMPLE_FOR_PROPOSAL

    @property
    def applied_changes(self) -> int:
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows": [row.to_dict() for row in self.rows],
            "reviewed_cases": self.reviewed_cases,
            "weights_version": self.weights_version,
            "min_sample_for_proposal": self.min_sample_for_proposal,
            "applied_changes": self.applied_changes,
            "note": (
                "Предложения не применяются автоматически: изменение весов или предиката"
                " выполняет человек правкой конфигурации. Автоматический пересчёт сделал бы"
                " вердикт невоспроизводимым."
            ),
        }


def invariant_feedback(cases: Iterable[Case], *, weights_version: str = "") -> InvariantFeedbackReport:
    """Свести разметку закрытых дел по инвариантам."""
    confirmed: Counter[str] = Counter()
    false_positive: Counter[str] = Counter()
    expected: Counter[str] = Counter()
    reviewed = 0

    for case in cases:
        if case.status not in _MARKUP_STATUSES:
            continue
        reviewed += 1
        bucket = {
            CaseStatus.CONFIRMED: confirmed,
            CaseStatus.FALSE_POSITIVE: false_positive,
            CaseStatus.EXPECTED_BEHAVIOR: expected,
        }[case.status]
        # Одно дело считается по инварианту один раз, даже если он сработал на нескольких
        # событиях: иначе шумное правило набирало бы вес самим фактом шумности.
        for invariant_id in sorted(set(case.invariant_hits)):
            bucket[invariant_id] += 1

    invariant_ids = sorted(set(confirmed) | set(false_positive) | set(expected))
    rows = tuple(
        _row(
            invariant_id,
            confirmed=confirmed[invariant_id],
            false_positive=false_positive[invariant_id],
            expected_behavior=expected[invariant_id],
        )
        for invariant_id in invariant_ids
    )
    return InvariantFeedbackReport(rows=rows, reviewed_cases=reviewed, weights_version=weights_version)


def _row(
    invariant_id: str,
    *,
    confirmed: int,
    false_positive: int,
    expected_behavior: int,
) -> InvariantFeedbackRow:
    total = confirmed + false_positive + expected_behavior
    precision = confirmed / total if total else 0.0
    proposal, comment = _proposal(
        total=total,
        precision=precision,
        expected_share=(expected_behavior / total if total else 0.0),
    )
    return InvariantFeedbackRow(
        invariant_id=invariant_id,
        confirmed=confirmed,
        false_positive=false_positive,
        expected_behavior=expected_behavior,
        precision=precision,
        proposal=proposal,
        comment=comment,
    )


def _proposal(*, total: int, precision: float, expected_share: float) -> tuple[str, str]:
    if total < MIN_SAMPLE_FOR_PROPOSAL:
        return (
            PROPOSAL_INSUFFICIENT_DATA,
            f"размечено дел: {total}, порог для предложения — {MIN_SAMPLE_FOR_PROPOSAL}.",
        )
    if expected_share > HIGH_EXPECTED_SHARE:
        return (
            PROPOSAL_COLLECT_CONTEXT,
            "большинство срабатываний оказалось штатным действием: правило работает,"
            " не хватает организационного контекста — наряда, заявки или окна работ.",
        )
    if precision < LOW_PRECISION_THRESHOLD:
        return (
            PROPOSAL_REVIEW_RULE,
            f"подтверждается {precision:.0%} срабатываний: предикат или его параметры"
            " стоит пересмотреть в config/invariants.",
        )
    return (
        PROPOSAL_KEEP,
        f"подтверждается {precision:.0%} срабатываний — изменение не требуется.",
    )
