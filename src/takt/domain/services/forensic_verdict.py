from __future__ import annotations

from dataclasses import dataclass, field

from takt.domain.entities.case import Case, FormalVerdictRecord, ManualPermit


@dataclass(frozen=True, slots=True)
class ContextMatchResult:
    """Результат сопоставления события с организационным контекстом."""

    matched: bool
    score: float
    reasons: tuple[str, ...] = field(default_factory=tuple)
    source: str = ""


@dataclass(frozen=True, slots=True)
class CaseForensicVerdict:
    """Формальный вердикт ФИПС, отдельный от рабочего статуса дела."""

    value: str
    source: str
    match: ContextMatchResult
    counterfactual: str = ""


def case_forensic_verdict(case: Case) -> CaseForensicVerdict:
    latest_record = case.formal_verdict_records[-1] if case.formal_verdict_records else None
    if latest_record is not None and latest_record.source == "operator_confirmation":
        return _verdict_from_operator_confirmation(latest_record)
    latest_permit = case.manual_permits[-1] if case.manual_permits else None
    if latest_permit is None:
        return CaseForensicVerdict(
            value="неопределённое",
            source="организационный контекст не приложен",
            match=ContextMatchResult(
                matched=False,
                score=0.0,
                reasons=("к делу не приложен ручной наряд или другой организационный документ",),
                source="manual_permits",
            ),
            counterfactual="Действие могло бы быть признано легитимным при наличии действующего наряда с совпадающим активом, операцией, исполнителем, временным окном и утверждающим.",
        )
    return _verdict_from_permit(latest_permit)


def _verdict_from_operator_confirmation(record: FormalVerdictRecord) -> CaseForensicVerdict:
    matched = record.next == "легитимное"
    reason = record.reason.strip() or "формальный вердикт подтвержден оператором"
    return CaseForensicVerdict(
        value=record.next,
        source="ручное подтверждение оператора",
        match=ContextMatchResult(
            matched=matched,
            score=record.score,
            reasons=(reason,),
            source="operator_confirmation",
        ),
        counterfactual="Вердикт изменился бы при новом организационном контексте или при повторном ручном подтверждении с другим основанием.",
    )


def _verdict_from_permit(permit: ManualPermit) -> CaseForensicVerdict:
    if permit.verdict == "legitimate":
        value = "легитимное"
        matched = True
    elif permit.verdict == "illegitimate":
        value = "нелегитимное"
        matched = False
    else:
        value = "неопределённое"
        matched = False
    reasons = tuple(part.strip() for part in permit.rationale.split(";") if part.strip())
    if not reasons:
        reasons = ("результат сопоставления получен из ручного наряда",)
    return CaseForensicVerdict(
        value=value,
        source=f"ручной наряд {permit.work_order_number}",
        match=ContextMatchResult(
            matched=matched,
            score=permit.confidence,
            reasons=reasons,
            source="manual_permits",
        ),
        counterfactual=permit.counterfactual,
    )
