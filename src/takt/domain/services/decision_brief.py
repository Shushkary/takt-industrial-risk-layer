"""Сводка по делу для лица, принимающего решение.

Этап 6 пути клиента (``docs/customer_value_map.md``, разрыв G-5): решение о реагировании
принимает руководитель, а цену ошибки — остановку процесса или пропущенную атаку — несёт
бизнес. Карточка аналитика для этого не годится: она рассчитана на разбор, а не на решение.

Сводка отвечает ровно на четыре вопроса и ни на один чужой:

1. Что произошло — риск, сработавшие инварианты, объяснение.
2. Насколько выводу можно верить — вердикт триады и обоснованность (``verdict_confidence``).
3. Чем это подтверждено — что реально приложено к делу: сырые доказательства, организационные
   документы с контрольной суммой, факт сборки доказательного пакета, объём аудиторского следа.
4. Чего не хватает — маршрут добора контекста.

Ничего не досочиняет: все значения берутся из состава дела. Меры показываются только
зафиксированные, новых рекомендаций сводка не порождает — иначе руководитель принял бы решение
по тексту, за которым нет ни расчёта, ни ответственного.

Граница продукта печатается в самой сводке: ТАКТ мер не исполняет. Документ уходит человеку,
который вправе распорядиться остановкой, и это должно быть видно там, где он решает, а не
только в документации.

Расчёт детерминирован и без ввода-вывода.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from takt.domain.entities.case import Case
from takt.domain.invariants.catalog import invariant_titles_by_id
from takt.domain.services.forensic_verdict import case_forensic_verdict
from takt.domain.services.verdict_confidence import MissingContextItem, verdict_confidence

ACTIVE_CONTROL_DISCLAIMER = (
    "ТАКТ не выполняет меры реагирования: пакет мер — рекомендации, исполняет их внешняя"
    " система после подтверждения оператора."
)

# Метка сборки доказательного пакета в журнале дела. Ставит `build_forensic_bundle`.
_BUNDLE_AUDIT_MARK = "forensic bundle generated"


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    """Чем подтверждён вывод — по тому, что действительно приложено к делу."""

    raw_evidence_count: int
    organizational_documents: int
    audit_entries: int
    forensic_bundle_exported: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_evidence_count": self.raw_evidence_count,
            "organizational_documents": self.organizational_documents,
            "audit_entries": self.audit_entries,
            "forensic_bundle_exported": self.forensic_bundle_exported,
        }


@dataclass(frozen=True, slots=True)
class BriefDecision:
    """Последнее зафиксированное решение по делу: кто, когда, что и на каком основании."""

    ts: datetime
    actor: str
    prev_status: str
    next_status: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts.isoformat(timespec="seconds"),
            "actor": self.actor,
            "prev_status": self.prev_status,
            "next_status": self.next_status,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class BriefMeasure:
    """Зафиксированная мера реагирования — та, что уже заведена в деле."""

    kind: str
    status: str
    action: str
    result: str
    actor: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "status": self.status,
            "action": self.action,
            "result": self.result,
            "actor": self.actor,
        }


@dataclass(frozen=True, slots=True)
class DecisionBrief:
    """Сводка на один экран и один лист."""

    case_id: str
    title: str
    status: str
    created_at: datetime
    risk_class: str
    risk_score: float
    verdict: str
    verdict_value: str
    confidence_score: float
    confidence_grade: str
    invariants: tuple[str, ...]
    explanation: str
    evidence: EvidenceSummary
    missing: tuple[MissingContextItem, ...]
    measures: tuple[BriefMeasure, ...]
    last_decision: BriefDecision | None
    boundary_note: str = ACTIVE_CONTROL_DISCLAIMER

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "risk_class": self.risk_class,
            "risk_score": round(self.risk_score, 4),
            "verdict": self.verdict,
            "verdict_value": self.verdict_value,
            "confidence_score": round(self.confidence_score, 4),
            "confidence_grade": self.confidence_grade,
            "invariants": list(self.invariants),
            "explanation": self.explanation,
            "evidence": self.evidence.to_dict(),
            "missing": [item.to_dict() for item in self.missing],
            "measures": [measure.to_dict() for measure in self.measures],
            "last_decision": self.last_decision.to_dict() if self.last_decision else None,
            "boundary_note": self.boundary_note,
        }


def decision_brief(case: Case) -> DecisionBrief:
    """Собрать сводку по делу для лица, принимающего решение."""
    confidence = verdict_confidence(case)
    titles = invariant_titles_by_id()
    return DecisionBrief(
        case_id=case.case_id,
        title=case.title,
        status=case.status.value,
        created_at=case.created_at,
        risk_class=case.risk_class,
        risk_score=case.risk_score,
        verdict=confidence.verdict,
        verdict_value=case_forensic_verdict(case).value,
        confidence_score=confidence.score,
        confidence_grade=confidence.grade,
        invariants=tuple(titles.get(hit, hit) for hit in case.invariant_hits),
        explanation=case.xai_summary,
        evidence=_evidence_summary(case),
        missing=confidence.missing,
        measures=tuple(
            BriefMeasure(
                kind=attempt.kind,
                status=attempt.status,
                action=attempt.action,
                result=attempt.result,
                actor=attempt.actor,
            )
            for attempt in case.remediation_attempts
        ),
        last_decision=_last_decision(case),
    )


def _evidence_summary(case: Case) -> EvidenceSummary:
    """Что подтверждено — по факту приложенного, а не по намерению приложить."""
    documents = sum(1 for permit in case.manual_permits if permit.organizational_context_sha256)
    return EvidenceSummary(
        raw_evidence_count=len(case.raw_evidence_refs),
        organizational_documents=documents,
        audit_entries=len(case.audit_log),
        forensic_bundle_exported=any(_BUNDLE_AUDIT_MARK in entry for entry in case.audit_log),
    )


def _last_decision(case: Case) -> BriefDecision | None:
    if not case.decision_records:
        return None
    record = case.decision_records[-1]
    return BriefDecision(
        ts=record.ts,
        actor=record.actor,
        prev_status=record.prev_status,
        next_status=record.next_status,
        reason=record.reason,
    )
