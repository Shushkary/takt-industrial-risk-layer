from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from takt.domain.entities.case import (
    Case,
    CaseArtifact,
    CaseDecisionRecord,
    CaseStatus,
    CorrelationEvidence,
    Finding,
    FormalVerdictRecord,
    InvariantHitRecord,
    ManualPermit,
    Observation,
    RemediationAttempt,
)
from takt.domain.invariants.catalog import invariant_titles_by_id
from takt.domain.services.decision_brief import decision_brief
from takt.domain.services.forensic_verdict import case_forensic_verdict
from takt.domain.services.verdict_confidence import MissingContextItem, verdict_confidence
from takt.interface_adapters.api.schemas.cases import (
    BriefDecisionDetail,
    BriefMeasureDetail,
    CaseArtifactDetail,
    CaseDecisionRecordDetail,
    CaseDetail,
    CaseForensicVerdictDetail,
    ConfidenceComponentDetail,
    ContextMatchDetail,
    CorrelationEvidenceDetail,
    DecisionBriefDetail,
    EvidenceSummaryDetail,
    FindingDetail,
    FormalVerdictRecordDetail,
    InvariantHitDetail,
    InvariantHitRecordDetail,
    ManualPermitDetail,
    MissingContextItemDetail,
    ObservationDetail,
    RemediationAttemptDetail,
    VerdictConfidenceDetail,
)


def parse_import_created_at(raw: str) -> datetime:
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def invariant_details_for_hits(hits: list[str]) -> list[InvariantHitDetail]:
    titles = invariant_titles_by_id()
    return [InvariantHitDetail(id=h, title_ru=titles.get(h) or h) for h in hits]


def manual_permit_to_detail(p: ManualPermit) -> ManualPermitDetail:
    return ManualPermitDetail(
        permit_id=p.permit_id,
        case_id=p.case_id,
        work_order_number=p.work_order_number,
        actor=p.actor,
        created_at=p.created_at.astimezone(UTC).isoformat(timespec="seconds"),
        asset_id=p.asset_id,
        operation=p.operation,
        action_class=p.action_class,
        verdict=p.verdict,
        confidence=p.confidence,
        rationale=p.rationale,
        counterfactual=p.counterfactual,
        executor=p.executor,
        approver=p.approver,
        valid_from=p.valid_from,
        valid_to=p.valid_to,
        document_status=p.document_status,
        restrictions=p.restrictions,
        organizational_context_sha256=p.organizational_context_sha256,
        note=p.note,
    )


def decision_record_to_detail(r: CaseDecisionRecord) -> CaseDecisionRecordDetail:
    return CaseDecisionRecordDetail(
        ts=r.ts.astimezone(UTC).isoformat(timespec="seconds"),
        actor=r.actor,
        prev_status=r.prev_status,
        next_status=r.next_status,
        reason=r.reason,
        request_id=r.request_id,
    )


def formal_verdict_record_to_detail(r: FormalVerdictRecord) -> FormalVerdictRecordDetail:
    return FormalVerdictRecordDetail(
        ts=r.ts.astimezone(UTC).isoformat(timespec="seconds"),
        actor=r.actor,
        prev=r.prev,
        next=r.next,
        score=r.score,
        source=r.source,
        permit_id=r.permit_id,
        reason=r.reason,
    )


def case_forensic_verdict_to_detail(c: Case) -> CaseForensicVerdictDetail:
    verdict = case_forensic_verdict(c)
    return CaseForensicVerdictDetail(
        value=verdict.value,
        source=verdict.source,
        context_match=ContextMatchDetail(
            matched=verdict.match.matched,
            score=verdict.match.score,
            reasons=list(verdict.match.reasons),
            source=verdict.match.source,
        ),
        counterfactual=verdict.counterfactual,
    )


def verdict_confidence_to_detail(c: Case) -> VerdictConfidenceDetail:
    confidence = verdict_confidence(c)
    return VerdictConfidenceDetail(
        verdict=confidence.verdict,
        score=round(confidence.score, 4),
        grade=confidence.grade,
        components=[
            ConfidenceComponentDetail(
                key=component.key,
                title_ru=component.title_ru,
                value=round(component.value, 4),
                weight=component.weight,
                contribution=round(component.contribution, 4),
                reasons=list(component.reasons),
            )
            for component in confidence.components
        ],
        missing=_missing_to_detail(confidence.missing),
    )


def _missing_to_detail(items: Sequence[MissingContextItem]) -> list[MissingContextItemDetail]:
    return [
        MissingContextItemDetail(
            kind=item.kind,
            text=item.text,
            required_document=item.required_document,
            sanctioning_party=item.sanctioning_party,
            admissible_window=item.admissible_window,
        )
        for item in items
    ]


def decision_brief_to_detail(c: Case) -> DecisionBriefDetail:
    brief = decision_brief(c)
    return DecisionBriefDetail(
        case_id=brief.case_id,
        title=brief.title,
        status=brief.status,
        created_at=brief.created_at.astimezone(UTC).isoformat(timespec="seconds"),
        risk_class=brief.risk_class,
        risk_score=brief.risk_score,
        verdict=brief.verdict,
        verdict_value=brief.verdict_value,
        confidence_score=round(brief.confidence_score, 4),
        confidence_grade=brief.confidence_grade,
        invariants=list(brief.invariants),
        explanation=brief.explanation,
        evidence=EvidenceSummaryDetail(
            raw_evidence_count=brief.evidence.raw_evidence_count,
            organizational_documents=brief.evidence.organizational_documents,
            audit_entries=brief.evidence.audit_entries,
            forensic_bundle_exported=brief.evidence.forensic_bundle_exported,
        ),
        missing=_missing_to_detail(brief.missing),
        measures=[
            BriefMeasureDetail(
                kind=measure.kind,
                status=measure.status,
                action=measure.action,
                result=measure.result,
                actor=measure.actor,
            )
            for measure in brief.measures
        ],
        last_decision=(
            BriefDecisionDetail(
                ts=brief.last_decision.ts.astimezone(UTC).isoformat(timespec="seconds"),
                actor=brief.last_decision.actor,
                prev_status=brief.last_decision.prev_status,
                next_status=brief.last_decision.next_status,
                reason=brief.last_decision.reason,
            )
            if brief.last_decision is not None
            else None
        ),
        boundary_note=brief.boundary_note,
    )


def remediation_attempt_to_detail(a: RemediationAttempt) -> RemediationAttemptDetail:
    return RemediationAttemptDetail(
        attempt_id=a.attempt_id,
        case_id=a.case_id,
        kind=a.kind,
        status=a.status,
        actor=a.actor,
        created_at=a.created_at.astimezone(UTC).isoformat(timespec="seconds"),
        action=a.action,
        result=a.result,
        readiness_before=a.readiness_before,
        readiness_after=a.readiness_after,
        note=a.note,
        request_id=a.request_id,
    )


def domain_case_from_detail(d: CaseDetail) -> Case:
    try:
        status = CaseStatus(d.status.strip().upper())
    except ValueError as e:
        raise ValueError(f"case {d.case_id}: invalid status {d.status!r}") from e
    obs_dom = [
        Observation(source=o.source, ingest_trust=o.ingest_trust, event_ids=list(o.event_ids))
        for o in d.observations
    ]
    rec_dom = [
        InvariantHitRecord(
            invariant_id=r.invariant_id,
            event_ref=r.event_ref,
            ts=parse_import_created_at(r.ts),
            score_contribution=r.score_contribution,
            dq_score=r.dq_score,
            dq_partial=r.dq_partial,
            dq_reasons=list(r.dq_reasons),
        )
        for r in d.invariant_hit_records
    ]
    permit_dom = [
        ManualPermit(
            permit_id=p.permit_id,
            case_id=p.case_id,
            work_order_number=p.work_order_number,
            actor=p.actor,
            created_at=parse_import_created_at(p.created_at),
            asset_id=p.asset_id,
            operation=p.operation,
            action_class=p.action_class,
            verdict=p.verdict,
            confidence=p.confidence,
            rationale=p.rationale,
            counterfactual=p.counterfactual,
            executor=p.executor,
            approver=p.approver,
            valid_from=p.valid_from,
            valid_to=p.valid_to,
            document_status=p.document_status,
            restrictions=p.restrictions,
            organizational_context_sha256=p.organizational_context_sha256,
            note=p.note,
        )
        for p in d.manual_permits
    ]
    remediation_dom = [
        RemediationAttempt(
            attempt_id=a.attempt_id,
            case_id=a.case_id,
            kind=a.kind,
            status=a.status,
            actor=a.actor,
            created_at=parse_import_created_at(a.created_at),
            action=a.action,
            result=a.result,
            readiness_before=a.readiness_before,
            readiness_after=a.readiness_after,
            note=a.note,
            request_id=a.request_id,
        )
        for a in d.remediation_attempts
    ]
    decision_dom = [
        CaseDecisionRecord(
            ts=parse_import_created_at(r.ts),
            actor=r.actor,
            prev_status=r.prev_status,
            next_status=r.next_status,
            reason=r.reason,
            request_id=r.request_id,
        )
        for r in d.decision_records
    ]
    formal_verdict_dom = [
        FormalVerdictRecord(
            ts=parse_import_created_at(r.ts),
            actor=r.actor,
            prev=r.prev,
            next=r.next,
            score=r.score,
            source=r.source,
            permit_id=r.permit_id,
            reason=r.reason,
        )
        for r in d.formal_verdict_records
    ]
    return Case(
        case_id=d.case_id,
        status=status,
        title=d.title,
        risk_class=d.risk_class,
        risk_score=d.risk_score,
        created_at=parse_import_created_at(d.created_at),
        normalized_event_ids=list(d.event_ids),
        xai_summary=d.xai_summary,
        audit_log=list(d.audit_log),
        burst_fingerprint=d.fingerprint,
        correlation_fingerprints=list(d.correlation_fingerprints),
        correlation_evidence=[
            CorrelationEvidence(
                event_id=item.event_id, fingerprint=item.fingerprint, rule=item.rule,
                fields=list(item.fields), manual=item.manual, reason=item.reason,
                request_id=item.request_id,
            )
            for item in d.correlation_evidence
        ],
        related_cases=list(d.related_cases),
        artifacts=[
            CaseArtifact(
                type=item.type, value=item.value, host_id=item.host_id,
                verification_status=item.verification_status, source=item.source,
                added_by=item.added_by,
                created_at=parse_import_created_at(item.created_at) if item.created_at else None,
            ) for item in d.artifacts
        ],
        findings=[
            Finding(
                finding_id=item.finding_id, text=item.text, author=item.author,
                created_at=parse_import_created_at(item.created_at), event_ids=list(item.event_ids),
                artifacts=[
                    CaseArtifact(
                        type=artifact.type, value=artifact.value, host_id=artifact.host_id,
                        verification_status=artifact.verification_status, source=artifact.source,
                        added_by=artifact.added_by,
                        created_at=parse_import_created_at(artifact.created_at) if artifact.created_at else None,
                    ) for artifact in item.artifacts
                ],
            ) for item in d.findings
        ],
        primary_asset_id=d.primary_asset_id,
        trigger_operation=d.trigger_operation,
        operator_id=d.operator_id,
        invariant_hits=list(d.invariant_hits),
        observations=obs_dom,
        manual_permits=permit_dom,
        formal_verdict_records=formal_verdict_dom,
        decision_records=decision_dom,
        remediation_attempts=remediation_dom,
        invariant_hit_records=rec_dom,
        dq_score=d.dq_score,
        dq_partial=d.dq_partial,
        dq_reasons=list(d.dq_reasons),
        last_event_source=d.last_event_source,
        pdf_last_sha256=d.pdf_last_sha256,
        pdf_last_generated_at=d.pdf_last_generated_at,
    )


def case_to_detail(c: Case) -> CaseDetail:
    hits = list(c.invariant_hits)
    obs_out = [
        ObservationDetail(source=o.source, ingest_trust=o.ingest_trust, event_ids=list(o.event_ids))
        for o in c.observations
    ]
    rec_out = [
        InvariantHitRecordDetail(
            invariant_id=r.invariant_id,
            event_ref=r.event_ref,
            ts=r.ts.astimezone(UTC).isoformat(timespec="seconds"),
            score_contribution=r.score_contribution,
            dq_score=r.dq_score,
            dq_partial=r.dq_partial,
            dq_reasons=list(r.dq_reasons),
        )
        for r in c.invariant_hit_records
    ]
    return CaseDetail(
        case_id=c.case_id,
        status=c.status.value,
        title=c.title,
        risk_class=c.risk_class,
        risk_score=c.risk_score,
        event_ids=list(c.normalized_event_ids),
        invariant_hits=hits,
        invariant_details=invariant_details_for_hits(hits),
        observations=obs_out,
        correlation_fingerprints=list(c.correlation_fingerprints),
        correlation_evidence=[
            CorrelationEvidenceDetail(
                event_id=item.event_id, fingerprint=item.fingerprint, rule=item.rule,
                fields=list(item.fields), manual=item.manual, reason=item.reason,
                request_id=item.request_id,
            )
            for item in c.correlation_evidence
        ],
        related_cases=list(c.related_cases),
        artifacts=[
            CaseArtifactDetail(
                type=item.type, value=item.value, host_id=item.host_id,
                verification_status=item.verification_status, source=item.source,
                added_by=item.added_by, created_at=item.created_at.isoformat() if item.created_at else None,
            ) for item in c.artifacts
        ],
        findings=[
            FindingDetail(
                finding_id=item.finding_id, text=item.text, author=item.author,
                created_at=item.created_at.isoformat(), event_ids=list(item.event_ids),
                artifacts=[
                    CaseArtifactDetail(
                        type=artifact.type, value=artifact.value, host_id=artifact.host_id,
                        verification_status=artifact.verification_status, source=artifact.source,
                        added_by=artifact.added_by,
                        created_at=artifact.created_at.isoformat() if artifact.created_at else None,
                    ) for artifact in item.artifacts
                ],
            ) for item in c.findings
        ],
        manual_permits=[manual_permit_to_detail(p) for p in c.manual_permits],
        formal_verdict=case_forensic_verdict_to_detail(c),
        verdict_confidence=verdict_confidence_to_detail(c),
        formal_verdict_records=[formal_verdict_record_to_detail(r) for r in c.formal_verdict_records],
        decision_records=[decision_record_to_detail(r) for r in c.decision_records],
        remediation_attempts=[remediation_attempt_to_detail(a) for a in c.remediation_attempts],
        invariant_hit_records=rec_out,
        xai_summary=c.xai_summary,
        audit_log=list(c.audit_log),
        fingerprint=c.burst_fingerprint,
        primary_asset_id=c.primary_asset_id,
        trigger_operation=c.trigger_operation,
        operator_id=c.operator_id,
        last_event_source=c.last_event_source,
        created_at=c.created_at.astimezone(UTC).isoformat(timespec="seconds"),
        dq_score=c.dq_score,
        dq_partial=c.dq_partial,
        dq_reasons=list(c.dq_reasons),
        pdf_last_sha256=c.pdf_last_sha256,
        pdf_last_generated_at=c.pdf_last_generated_at,
    )
