from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from takt.application.use_cases.assess_risk import AssessmentResult, AssessRiskUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.engines.risk_engine import worst_risk_class
from takt.domain.entities.case import Case, CorrelationEvidence, InvariantHitRecord, Observation
from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.services.case_merge import absorb_correlated_case
from takt.domain.services.event_enrichment import apply_enrichment_rules
from takt.domain.services.telemetry_hints import apply_telemetry_hints


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    """Итог обработки: новый или дополненный кейс (Alert Fatigue)."""

    case: Case
    assessment: AssessmentResult
    merged_into_existing: bool


def _ingest_trust_for(event: NormalizedEvent, trust_by_source: Mapping[str, float] | None) -> float:
    t = dict(trust_by_source or {})
    return float(t.get(event.source.value, 1.0))


def _merge_observation(existing: Case, event: NormalizedEvent, trust: float) -> None:
    src = event.source.value
    eid = event.event_id
    for obs in existing.observations:
        if obs.source == src:
            if eid not in obs.event_ids:
                obs.event_ids.append(eid)
            obs.ingest_trust = trust
            return
    existing.observations.append(Observation(source=src, ingest_trust=trust, event_ids=[eid]))


def _append_hit_records(existing: Case, incoming: list[InvariantHitRecord]) -> None:
    if not incoming:
        return
    seen = {(r.invariant_id, r.event_ref) for r in existing.invariant_hit_records}
    for r in incoming:
        key = (r.invariant_id, r.event_ref)
        if key in seen:
            continue
        existing.invariant_hit_records.append(r)
        seen.add(key)


class ProcessEventUseCase:
    def __init__(
        self,
        assess: AssessRiskUseCase,
        repo: CaseRepositoryPort,
        *,
        enrichment: Mapping[str, Any] | None = None,
    ) -> None:
        self._assess = assess
        self._repo = repo
        self._enrichment = enrichment

    @property
    def recent_context_event_count(self) -> int:
        return self._assess.recent_context_event_count

    def execute(
        self,
        event: NormalizedEvent,
        *,
        persist: bool = True,
        recent_events: Sequence[NormalizedEvent],
        tickets: list[ServiceTicket],
        graph_edges: list[GraphEdge],
        polling_intervals_us: Sequence[float],
        clock: datetime,
        trust_by_source: Mapping[str, float] | None = None,
    ) -> ProcessOutcome:
        event = apply_enrichment_rules(event, self._enrichment)
        event = apply_telemetry_hints(event, enrichment_rules=self._enrichment)
        assessment = self._assess.execute(
            event,
            recent_events=recent_events,
            tickets=tickets,
            graph_edges=graph_edges,
            polling_intervals_us=polling_intervals_us,
            clock=clock,
            trust_by_source=trust_by_source,
        )
        new_case = assessment.suggested_case
        fp = new_case.burst_fingerprint
        candidates = new_case.correlation_fingerprints
        # Открытые дела, с которыми событие совпало хоть чем-нибудь: сначала по правилам
        # корреляции в порядке их приоритета, затем по ключу подавления шума. Порядок задаёт
        # старшинство — первое дело выживает, остальные поглощаются им.
        candidate_matches: list[tuple[Case, str]] = []
        seen_case_ids: set[str] = set()
        for candidate in candidates:
            found = self._repo.find_open_by_fingerprints([candidate])
            if found is not None and found[0].case_id not in seen_case_ids:
                candidate_matches.append(found)
                seen_case_ids.add(found[0].case_id)
        match = candidate_matches[0] if candidate_matches else None
        burst_match = self._repo.find_open_by_fingerprint(fp)
        if burst_match is not None and burst_match.case_id not in seen_case_ids:
            candidate_matches.append((burst_match, fp))
            seen_case_ids.add(burst_match.case_id)
        existing = candidate_matches[0][0] if candidate_matches else None
        if existing is not None:
            if not persist:
                existing = deepcopy(existing)
            existing.normalized_event_ids.extend(new_case.normalized_event_ids)
            merged_hits = sorted(frozenset(existing.invariant_hits) | frozenset(assessment.invariant_hits))
            existing.invariant_hits = merged_hits
            t_new = _ingest_trust_for(event, trust_by_source)
            ns, nc = new_case.risk_score, new_case.risk_class
            weighted = ns * t_new
            if weighted > existing.risk_score:
                existing.risk_score = weighted
                existing.risk_class = nc
            elif weighted == existing.risk_score:
                existing.risk_class = worst_risk_class(existing.risk_class, nc)
            base_title = new_case.title
            if "] " in existing.title:
                base_title = existing.title.split("] ", 1)[-1]
            existing.xai_summary = new_case.xai_summary
            existing.trigger_operation = new_case.trigger_operation
            existing.operator_id = new_case.operator_id or existing.operator_id
            existing.last_event_source = new_case.last_event_source
            existing.dq_score = assessment.data_quality.dq_score
            existing.dq_partial = assessment.data_quality.partial_observability
            existing.dq_reasons = list(assessment.data_quality.reasons)
            if not existing.primary_asset_id and new_case.primary_asset_id:
                existing.primary_asset_id = new_case.primary_asset_id
            _merge_observation(existing, event, t_new)
            _append_hit_records(existing, new_case.invariant_hit_records)
            # Ключи события переходят делу независимо от того, каким совпадением оно в него
            # попало. Пока ключи забирались только при совпадении по правилу корреляции,
            # событие, слитое по ключу подавления шума, приносило в дело свои сущности, но не
            # свои ключи: дело содержало событие и при этом не находилось по его узлу.
            existing.correlation_fingerprints = list(
                dict.fromkeys([*existing.correlation_fingerprints, *candidates])
            )
            if match is not None:
                matched_fingerprint = match[1]
                existing.correlation_evidence.append(
                    CorrelationEvidence(
                        event_id=event.event_id,
                        fingerprint=matched_fingerprint,
                        rule=matched_fingerprint.split(":", 2)[1],
                    )
                )
                # Событие совпало сразу с несколькими открытыми делами — значит, дела
                # описывают одну цепочку и связывающее их событие уже принято. Ссылкой
                # `related_cases` этого не выразить: аналитик всё равно получал отдельные
                # дела и собирал цепочку руками.
                for related, related_fingerprint in candidate_matches[1:]:
                    absorb_correlated_case(existing, related, fingerprint=related_fingerprint, clock=clock)
                    if persist:
                        self._repo.save(related)
            existing.title = f"[x{len(existing.normalized_event_ids)}] {base_title}"
            existing.append_audit(f"merged burst fingerprint {fp}", clock)
            if persist:
                self._repo.save(existing)
            return ProcessOutcome(case=existing, assessment=assessment, merged_into_existing=True)

        if persist:
            self._repo.save(new_case)
        return ProcessOutcome(case=new_case, assessment=assessment, merged_into_existing=False)
