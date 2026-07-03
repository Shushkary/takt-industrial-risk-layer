from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from takt.application.use_cases.assess_risk import AssessRiskUseCase, AssessmentResult
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.engines.risk_engine import worst_risk_class
from takt.domain.entities.case import Case, InvariantHitRecord, Observation
from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.ports.case_repository import CaseRepositoryPort
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
        existing = self._repo.find_open_by_fingerprint(fp)
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
            n = len(existing.normalized_event_ids)
            base_title = new_case.title
            if "] " in existing.title:
                base_title = existing.title.split("] ", 1)[-1]
            existing.title = f"[x{n}] {base_title}"
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
            existing.append_audit(f"merged burst fingerprint {fp}", clock)
            if persist:
                self._repo.save(existing)
            return ProcessOutcome(case=existing, assessment=assessment, merged_into_existing=True)

        if persist:
            self._repo.save(new_case)
        return ProcessOutcome(case=new_case, assessment=assessment, merged_into_existing=False)
