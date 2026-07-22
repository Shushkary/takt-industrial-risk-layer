from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from takt.application.system_defaults import default_clock, default_id_provider
from takt.domain.engines.alert_fatigue import (
    compute_burst_fingerprint,
    correlation_fingerprints,
    correlation_rules_from_config,
)
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.engines.chaos_predictor import predict_polling_chaos
from takt.domain.engines.context_matcher import match_event_to_ticket
from takt.domain.engines.data_quality import DataQualitySnapshot, evaluate_full_pipeline
from takt.domain.engines.phase_time_tagger import tag_phase
from takt.domain.engines.risk_engine import RiskBreakdown, combine_risk
from takt.domain.engines.xai import XAIReport, build_xai
from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation
from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import MaintenanceWindow, ServiceTicket
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import (
    InvariantContext,
    InvariantRuleOverrides,
    collect_extended_invariants,
    graph_topology_boost,
    hitl_context_boost,
    integrity_boost,
    physics_boost,
    request_reply_boost,
    rhythm_boost,
    trust_boost,
    user_boost,
)
from takt.domain.invariants.rule_spec import InvariantRuleSpec, default_extended_rule_specs, max_rule_context_window
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    risk_score: float
    risk_class: str
    xai: XAIReport
    suggested_case: Case
    invariant_hits: list[str]
    data_quality: DataQualitySnapshot


class AssessRiskUseCase:
    """Сквозная оценка одного нормализованного события (MVP-конвейер)."""

    def __init__(
        self,
        weights: Mapping[str, Any],
        *,
        jump_host: str = "jump-01",
        plc_hosts: frozenset[str] | None = None,
        expected_behavior: ExpectedBehaviorPort | None = None,
        invariant_profile: InvariantContext | None = None,
        clock: SystemClockPort | None = None,
        ids: IdProviderPort | None = None,
        rule_overrides: InvariantRuleOverrides | None = None,
        experimental_invariant_ids: frozenset[str] = frozenset(),
        rule_specs: tuple[InvariantRuleSpec, ...] | None = None,
    ) -> None:
        self._w = weights
        self._jump = jump_host
        self._plc = plc_hosts or frozenset({"plc-01", "plc-02"})
        self._expected = expected_behavior
        self._inv_profile = invariant_profile or InvariantContext()
        self._clock = default_clock if clock is None else clock
        self._ids = default_id_provider if ids is None else ids
        self._rule_overrides = rule_overrides
        self._experimental_ids = frozenset(experimental_invariant_ids)
        self._rule_specs = rule_specs

    @property
    def recent_context_event_count(self) -> int:
        """Сколько последних событий передавать в оценку (минимум 5, окна из risk_weights и каталога правил)."""
        specs = self._rule_specs if self._rule_specs is not None else default_extended_rule_specs()
        return max(5, int(self._inv_profile.auth_fail_window), max_rule_context_window(specs))

    def _alert_fatigue_options(self) -> tuple[str, int]:
        raw = self._w.get("alert_fatigue")
        if isinstance(raw, dict):
            mode = str(raw.get("mode", "bucketed")).strip().lower() or "bucketed"
            try:
                bucket_sec = int(raw.get("bucket_sec", 300))
            except (TypeError, ValueError):
                bucket_sec = 300
            return mode, bucket_sec
        return "bucketed", 300

    def _correlation_candidates(self, event: NormalizedEvent) -> list[str]:
        raw = self._w.get("correlation")
        if not isinstance(raw, Mapping) or str(raw.get("mode", "legacy")).strip().lower() == "legacy":
            return []
        return correlation_fingerprints(event, correlation_rules_from_config(raw))

    def execute(
        self,
        event: NormalizedEvent,
        *,
        recent_events: Sequence[NormalizedEvent],
        tickets: list[ServiceTicket],
        graph_edges: list[GraphEdge],
        polling_intervals_us: Sequence[float],
        clock: datetime | None = None,
        eps_estimate: float = 1000.0,
        trust_by_source: Mapping[str, float] | None = None,
        invariant_ctx: InvariantContext | None = None,
    ) -> AssessmentResult:
        inv: list[str] = []
        profile = invariant_ctx if invariant_ctx is not None else self._inv_profile
        eff_lab = self._experimental_ids if not profile.include_experimental_invariants else frozenset()
        ts = clock if clock is not None else self._clock.now_utc()

        asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")

        # --- Движки: вычисляем сигналы (инварианты детектируются предикатами) ---
        phase = tag_phase(event.observed_at)

        chaos = predict_polling_chaos(polling_intervals_us)
        rhythm_signal = 0.15
        if chaos:
            if chaos.suggests_period_doubling_cluster:
                rhythm_signal = 0.75
            elif chaos.jitter_trend_increasing:
                rhythm_signal = max(rhythm_signal, 0.42)
                # POLLING_JITTER остаётся с ручным детектированием (флаг-чекер + chaos)
                jid = InvariantId.POLLING_JITTER.value
                if jid not in eff_lab:
                    inv.append(jid)

        ctx = match_event_to_ticket(event, tickets, now=ts)

        trust = dict(trust_by_source or {})
        dq = evaluate_full_pipeline(
            (*recent_events, event),
            max_gap_seconds=120.0,
            stale_window_seconds=90.0,
            source_key=event.source.value,
            trust_by_source=trust,
        )

        # --- Расширенный контекст для предикатов 7 инвариантов ---
        eff_profile = replace(
            profile,
            tickets=tuple(tickets),
            graph_edges=tuple(graph_edges),
            jump_host=self._jump,
            plc_hosts=self._plc,
            polling_intervals_us=tuple(polling_intervals_us),
            trust_by_source=trust,
            now=ts,
            max_gap_seconds=120.0,
            stale_window_seconds=90.0,
        )

        inv.extend(
            collect_extended_invariants(
                event,
                recent_events,
                eff_profile,
                rule_overrides=self._rule_overrides,
                rule_specs=self._rule_specs,
            )
        )
        inv = list(dict.fromkeys(inv))
        if eff_lab:
            inv = [i for i in inv if i not in eff_lab]

        graph_signal = 0.8 if InvariantId.JUMP_SERVER_BYPASS.value in inv else 0.1
        graph_signal = max(graph_signal, integrity_boost(inv), graph_topology_boost(inv))
        rhythm_signal = max(
            rhythm_signal,
            rhythm_boost(inv),
            physics_boost(inv),
            request_reply_boost(inv),
        )
        context_signal = 1.0 - ctx.context_score
        context_signal = max(context_signal, hitl_context_boost(inv))
        user_signal = 0.7 if InvariantId.OUT_OF_SHIFT_ACCESS.value in inv else 0.1
        user_signal = max(user_signal, user_boost(inv), trust_boost(inv))
        dq_signal = 1.0 - dq.dq_score

        if self._expected and asset_id and self._expected.is_expected(asset_id, event.operation):
            user_signal = min(user_signal, 0.08)
            context_signal = min(context_signal, 0.12)

        vectors = RiskBreakdown(
            rhythm=rhythm_signal,
            graph=graph_signal,
            context=context_signal,
            user=user_signal,
            data_quality=dq_signal,
        )
        assessment = combine_risk(
            vectors,
            self._w,
            dq_score=dq.dq_score,
            eps_estimate=eps_estimate,
            mandel_cap=float(self._w.get("mandelbrot_entropy_cap", 2.5)),
            eps_soft_cap=float(self._w.get("eps_soft_cap", 100_000)),
            risk_class_thresholds=self._w.get("risk_class_thresholds"),
        )
        xai = build_xai(
            assessment,
            invariant_hits=inv,
            context_note=f"Фаза: {phase.phase}, окно ТО: {ctx.in_maintenance_window}",
        )
        cid = self._ids.new_case_id_short()
        af_mode, af_bucket = self._alert_fatigue_options()
        fp = compute_burst_fingerprint(event, mode=af_mode, bucket_sec=af_bucket)
        correlation_keys = self._correlation_candidates(event)
        if correlation_keys:
            fp = correlation_keys[0]
        trust_val = float(trust.get(event.source.value, 1.0))
        hit_records = [
            InvariantHitRecord(
                invariant_id=iid,
                event_ref=event.event_id,
                ts=ts,
                score_contribution=assessment.score,
                dq_score=dq.dq_score,
                dq_partial=dq.partial_observability,
                dq_reasons=list(dq.reasons),
            )
            for iid in inv
        ]
        obs = [Observation(source=event.source.value, ingest_trust=trust_val, event_ids=[event.event_id])]
        case = Case(
            case_id=cid,
            status=CaseStatus.NEW,
            title=f"Risk {assessment.risk_class}: {event.operation}",
            risk_class=assessment.risk_class,
            risk_score=assessment.score,
            created_at=ts,
            normalized_event_ids=[event.event_id],
            xai_summary=f"{xai.what} | {xai.why_unusual}",
            burst_fingerprint=fp,
            correlation_fingerprints=correlation_keys,
            primary_asset_id=asset_id,
            trigger_operation=event.operation,
            operator_id=event.operator_id,
            invariant_hits=list(inv),
            invariant_hit_records=hit_records,
            observations=obs,
            dq_score=dq.dq_score,
            dq_partial=dq.partial_observability,
            dq_reasons=list(dq.reasons),
            last_event_source=event.source.value,
        )
        case.append_audit("case created by AssessRiskUseCase", ts)
        return AssessmentResult(
            risk_score=assessment.score,
            risk_class=assessment.risk_class,
            xai=xai,
            suggested_case=case,
            invariant_hits=inv,
            data_quality=dq,
        )


def demo_ticket_for_asset(asset_id: str, *, start: datetime, end: datetime) -> ServiceTicket:
    """Вспомогательная фабрика для тестов и демо."""
    mw = MaintenanceWindow(
        window_id="mw-1",
        title="Плановое ТО",
        starts_at=start,
        ends_at=end,
        asset_ids=frozenset({asset_id}),
    )
    return ServiceTicket(ticket_id="SD-1", title="ТО", maintenance_window=mw)
