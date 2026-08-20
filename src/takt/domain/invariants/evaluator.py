from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Mapping, Sequence

from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.engines.risk_engine import RiskBreakdown
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.rule_predicates import PREDICATE_REGISTRY
from takt.domain.invariants.rule_spec import InvariantRuleSpec, default_extended_rule_specs


@dataclass(frozen=True, slots=True)
class InvariantRuleOverrides:
    """Параметры правил из декларативного каталога (`config/invariants/*.yaml`)."""

    brute_force_auth_fail_threshold: int | None = None


@dataclass(frozen=True, slots=True)
class InvariantContext:
    """Параметры правил (пороги задаются из YAML / конфигурации L4, значения приходят в use case)."""

    allowed_function_codes: frozenset[str] | None = None
    expected_payload_baseline: int | None = None
    payload_drift_ratio: float = 0.45
    auth_fail_window: int = 20
    auth_fail_threshold: int = 5
    protocol_tier: dict[str, int] | None = None
    iec104_disallowed_type_ids: frozenset[int] | None = None
    include_experimental_invariants: bool = False
    # --- Данные для инвариантов, детектируемых внутри предикатов ---
    tickets: tuple[ServiceTicket, ...] = ()
    graph_edges: tuple[GraphEdge, ...] = ()
    jump_host: str = ""
    plc_hosts: frozenset[str] = frozenset()
    polling_intervals_us: tuple[float, ...] = ()
    trust_by_source: Mapping[str, float] | None = None
    now: datetime | None = None
    max_gap_seconds: float = 120.0
    stale_window_seconds: float = 90.0
    max_rate_of_change: float = 100.0
    trusted_admin_ips: frozenset[str] = frozenset()
    # Реестр известных адресов изолированного сегмента. Пустой набор означает,
    # что реестра нет и правило «новый узел в air-gap» неприменимо.
    airgap_known_addresses: frozenset[str] = frozenset()


def invariant_context_from_config(cfg: Mapping[str, Any] | None) -> InvariantContext:
    """Собирает контекст из секции верхнего уровня YAML (весь load_risk_weights)."""
    if not cfg:
        return InvariantContext()
    inv = cfg.get("invariants")
    if not isinstance(inv, dict):
        return InvariantContext()
    allowed = inv.get("allowed_function_codes")
    codes: frozenset[str] | None = None
    if isinstance(allowed, list):
        codes = frozenset(str(x).strip() for x in allowed)
    raw_base = inv.get("expected_payload_baseline")
    baseline = None if raw_base is None else int(raw_base)
    ptr = inv.get("protocol_tiers")
    pt: dict[str, int] | None = None
    if isinstance(ptr, dict):
        pt = {str(k).upper(): int(v) for k, v in ptr.items()}
    return InvariantContext(
        allowed_function_codes=codes,
        expected_payload_baseline=baseline,
        payload_drift_ratio=float(inv.get("payload_drift_ratio", 0.45)),
        auth_fail_window=int(inv.get("auth_fail_window", 20)),
        auth_fail_threshold=int(inv.get("auth_fail_threshold", 5)),
        protocol_tier=pt,
        iec104_disallowed_type_ids=_parse_iec_disallowed(inv.get("iec104_disallowed_type_ids")),
        include_experimental_invariants=bool(inv.get("include_experimental_invariants", False)),
    )


def _parse_iec_disallowed(raw: Any) -> frozenset[int] | None:
    if raw is None or not isinstance(raw, list) or not raw:
        return None
    return frozenset(int(x) for x in raw)


def _event_has_input_path(event: NormalizedEvent, path: str) -> bool:
    path = path.strip()
    if not path:
        return True
    parts = path.split(".", 1)
    if len(parts) == 2 and parts[0] == "payload":
        key = parts[1]
        return key in event.payload and event.payload[key] is not None
    return True


def rule_inputs_satisfied(spec: InvariantRuleSpec, event: NormalizedEvent) -> bool:
    for p in spec.inputs:
        if not _event_has_input_path(event, p):
            return False
    return True


def evaluate_declared_rules(
    event: NormalizedEvent,
    recent: Sequence[NormalizedEvent],
    ctx: InvariantContext | None,
    specs: Sequence[InvariantRuleSpec],
    *,
    rule_overrides: InvariantRuleOverrides | None = None,
) -> list[str]:
    eff_ctx = ctx or InvariantContext()
    if rule_overrides and rule_overrides.brute_force_auth_fail_threshold is not None:
        eff_ctx = replace(eff_ctx, auth_fail_threshold=rule_overrides.brute_force_auth_fail_threshold)
    recent_list = list(recent)
    out: list[str] = []
    for spec in sorted(specs, key=lambda s: s.id):
        if not rule_inputs_satisfied(spec, event):
            continue
        name = spec.predicate_name()
        fn = PREDICATE_REGISTRY[name]
        n = max(1, spec.context_window_events)
        tail = recent_list[-n:] if recent_list else []
        got = fn(event, tail, eff_ctx, spec)
        out.extend(g for g in got if g == spec.id)
    return out


def collect_extended_invariants(
    event: NormalizedEvent,
    recent: Sequence[NormalizedEvent],
    ctx: InvariantContext | None = None,
    *,
    rule_overrides: InvariantRuleOverrides | None = None,
    rule_specs: Sequence[InvariantRuleSpec] | None = None,
) -> list[str]:
    """Правила из каталога (`rule_specs`) или встроенный набор по умолчанию."""
    specs: tuple[InvariantRuleSpec, ...] = (
        tuple(rule_specs)
        if rule_specs is not None
        else default_extended_rule_specs()
    )
    return evaluate_declared_rules(event, recent, ctx, specs, rule_overrides=rule_overrides)


def integrity_boost(invariant_ids: list[str]) -> float:
    """Множитель усиления топологии/целостности при срабатывании блока 5."""
    markers = {
        InvariantId.LOG_WIPING.value,
        InvariantId.RUNTIME_CONFIG_CHANGE.value,
        InvariantId.C2_EXTERNAL_DNS.value,
    }
    return 0.9 if markers & set(invariant_ids) else 0.0


def rhythm_boost(invariant_ids: list[str]) -> float:
    markers = {
        InvariantId.ILLEGAL_FUNCTION_CODE.value,
        InvariantId.PAYLOAD_LENGTH_DRIFT.value,
        InvariantId.POLLING_JITTER.value,
        InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value,
    }
    return 0.55 if markers & set(invariant_ids) else 0.0


def user_boost(invariant_ids: list[str]) -> float:
    markers = {
        InvariantId.BRUTE_FORCE.value,
        InvariantId.PROTOCOL_ESCALATION.value,
        InvariantId.BLIND_COMMAND.value,
        InvariantId.UNTRUSTED_IP_ADMIN.value,
    }
    return 0.75 if markers & set(invariant_ids) else 0.0


def graph_topology_boost(invariant_ids: list[str]) -> float:
    markers = {
        InvariantId.NEW_NODE_AIRGAP.value,
        InvariantId.RECONNAISSANCE.value,
        InvariantId.LATERAL_MOVEMENT.value,
    }
    return 0.7 if markers & set(invariant_ids) else 0.0


def physics_boost(invariant_ids: list[str]) -> float:
    markers = {
        InvariantId.PHYSICAL_INVARIANT_BREACH.value,
        InvariantId.CYCLIC_SERVICE_CRASH.value,
        InvariantId.CONFLICT_LOGIC.value,
    }
    return 0.65 if markers & set(invariant_ids) else 0.0


def hitl_context_boost(invariant_ids: list[str]) -> float:
    """Блок 6 — расхождение с экспертной оценкой / HITL."""
    return 0.6 if InvariantId.EXPERT_DISSONANCE.value in invariant_ids else 0.0


def trust_boost(invariant_ids: list[str]) -> float:
    return 0.55 if InvariantId.TRUST_INDEX_DROP.value in invariant_ids else 0.0


def request_reply_boost(invariant_ids: list[str]) -> float:
    return 0.6 if InvariantId.REQUEST_REPLY_DISSONANCE.value in invariant_ids else 0.0


def risk_vectors_from_invariants(
    invariant_ids: Sequence[str],
    *,
    base_rhythm: float = 0.0,
    base_context: float = 0.0,
    data_quality: float = 0.0,
) -> RiskBreakdown:
    """Векторы Risk = F(R, G, C, U, DQ) по набору сработавших инвариантов.

    Одно место, где срабатывания превращаются в векторы риска. Раньше это правило жило
    внутри оценки одного события; при появлении оценки собранного инцидента копия правила
    неизбежно разошлась бы с оригиналом, а расхождение здесь означает два разных ответа
    на один вопрос «насколько это опасно».

    Базовые значения (`base_rhythm`, `base_context`, `data_quality`) приходят из измерений
    по самому событию или кейсу; срабатывания могут только поднять их, но не опустить.
    """
    ids = list(invariant_ids)
    graph = 0.8 if InvariantId.JUMP_SERVER_BYPASS.value in ids else 0.1
    graph = max(graph, integrity_boost(ids), graph_topology_boost(ids))
    rhythm = max(base_rhythm, rhythm_boost(ids), physics_boost(ids), request_reply_boost(ids))
    context = max(base_context, hitl_context_boost(ids))
    user = 0.7 if InvariantId.OUT_OF_SHIFT_ACCESS.value in ids else 0.1
    user = max(user, user_boost(ids), trust_boost(ids))
    return RiskBreakdown(
        rhythm=rhythm,
        graph=graph,
        context=context,
        user=user,
        data_quality=data_quality,
    )
