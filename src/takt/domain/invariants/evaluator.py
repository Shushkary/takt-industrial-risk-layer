from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

from takt.domain.entities.event import NormalizedEvent
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