from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from takt.domain.entities.event import NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.rule_spec import InvariantRuleSpec

PredicateFn = Callable[
    [NormalizedEvent, list[NormalizedEvent], Any, InvariantRuleSpec],
    list[str],
]


def _tier_map() -> dict[str, int]:
    return {
        "MODBUS": 1,
        "IEC104": 1,
        "DNP3": 2,
        "MQTT": 2,
        "HTTP": 3,
        "HTTPS": 3,
        "SSH": 4,
        "SMB": 5,
        "WINRM": 5,
    }


def _recent_same_asset(recent: Sequence[NormalizedEvent], asset_key: str) -> list[NormalizedEvent]:
    return [e for e in recent if str(e.payload.get("asset_id") or e.payload.get("plc_id") or "") == asset_key]


def pred_noop(
    _event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    _spec: InvariantRuleSpec,
) -> list[str]:
    return []


def pred_illegal_function_code(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    pl = event.payload
    fc = pl.get("function_code")
    if ctx.allowed_function_codes is not None and fc is not None:
        if str(fc).strip() not in ctx.allowed_function_codes:
            return [spec.id]
    if ctx.iec104_disallowed_type_ids:
        tid = pl.get("iec104_type_id")
        if tid is not None:
            try:
                if int(tid) in ctx.iec104_disallowed_type_ids:
                    return [spec.id]
            except (TypeError, ValueError):
                pass
    return []


def pred_payload_length_drift(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    baseline = ctx.expected_payload_baseline
    if baseline is not None and baseline > 0:
        drift = abs(event.payload_size - baseline) / baseline
        if drift >= ctx.payload_drift_ratio:
            return [spec.id]
    return []


def pred_brute_force(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    window = list(recent[-ctx.auth_fail_window :]) + [event]
    fails = sum(1 for e in window if "FAIL" in e.operation.upper() or "DENIED" in e.operation.upper())
    return [spec.id] if fails >= ctx.auth_fail_threshold else []


def pred_protocol_escalation(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    proto = event.protocol.upper()
    asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")
    tiers = ctx.protocol_tier or _tier_map()
    same_asset_recent = [e for e in recent if asset_id and str(e.payload.get("asset_id") or e.payload.get("plc_id") or "") == asset_id]
    if same_asset_recent:
        prev = same_asset_recent[-1]
        pt = tiers.get(prev.protocol.upper(), 0)
        ct = tiers.get(proto, 0)
        if ct > pt + 1:
            return [spec.id]
    return []


def pred_log_wiping(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    op = event.operation.upper()
    if any(x in op for x in ("LOG_WIPE", "AUDIT_CLEAR", "CLEAR_LOG", "WIPE_AUDIT")):
        return [spec.id]
    return []


def pred_runtime_config_change(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    op = event.operation.upper()
    if any(x in op for x in ("CONFIG_WRITE", "FW_UPDATE", "FIRMWARE", "WRITE_CONFIG")):
        return [spec.id]
    return []


def pred_c2_external_dns(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    pl = event.payload
    dom = str(pl.get("domain") or pl.get("dns_query") or "").lower()
    if dom.endswith((".onion", ".tk")) or "malware" in dom:
        return [spec.id]
    return []


def pred_blind_command(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    op = event.operation.upper()
    asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")
    recent_for_asset = _recent_same_asset(recent, asset_id)
    if "WRITE" in op or "TRIP" in op or "COIL" in op:
        had_read = False
        if recent_for_asset:
            prev = recent_for_asset[-1]
            had_read = "READ" in prev.operation.upper() or "POLL" in prev.operation.upper()
        if asset_id and not had_read:
            return [spec.id]
    return []


def pred_reconnaissance(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    op = event.operation.upper()
    if any(x in op for x in ("PORT_SCAN", "TOPOLOGY_SCAN", "RECON", "SNMP_WALK")):
        return [spec.id]
    return []


def pred_new_node_airgap(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("new_node_airgap") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_physical_invariant_breach(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("physical_invariant_breach") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_trust_index_drop(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("trust_index_drop") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_request_reply_dissonance(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("reply_without_prior_request") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_cyclic_service_crash(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("cyclic_service_crash") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_untrusted_ip_admin(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("untrusted_ip_admin") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_conflict_logic(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    pl = event.payload
    op = event.operation.upper()
    if any(x in op for x in ("STATE_MISMATCH", "INTERLOCK_TRIP", "CONTROL_CONFLICT", "LOGIC_FAULT")):
        return [spec.id]
    if pl.get("conflict_logic") in (True, "true", "1", 1) or pl.get("control_conflict") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_expert_dissonance(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    pl = event.payload
    if pl.get("expert_dissonance") in (True, "true", "1", 1) or pl.get("hitl_dissonance") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_polling_jitter(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("polling_jitter") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_lateral_movement(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    if event.payload.get("lateral_movement") in (True, "true", "1", 1):
        return [spec.id]
    return []


PREDICATE_REGISTRY: dict[str, PredicateFn] = {
    "noop": pred_noop,
    InvariantId.ILLEGAL_FUNCTION_CODE.value: pred_illegal_function_code,
    InvariantId.PAYLOAD_LENGTH_DRIFT.value: pred_payload_length_drift,
    InvariantId.BRUTE_FORCE.value: pred_brute_force,
    InvariantId.PROTOCOL_ESCALATION.value: pred_protocol_escalation,
    InvariantId.LOG_WIPING.value: pred_log_wiping,
    InvariantId.RUNTIME_CONFIG_CHANGE.value: pred_runtime_config_change,
    InvariantId.C2_EXTERNAL_DNS.value: pred_c2_external_dns,
    InvariantId.BLIND_COMMAND.value: pred_blind_command,
    InvariantId.RECONNAISSANCE.value: pred_reconnaissance,
    InvariantId.NEW_NODE_AIRGAP.value: pred_new_node_airgap,
    InvariantId.PHYSICAL_INVARIANT_BREACH.value: pred_physical_invariant_breach,
    InvariantId.TRUST_INDEX_DROP.value: pred_trust_index_drop,
    InvariantId.REQUEST_REPLY_DISSONANCE.value: pred_request_reply_dissonance,
    InvariantId.CYCLIC_SERVICE_CRASH.value: pred_cyclic_service_crash,
    InvariantId.UNTRUSTED_IP_ADMIN.value: pred_untrusted_ip_admin,
    InvariantId.CONFLICT_LOGIC.value: pred_conflict_logic,
    InvariantId.EXPERT_DISSONANCE.value: pred_expert_dissonance,
    InvariantId.POLLING_JITTER.value: pred_polling_jitter,
    InvariantId.LATERAL_MOVEMENT.value: pred_lateral_movement,
}

VALID_BUILTIN_PREDICATE_KEYS: frozenset[str] = frozenset(PREDICATE_REGISTRY.keys())
