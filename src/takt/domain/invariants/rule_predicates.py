from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from takt.domain.engines.causal_mesh import detect_jump_server_bypass
from takt.domain.engines.chaos_predictor import predict_polling_chaos
from takt.domain.engines.context_matcher import match_event_to_ticket
from takt.domain.engines.data_quality import (
    evaluate_sequence_gaps,
    evaluate_source_reputation,
    evaluate_stale_telemetry,
)
from takt.domain.engines.phase_time_tagger import phase_dissonance_admin_activity, tag_phase
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


def _declared_source_operations(spec: InvariantRuleSpec) -> frozenset[str]:
    """Операции-вердикты, объявленные для правила в `config/invariants/<id>.yaml`."""
    raw = spec.params.get("source_operations") or ()
    return frozenset(str(item).strip().upper() for item in raw if str(item).strip())


def _matches_declared_operation(event: NormalizedEvent, spec: InvariantRuleSpec) -> bool:
    """Событие несёт вердикт вышестоящей автоматики, сопоставленный этому инварианту.

    ТАКТ работает **после** средств обнаружения: NDR отдаёт `verdict`, SIEM — `rule_name`,
    и импортёры кладут их в `operation` нормализованного события. Пока сопоставления не было,
    предикаты искали промышленные поля (`asset_id`, `function_code`, флаг `lateral_movement`),
    которых в событиях SOC нет, — и весь поток SOC проходил мимо риск-слоя: на фикстуре
    INC-002 все 122 кейса получали одинаковый LOW.

    Сопоставление объявляется в каталоге, а не зашивается в предикат: набор вердиктов у
    каждого заказчика свой, и решение «этот вердикт означает этот инвариант» должно быть
    предметом ревью конфигурации, а не правки кода.
    """
    declared = _declared_source_operations(spec)
    return bool(declared) and event.operation.strip().upper() in declared


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
        # Уровни сравнимы только если оба протокола описаны в таблице. Раньше неизвестный
        # протокол получал уровень 0, и любой переход к описанному протоколу читался как
        # эскалация: на потоках Netflow обычная последовательность DNS -> HTTPS давала
        # срабатывание на штатном трафике.
        pt = tiers.get(prev.protocol.upper())
        ct = tiers.get(proto)
        if pt is None or ct is None:
            return []
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
    if _matches_declared_operation(event, spec):
        return [spec.id]
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
    if _matches_declared_operation(event, spec):
        return [spec.id]
    op = event.operation.upper()
    if any(x in op for x in ("PORT_SCAN", "TOPOLOGY_SCAN", "RECON", "SNMP_WALK")):
        return [spec.id]
    return []


def pred_new_node_airgap(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """New Node в Air-Gap: MAC/IP отсутствует в реестре известных активов.

    Активная детекция применима только к изолированному сегменту с объявленным реестром
    адресов (`ctx.airgap_known_addresses`). Без реестра единственным доступным «реестром»
    оказывались последние события буфера контекста — и в обычной сети из сотен узлов
    правило объявляло новым почти каждый адрес: на фикстуре INC-002 это давало 82
    срабатывания из 121 кейса, то есть шумовой пол вместо признака.

    Правило, которое нечем проверить, молчит: остаётся путь по явному признаку от
    внешнего средства обнаружения.
    """
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("new_node_airgap") in (True, "true", "1", 1):
        return [spec.id]
    known = getattr(ctx, "airgap_known_addresses", frozenset()) or frozenset()
    if not known:
        return []
    src_ip = str(event.payload.get("src_ip") or "")
    mac = str(event.payload.get("mac") or "")
    if not src_ip and not mac:
        return []
    if src_ip and src_ip not in known:
        return [spec.id]
    if mac and mac not in known:
        return [spec.id]
    return []


def pred_physical_invariant_breach(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Physical Invariant Breach: аномальная скорость изменения dX/dt датчика."""
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("physical_invariant_breach") in (True, "true", "1", 1):
        return [spec.id]
    # Активная детекция: |dX/dt| превышает порог
    val = event.payload.get("telemetry_value")
    if val is None:
        return []
    try:
        cur = float(val)
    except (TypeError, ValueError):
        return []
    asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")
    same_asset = _recent_same_asset(recent, asset_id) if asset_id else recent
    if not same_asset:
        return []
    prev = same_asset[-1]
    prev_val = prev.payload.get("telemetry_value")
    if prev_val is None:
        return []
    try:
        prev_f = float(prev_val)
    except (TypeError, ValueError):
        return []
    dt = (event.observed_at - prev.observed_at).total_seconds()
    if dt <= 0:
        return []
    rate = abs(cur - prev_f) / dt
    max_rate = float(ctx.max_rate_of_change) if hasattr(ctx, "max_rate_of_change") and ctx.max_rate_of_change else 100.0
    if rate > max_rate:
        return [spec.id]
    return []


def pred_trust_index_drop(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Trust Index Drop: кумулятивный дрейф доверия ниже порога."""
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("trust_index_drop") in (True, "true", "1", 1):
        return [spec.id]
    # Активная детекция: trust источника ниже критического порога
    trust_map = ctx.trust_by_source or {}
    trust = float(trust_map.get(event.source.value, 1.0))
    if trust < 0.3:
        return [spec.id]
    return []


def pred_request_reply_dissonance(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Request-Reply Dissonance: ответ (REPLY/RESPONSE) без предшествующего запроса."""
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("reply_without_prior_request") in (True, "true", "1", 1):
        return [spec.id]
    # Активная детекция: REPLY без REQUEST в recent для того же актива
    op = event.operation.upper()
    if not any(x in op for x in ("REPLY", "RESPONSE", "ANSWER")):
        return []
    asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")
    same_asset = _recent_same_asset(recent, asset_id) if asset_id else recent
    had_request = any(
        any(x in e.operation.upper() for x in ("REQUEST", "READ", "POLL", "QUERY"))
        for e in same_asset
    )
    if not had_request:
        return [spec.id]
    return []


def pred_cyclic_service_crash(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Cyclic Service Crash: ≥3 CRASH/RESTART для того же сервиса в recent."""
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("cyclic_service_crash") in (True, "true", "1", 1):
        return [spec.id]
    # Активная детекция: ≥3 событий CRASH/RESTART в recent
    op = event.operation.upper()
    is_crash = any(x in op for x in ("CRASH", "RESTART", "PANIC", "FAULT"))
    if not is_crash:
        return []
    asset_id = str(event.payload.get("asset_id") or event.payload.get("plc_id") or "")
    same_asset = _recent_same_asset(recent, asset_id) if asset_id else recent
    crash_count = sum(
        1 for e in same_asset
        if any(x in e.operation.upper() for x in ("CRASH", "RESTART", "PANIC", "FAULT"))
    )
    if crash_count + 1 >= 3:
        return [spec.id]
    return []


def pred_untrusted_ip_admin(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Untrusted IP Admin: админская операция с непроверенного IP."""
    # Флаг-чекер (внешний SIEM уже определил)
    if event.payload.get("untrusted_ip_admin") in (True, "true", "1", 1):
        return [spec.id]
    # Активная детекция: src_ip не в списке доверенных админских IP
    op = event.operation.upper()
    if not any(x in op for x in ("ADMIN", "LOGIN", "SSH", "REMOTE_SESSION")):
        return []
    src_ip = str(event.payload.get("src_ip") or "")
    if not src_ip:
        return []
    trusted_ips = ctx.trusted_admin_ips if hasattr(ctx, "trusted_admin_ips") and ctx.trusted_admin_ips else frozenset()
    if trusted_ips and src_ip not in trusted_ips:
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
    if _matches_declared_operation(event, spec):
        return [spec.id]
    if event.payload.get("lateral_movement") in (True, "true", "1", 1):
        return [spec.id]
    return []


def pred_stale_data(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Inv_DQ_01: замерзший датчик — одинаковые payload при долгом интервале."""
    seq = list(recent) + [event]
    if len(seq) < 2:
        return []
    snap = evaluate_stale_telemetry(seq, stale_window_seconds=ctx.stale_window_seconds)
    if "stale_data" in snap.reasons:
        return [spec.id]
    return []


def pred_telemetry_gap(
    event: NormalizedEvent,
    recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Inv_DQ_02: потеря пакетов — большие разрывы между событиями источника."""
    seq = list(recent) + [event]
    if len(seq) < 2:
        return []
    snap = evaluate_sequence_gaps(seq, max_gap_seconds=ctx.max_gap_seconds)
    if "telemetry_gap" in snap.reasons:
        return [spec.id]
    return []


def pred_source_reputation_drift(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Inv_DQ_03: дрейф репутации источника — trust < 0.85."""
    trust_map = ctx.trust_by_source or {}
    snap = evaluate_source_reputation(
        source_key=event.source.value,
        trust_by_source=trust_map,
    )
    if "source_reputation_drift" in snap.reasons:
        return [spec.id]
    return []


def pred_context_dissonance(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Критическая операция вне окна регламентных работ."""
    if ctx.now is None:
        return []
    match = match_event_to_ticket(event, list(ctx.tickets), now=ctx.now)
    if match.dissonance:
        return [spec.id]
    return []


def pred_out_of_shift_access(
    event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    _ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Админская активность вне дневной смены (ночь/выходной)."""
    if _matches_declared_operation(event, spec):
        return [spec.id]
    if "admin" not in event.operation.lower():
        return []
    label = tag_phase(event.observed_at)
    if phase_dissonance_admin_activity(label):
        return [spec.id]
    return []


def pred_jump_server_bypass(
    _event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Прямое обращение к ПЛК в обход jump-сервера."""
    if not ctx.graph_edges or not ctx.jump_host:
        return []
    if detect_jump_server_bypass(
        list(ctx.graph_edges),
        ctx.jump_host,
        ctx.plc_hosts,
    ):
        return [spec.id]
    return []


def pred_polling_period_doubling_suspect(
    _event: NormalizedEvent,
    _recent: list[NormalizedEvent],
    ctx: Any,
    spec: InvariantRuleSpec,
) -> list[str]:
    """Chaos Predictor: каскадное удвоение интервалов опроса (Фейгенбаум ≈ 4.669)."""
    if not ctx.polling_intervals_us:
        return []
    result = predict_polling_chaos(ctx.polling_intervals_us)
    if result and result.suggests_period_doubling_cluster:
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
    InvariantId.STALE_DATA.value: pred_stale_data,
    InvariantId.TELEMETRY_GAP.value: pred_telemetry_gap,
    InvariantId.SOURCE_REPUTATION_DRIFT.value: pred_source_reputation_drift,
    InvariantId.CONTEXT_DISSONANCE.value: pred_context_dissonance,
    InvariantId.OUT_OF_SHIFT_ACCESS.value: pred_out_of_shift_access,
    InvariantId.JUMP_SERVER_BYPASS.value: pred_jump_server_bypass,
    InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value: pred_polling_period_doubling_suspect,
}

VALID_BUILTIN_PREDICATE_KEYS: frozenset[str] = frozenset(PREDICATE_REGISTRY.keys())
