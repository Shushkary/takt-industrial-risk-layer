from __future__ import annotations

from datetime import datetime, timezone

import pytest

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import InvariantContext, collect_extended_invariants


def test_illegal_function_code():
    ctx = InvariantContext(allowed_function_codes=frozenset({"3", "4"}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "a1", "function_code": "99"},
    )
    hits = collect_extended_invariants(ev, (), ctx)
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value in hits


def test_log_wiping():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.AUTH_LOGS,
        protocol="SYS",
        operation="AUDIT_CLEAR",
        payload_size=4,
        payload={},
    )
    assert InvariantId.LOG_WIPING.value in collect_extended_invariants(ev, (), None)


def test_brute_force_window():
    t0 = datetime.now(timezone.utc)
    fails = [
        NormalizedEvent(
            event_id=str(i),
            observed_at=t0,
            source=EventSource.AUTH_LOGS,
            protocol="SSH",
            operation="AUTH_FAIL",
            payload_size=1,
            payload={"asset_id": "x"},
        )
        for i in range(6)
    ]
    ev = fails[-1]
    ctx = InvariantContext(auth_fail_threshold=5, auth_fail_window=20)
    hits = collect_extended_invariants(ev, fails[:-1], ctx)
    assert InvariantId.BRUTE_FORCE.value in hits


def test_brute_force_not_triggered_one_below_threshold():
    t0 = datetime.now(timezone.utc)
    ctx = InvariantContext(auth_fail_threshold=5, auth_fail_window=20)
    prev_fails = [
        NormalizedEvent(
            event_id=str(i),
            observed_at=t0,
            source=EventSource.AUTH_LOGS,
            protocol="SSH",
            operation="AUTH_FAIL",
            payload_size=1,
            payload={"asset_id": "gate"},
        )
        for i in range(3)
    ]
    ev = NormalizedEvent(
        event_id="current",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="AUTH_FAIL",
        payload_size=1,
        payload={"asset_id": "gate"},
    )
    hits = collect_extended_invariants(ev, prev_fails, ctx)
    assert InvariantId.BRUTE_FORCE.value not in hits


def test_brute_force_triggered_at_exact_threshold_five():
    t0 = datetime.now(timezone.utc)
    ctx = InvariantContext(auth_fail_threshold=5, auth_fail_window=20)
    prev_fails = [
        NormalizedEvent(
            event_id=str(i),
            observed_at=t0,
            source=EventSource.AUTH_LOGS,
            protocol="SSH",
            operation="AUTH_FAIL",
            payload_size=1,
            payload={"asset_id": "gate"},
        )
        for i in range(4)
    ]
    ev = NormalizedEvent(
        event_id="fifth",
        observed_at=t0,
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="AUTH_DENIED",
        payload_size=1,
        payload={"asset_id": "gate"},
    )
    hits = collect_extended_invariants(ev, prev_fails, ctx)
    assert InvariantId.BRUTE_FORCE.value in hits


def test_case_to_siem_invariant_details():
    from takt.domain.entities.case import Case, CaseStatus
    from takt.domain.invariants.catalog import InvariantId
    from takt.infrastructure.export.siem_webhook import case_to_siem_payload

    c = Case(
        case_id="x",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=datetime.now(timezone.utc),
        invariant_hits=[InvariantId.TRUST_INDEX_DROP.value],
    )
    d = case_to_siem_payload(c).model_dump(mode="json")
    assert d["invariant_hits"] == [InvariantId.TRUST_INDEX_DROP.value]
    assert len(d["invariant_details"]) == 1
    assert d["invariant_details"][0]["id"] == InvariantId.TRUST_INDEX_DROP.value
    assert d["invariant_details"][0]["title_ru"]


def test_case_to_siem_payload_keys():
    from takt.domain.entities.case import Case, CaseStatus
    from takt.infrastructure.export.siem_webhook import case_to_siem_payload

    c = Case(
        case_id="abc",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=datetime.now(timezone.utc),
    )
    d = case_to_siem_payload(c).model_dump(mode="json")
    assert d["case_id"] == "abc"
    assert "risk_score" in d
    assert d["invariant_hits"] == []
    assert d["invariant_details"] == []
    assert d["data_quality"]["dq_score"] == 1.0
    assert d["data_quality"]["partial_observability"] is False
    assert d["data_quality"]["reasons"] == []
    assert d["last_event_source"] == ""


def test_case_to_siem_known_invariant_uses_catalog_title_ru():
    from takt.domain.entities.case import Case, CaseStatus
    from takt.domain.invariants.catalog import invariant_titles_by_id
    from takt.infrastructure.export.siem_webhook import case_to_siem_payload

    title = invariant_titles_by_id()[InvariantId.LOG_WIPING.value]
    c = Case(
        case_id="cat",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
        invariant_hits=[InvariantId.LOG_WIPING.value],
    )
    d = case_to_siem_payload(c).model_dump(mode="json")
    assert d["invariant_details"][0]["id"] == InvariantId.LOG_WIPING.value
    assert d["invariant_details"][0]["title_ru"] == title
    assert len(title) > len(InvariantId.LOG_WIPING.value)


def test_case_to_siem_unknown_invariant_id_uses_id_as_detail_title():
    from takt.domain.entities.case import Case, CaseStatus
    from takt.infrastructure.export.siem_webhook import case_to_siem_payload

    c = Case(
        case_id="x",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
        invariant_hits=["not_in_catalog_xyz"],
    )
    d = case_to_siem_payload(c).model_dump(mode="json")
    assert len(d["invariant_details"]) == 1
    assert d["invariant_details"][0]["id"] == "not_in_catalog_xyz"
    assert d["invariant_details"][0]["title_ru"] == "not_in_catalog_xyz"


def test_case_to_siem_audit_tail_keeps_last_twenty_lines():
    from takt.domain.entities.case import Case, CaseStatus
    from takt.infrastructure.export.siem_webhook import case_to_siem_payload

    logs = [f"L{i:03d}" for i in range(25)]
    c = Case(
        case_id="audit-cap",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
        audit_log=logs,
    )
    d = case_to_siem_payload(c).model_dump(mode="json")
    assert len(d["audit_tail"]) == 20
    assert d["audit_tail"][0] == "L005"
    assert d["audit_tail"][-1] == "L024"


def test_payload_semantic_flags():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="TCP",
        operation="PING",
        payload_size=1,
        payload={
            "asset_id": "z",
            "new_node_airgap": True,
            "trust_index_drop": 1,
            "reply_without_prior_request": True,
        },
    )
    h = collect_extended_invariants(ev, (), None)
    assert InvariantId.NEW_NODE_AIRGAP.value in h
    assert InvariantId.TRUST_INDEX_DROP.value in h
    assert InvariantId.REQUEST_REPLY_DISSONANCE.value in h


def test_conflict_logic_operation_token():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="STATE_MISMATCH_ALARM",
        payload_size=1,
        payload={"asset_id": "p1"},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_conflict_logic_interlock_trip_keyword():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="INTERLOCK_TRIP_EVENT",
        payload_size=1,
        payload={"asset_id": "p2"},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_expert_dissonance_payload():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.SERVICE_DESK,
        protocol="HTTP",
        operation="REVIEW",
        payload_size=1,
        payload={"asset_id": "x", "expert_dissonance": True},
    )
    assert InvariantId.EXPERT_DISSONANCE.value in collect_extended_invariants(ev, (), None)


def test_expert_dissonance_hitl_alias_payload():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.SERVICE_DESK,
        protocol="HTTP",
        operation="NOTE",
        payload_size=1,
        payload={"asset_id": "x", "hitl_dissonance": True},
    )
    assert InvariantId.EXPERT_DISSONANCE.value in collect_extended_invariants(ev, (), None)


def test_conflict_logic_control_conflict_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="PERIODIC",
        payload_size=1,
        payload={"asset_id": "x", "control_conflict": True},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_conflict_logic_control_conflict_numeric_string():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="SCAN",
        payload_size=1,
        payload={"asset_id": "y", "control_conflict": "1"},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_conflict_logic_logic_fault_keyword():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="LOGIC_FAULT_DETECTED",
        payload_size=1,
        payload={"asset_id": "z"},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_conflict_logic_payload_conflict_logic_true_string():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="HEARTBEAT",
        payload_size=1,
        payload={"asset_id": "z", "conflict_logic": "true"},
    )
    assert InvariantId.CONFLICT_LOGIC.value in collect_extended_invariants(ev, (), None)


def test_polling_jitter_payload_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="POLL",
        payload_size=4,
        payload={"asset_id": "a", "polling_jitter": True},
    )
    assert InvariantId.POLLING_JITTER.value in collect_extended_invariants(ev, (), None)


def test_invariant_records_match_enum():
    from takt.domain.invariants.catalog import INVARIANT_RECORDS

    assert {r.id for r in INVARIANT_RECORDS} == {m.value for m in InvariantId}
    assert len(INVARIANT_RECORDS) == len(InvariantId)


def test_payload_length_drift():
    ctx = InvariantContext(expected_payload_baseline=100, payload_drift_ratio=0.2)
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=500,
        payload={"asset_id": "a1"},
    )
    assert InvariantId.PAYLOAD_LENGTH_DRIFT.value in collect_extended_invariants(ev, (), ctx)


def test_protocol_escalation_same_asset():
    t0 = datetime.now(timezone.utc)
    prev = NormalizedEvent(
        event_id="0",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="MODBUS",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    ev = NormalizedEvent(
        event_id="1",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="SMB",
        operation="READ",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    assert InvariantId.PROTOCOL_ESCALATION.value in collect_extended_invariants(ev, [prev], None)


def test_protocol_escalation_skips_adjacent_tier_step():
    t0 = datetime.now(timezone.utc)
    prev = NormalizedEvent(
        event_id="0",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="MODBUS",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    ev = NormalizedEvent(
        event_id="1",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="DNP3",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    assert InvariantId.PROTOCOL_ESCALATION.value not in collect_extended_invariants(ev, [prev], None)


def test_protocol_escalation_skips_different_asset():
    t0 = datetime.now(timezone.utc)
    prev = NormalizedEvent(
        event_id="0",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="MODBUS",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": "plc-a"},
    )
    ev = NormalizedEvent(
        event_id="1",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="SMB",
        operation="READ",
        payload_size=1,
        payload={"asset_id": "plc-b"},
    )
    assert InvariantId.PROTOCOL_ESCALATION.value not in collect_extended_invariants(ev, [prev], None)


def test_protocol_escalation_uses_custom_protocol_tier_from_context():
    ctx = InvariantContext(protocol_tier={"MODBUS": 1, "SSH": 5})
    t0 = datetime.now(timezone.utc)
    prev = NormalizedEvent(
        event_id="0",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="MODBUS",
        operation="POLL",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    ev = NormalizedEvent(
        event_id="1",
        observed_at=t0,
        source=EventSource.NETWORK,
        protocol="SSH",
        operation="READ",
        payload_size=1,
        payload={"asset_id": "shared"},
    )
    assert InvariantId.PROTOCOL_ESCALATION.value in collect_extended_invariants(ev, [prev], ctx)


def test_runtime_config_change():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="WRITE_CONFIG",
        payload_size=1,
        payload={},
    )
    assert InvariantId.RUNTIME_CONFIG_CHANGE.value in collect_extended_invariants(ev, (), None)


def test_c2_external_dns():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="UDP",
        operation="DNS_QUERY",
        payload_size=1,
        payload={"domain": "evil.onion"},
    )
    assert InvariantId.C2_EXTERNAL_DNS.value in collect_extended_invariants(ev, (), None)


def test_c2_external_dns_malware_substring_in_domain():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="UDP",
        operation="DNS_QUERY",
        payload_size=1,
        payload={"domain": "track-malware.azure.net"},
    )
    assert InvariantId.C2_EXTERNAL_DNS.value in collect_extended_invariants(ev, (), None)


def test_blind_command_without_prior_read():
    t0 = datetime.now(timezone.utc)
    ev = NormalizedEvent(
        event_id="1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="WRITE_COIL",
        payload_size=4,
        payload={"asset_id": "plc-x"},
    )
    assert InvariantId.BLIND_COMMAND.value in collect_extended_invariants(ev, (), None)


def test_blind_command_trip_without_prior_read():
    t0 = datetime(2026, 6, 10, 8, 0, tzinfo=timezone.utc)
    ev = NormalizedEvent(
        event_id="t1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="REMOTE_TRIP",
        payload_size=2,
        payload={"asset_id": "relay-1"},
    )
    assert InvariantId.BLIND_COMMAND.value in collect_extended_invariants(ev, (), None)


def test_blind_command_coil_keyword_without_write_prefix():
    t0 = datetime(2026, 6, 11, 9, 0, tzinfo=timezone.utc)
    ev = NormalizedEvent(
        event_id="c1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="FORCE_COIL_ON",
        payload_size=1,
        payload={"asset_id": "out-1"},
    )
    assert InvariantId.BLIND_COMMAND.value in collect_extended_invariants(ev, (), None)


def test_reconnaissance_operation():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="TCP",
        operation="PORT_SCAN",
        payload_size=1,
        payload={},
    )
    assert InvariantId.RECONNAISSANCE.value in collect_extended_invariants(ev, (), None)


def test_physical_invariant_breach_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="READ",
        payload_size=4,
        payload={"asset_id": "a", "physical_invariant_breach": True},
    )
    assert InvariantId.PHYSICAL_INVARIANT_BREACH.value in collect_extended_invariants(ev, (), None)


def test_cyclic_service_crash_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="POLL",
        payload_size=4,
        payload={"asset_id": "a", "cyclic_service_crash": True},
    )
    assert InvariantId.CYCLIC_SERVICE_CRASH.value in collect_extended_invariants(ev, (), None)


def test_untrusted_ip_admin_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="LOGIN",
        payload_size=4,
        payload={"asset_id": "a", "untrusted_ip_admin": True},
    )
    assert InvariantId.UNTRUSTED_IP_ADMIN.value in collect_extended_invariants(ev, (), None)


def test_lateral_movement_flag():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="TCP",
        operation="RPC",
        payload_size=1,
        payload={"asset_id": "a", "lateral_movement": True},
    )
    assert InvariantId.LATERAL_MOVEMENT.value in collect_extended_invariants(ev, (), None)


def test_illegal_function_code_iec104_type_id():
    ctx = InvariantContext(iec104_disallowed_type_ids=frozenset({99}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "a1", "iec104_type_id": 99},
    )
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value in collect_extended_invariants(ev, (), ctx)


def test_illegal_function_code_iec104_not_hit_when_type_allowed():
    ctx = InvariantContext(iec104_disallowed_type_ids=frozenset({99}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "a1", "iec104_type_id": 45},
    )
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value not in collect_extended_invariants(ev, (), ctx)


def test_illegal_function_code_iec104_type_id_numeric_string():
    ctx = InvariantContext(iec104_disallowed_type_ids=frozenset({13}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "a1", "iec104_type_id": "13"},
    )
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value in collect_extended_invariants(ev, (), ctx)


def test_illegal_function_code_iec104_malformed_type_id_ignored():
    ctx = InvariantContext(iec104_disallowed_type_ids=frozenset({13}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="READ",
        payload_size=8,
        payload={"asset_id": "a1", "iec104_type_id": "n/a"},
    )
    hits = collect_extended_invariants(ev, (), ctx)
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value not in hits


def test_blind_command_suppressed_when_prior_poll_same_plc_id():
    t0 = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    recent = [
        NormalizedEvent(
            event_id="r1",
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="POLL",
            payload_size=1,
            payload={"plc_id": "plc-9"},
        ),
    ]
    ev = NormalizedEvent(
        event_id="w1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="WRITE",
        payload_size=1,
        payload={"plc_id": "plc-9"},
    )
    assert InvariantId.BLIND_COMMAND.value not in collect_extended_invariants(ev, recent, None)


def test_blind_command_only_immediate_prior_same_asset_matters():
    """Учитывается только последнее по тому же активу событие (не любой read в глубине окна)."""
    t0 = datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
    recent = [
        NormalizedEvent(
            event_id="r1",
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="READ",
            payload_size=1,
            payload={"asset_id": "a1"},
        ),
        NormalizedEvent(
            event_id="p1",
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="PING",
            payload_size=1,
            payload={"asset_id": "a1"},
        ),
    ]
    ev = NormalizedEvent(
        event_id="w1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="COIL_WRITE",
        payload_size=1,
        payload={"asset_id": "a1"},
    )
    assert InvariantId.BLIND_COMMAND.value in collect_extended_invariants(ev, recent, None)


def test_boost_helpers_nonzero_when_markers_present():
    from takt.domain.invariants.evaluator import (
        graph_topology_boost,
        hitl_context_boost,
        integrity_boost,
        physics_boost,
        request_reply_boost,
        rhythm_boost,
        trust_boost,
        user_boost,
    )

    assert integrity_boost([InvariantId.LOG_WIPING.value]) == pytest.approx(0.9)
    assert rhythm_boost([InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value]) == pytest.approx(0.55)
    assert user_boost([InvariantId.UNTRUSTED_IP_ADMIN.value]) == pytest.approx(0.75)
    assert graph_topology_boost([InvariantId.LATERAL_MOVEMENT.value]) == pytest.approx(0.7)
    assert physics_boost([InvariantId.PHYSICAL_INVARIANT_BREACH.value]) == pytest.approx(0.65)
    assert hitl_context_boost([InvariantId.EXPERT_DISSONANCE.value]) == pytest.approx(0.6)
    assert trust_boost([InvariantId.TRUST_INDEX_DROP.value]) == pytest.approx(0.55)
    assert request_reply_boost([InvariantId.REQUEST_REPLY_DISSONANCE.value]) == pytest.approx(0.6)


def test_boost_helpers_zero_without_markers():
    from takt.domain.invariants.evaluator import (
        graph_topology_boost,
        hitl_context_boost,
        integrity_boost,
        physics_boost,
        request_reply_boost,
        rhythm_boost,
        trust_boost,
        user_boost,
    )

    empty: list[str] = []
    assert integrity_boost(empty) == 0.0
    assert rhythm_boost(empty) == 0.0
    assert user_boost(empty) == 0.0
    assert graph_topology_boost(empty) == 0.0
    assert physics_boost(empty) == 0.0
    assert hitl_context_boost(empty) == 0.0
    assert trust_boost(empty) == 0.0
    assert request_reply_boost(empty) == 0.0


def test_blind_command_suppressed_when_prior_read_same_asset():
    t0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    recent = [
        NormalizedEvent(
            event_id="r1",
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="READ",
            payload_size=1,
            payload={"asset_id": "plc-1"},
        ),
    ]
    ev = NormalizedEvent(
        event_id="w1",
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation="WRITE_COIL",
        payload_size=1,
        payload={"asset_id": "plc-1"},
    )
    hits = collect_extended_invariants(ev, recent, None)
    assert InvariantId.BLIND_COMMAND.value not in hits


def test_c2_external_dns_via_dns_query_tk_tld():
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="UDP",
        operation="DNS_LOOKUP",
        payload_size=1,
        payload={"dns_query": "beacon.evil.tk"},
    )
    assert InvariantId.C2_EXTERNAL_DNS.value in collect_extended_invariants(ev, (), None)
