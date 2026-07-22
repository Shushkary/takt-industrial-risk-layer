"""Размеченный корпус сценариев для оценки TPR/FPR декларативных инвариантов.

Каждый `EvalScenario` — одно нормализованное событие (+ история `recent`)
с ожидаемым набором сработавших инвариантов `expected_hits` (пустой —
легитимный трафик, непустой — эталонная атака).

Область охвата (11 из 26 инвариантов с детерминированными триггерами на
уровне `collect_extended_invariants`, без топологии/графа и без 7 правил,
для которых на момент записи не совпадают production-конфиг и код —
см. `docs/invariant_matrix.md`):

illegal_function_code, log_wiping, brute_force, payload_length_drift,
protocol_escalation, blind_command, reconnaissance,
physical_invariant_breach, cyclic_service_crash, untrusted_ip_admin,
lateral_movement.

Это не эталонная выборка «боевого» трафика КИИ, а минимальный синтетический
корпус для замера методологии (см. `docs/detection_quality.md`). Расширение
на оставшиеся инварианты и промышленные датасеты — отдельная задача.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import InvariantContext

_T0 = datetime(2026, 6, 1, 8, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class EvalScenario:
    name: str
    event: NormalizedEvent
    recent: tuple[NormalizedEvent, ...]
    ctx: InvariantContext | None
    expected_hits: frozenset[str]


def _ev(event_id: str, *, source: EventSource, protocol: str, operation: str, payload: dict, size: int = 8) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=_T0,
        source=source,
        protocol=protocol,
        operation=operation,
        payload_size=size,
        payload=payload,
    )


def _attack_scenarios() -> list[EvalScenario]:
    fails = tuple(
        _ev(f"fail-{i}", source=EventSource.AUTH_LOGS, protocol="SSH", operation="AUTH_FAIL", payload={"asset_id": "gate"})
        for i in range(5)
    )
    return [
        EvalScenario(
            name="illegal_function_code/disallowed_code",
            event=_ev("atk-1", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ",
                       payload={"asset_id": "plc-1", "function_code": "99"}),
            recent=(),
            ctx=InvariantContext(allowed_function_codes=frozenset({"3", "4"})),
            expected_hits=frozenset({InvariantId.ILLEGAL_FUNCTION_CODE.value}),
        ),
        EvalScenario(
            name="log_wiping/audit_clear",
            event=_ev("atk-2", source=EventSource.AUTH_LOGS, protocol="SYS", operation="AUDIT_CLEAR", payload={}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.LOG_WIPING.value}),
        ),
        EvalScenario(
            name="brute_force/five_consecutive_failures",
            event=fails[-1],
            recent=fails[:-1],
            ctx=InvariantContext(auth_fail_threshold=5, auth_fail_window=20),
            expected_hits=frozenset({InvariantId.BRUTE_FORCE.value}),
        ),
        EvalScenario(
            name="payload_length_drift/5x_baseline",
            event=_ev("atk-4", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ",
                       payload={"asset_id": "a1"}, size=500),
            recent=(),
            ctx=InvariantContext(expected_payload_baseline=100, payload_drift_ratio=0.2),
            expected_hits=frozenset({InvariantId.PAYLOAD_LENGTH_DRIFT.value}),
        ),
        EvalScenario(
            name="protocol_escalation/modbus_to_smb_same_asset",
            event=_ev("atk-5", source=EventSource.NETWORK, protocol="SMB", operation="READ", payload={"asset_id": "shared"}),
            recent=(_ev("atk-5-prev", source=EventSource.NETWORK, protocol="MODBUS", operation="POLL", payload={"asset_id": "shared"}),),
            ctx=None,
            expected_hits=frozenset({InvariantId.PROTOCOL_ESCALATION.value}),
        ),
        EvalScenario(
            name="blind_command/write_without_prior_read",
            event=_ev("atk-6", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="WRITE_COIL", payload={"asset_id": "plc-x"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.BLIND_COMMAND.value}),
        ),
        EvalScenario(
            name="reconnaissance/port_scan",
            event=_ev("atk-7", source=EventSource.NETWORK, protocol="TCP", operation="PORT_SCAN", payload={}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.RECONNAISSANCE.value}),
        ),
        EvalScenario(
            name="physical_invariant_breach/flagged_reading",
            event=_ev("atk-8", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ",
                       payload={"asset_id": "a", "physical_invariant_breach": True}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.PHYSICAL_INVARIANT_BREACH.value}),
        ),
        EvalScenario(
            name="cyclic_service_crash/flagged_restart_loop",
            event=_ev("atk-9", source=EventSource.PLC_POLLING, protocol="IEC104", operation="POLL",
                       payload={"asset_id": "a", "cyclic_service_crash": True}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.CYCLIC_SERVICE_CRASH.value}),
        ),
        EvalScenario(
            name="untrusted_ip_admin/flagged_login",
            event=_ev("atk-10", source=EventSource.AUTH_LOGS, protocol="SSH", operation="LOGIN",
                       payload={"asset_id": "a", "untrusted_ip_admin": True}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.UNTRUSTED_IP_ADMIN.value}),
        ),
        EvalScenario(
            name="lateral_movement/flagged_rpc",
            event=_ev("atk-11", source=EventSource.NETWORK, protocol="TCP", operation="RPC",
                       payload={"asset_id": "a", "lateral_movement": True}),
            recent=(),
            ctx=None,
            expected_hits=frozenset({InvariantId.LATERAL_MOVEMENT.value}),
        ),
    ]


def _benign_scenarios() -> list[EvalScenario]:
    return [
        EvalScenario(
            name="benign/normal_modbus_read_allowed_code",
            event=_ev("ben-1", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ",
                       payload={"asset_id": "plc-1", "function_code": "3"}),
            recent=(),
            ctx=InvariantContext(allowed_function_codes=frozenset({"3", "4"})),
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/routine_auth_login_success",
            event=_ev("ben-2", source=EventSource.AUTH_LOGS, protocol="SSH", operation="LOGIN", payload={"asset_id": "gate"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/single_auth_failure_below_threshold",
            event=_ev("ben-3", source=EventSource.AUTH_LOGS, protocol="SSH", operation="AUTH_FAIL", payload={"asset_id": "gate"}),
            recent=(
                _ev("ben-3-prev1", source=EventSource.AUTH_LOGS, protocol="SSH", operation="AUTH_FAIL", payload={"asset_id": "gate"}),
            ),
            ctx=InvariantContext(auth_fail_threshold=5, auth_fail_window=20),
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/payload_within_drift_tolerance",
            event=_ev("ben-4", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ",
                       payload={"asset_id": "a1"}, size=110),
            recent=(),
            ctx=InvariantContext(expected_payload_baseline=100, payload_drift_ratio=0.2),
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/same_protocol_repeat_poll",
            event=_ev("ben-5", source=EventSource.NETWORK, protocol="MODBUS", operation="POLL", payload={"asset_id": "shared"}),
            recent=(_ev("ben-5-prev", source=EventSource.NETWORK, protocol="MODBUS", operation="POLL", payload={"asset_id": "shared"}),),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/read_before_write",
            event=_ev("ben-6", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="WRITE_COIL", payload={"asset_id": "plc-x"}),
            recent=(_ev("ben-6-prev", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ", payload={"asset_id": "plc-x"}),),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/routine_network_poll",
            event=_ev("ben-7", source=EventSource.NETWORK, protocol="TCP", operation="POLL", payload={}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/normal_reading_no_breach_flag",
            event=_ev("ben-8", source=EventSource.PLC_POLLING, protocol="MODBUS", operation="READ", payload={"asset_id": "a"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/normal_poll_no_crash_flag",
            event=_ev("ben-9", source=EventSource.PLC_POLLING, protocol="IEC104", operation="POLL", payload={"asset_id": "a"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/trusted_ip_login",
            event=_ev("ben-10", source=EventSource.AUTH_LOGS, protocol="SSH", operation="LOGIN", payload={"asset_id": "a"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
        EvalScenario(
            name="benign/routine_rpc_no_lateral_flag",
            event=_ev("ben-11", source=EventSource.NETWORK, protocol="TCP", operation="RPC", payload={"asset_id": "a"}),
            recent=(),
            ctx=None,
            expected_hits=frozenset(),
        ),
    ]


IN_SCOPE_INVARIANT_IDS: frozenset[str] = frozenset(
    {
        InvariantId.ILLEGAL_FUNCTION_CODE.value,
        InvariantId.LOG_WIPING.value,
        InvariantId.BRUTE_FORCE.value,
        InvariantId.PAYLOAD_LENGTH_DRIFT.value,
        InvariantId.PROTOCOL_ESCALATION.value,
        InvariantId.BLIND_COMMAND.value,
        InvariantId.RECONNAISSANCE.value,
        InvariantId.PHYSICAL_INVARIANT_BREACH.value,
        InvariantId.CYCLIC_SERVICE_CRASH.value,
        InvariantId.UNTRUSTED_IP_ADMIN.value,
        InvariantId.LATERAL_MOVEMENT.value,
    }
)


def all_scenarios() -> list[EvalScenario]:
    return _attack_scenarios() + _benign_scenarios()
