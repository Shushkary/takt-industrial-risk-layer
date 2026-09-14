"""Общий корпус сценариев для вариационных гвардов детерминизма.

Три теста (`test_verdict_gauge_invariance_redaction`, `test_verdict_permutation_invariance`,
`test_verdict_clock_and_id_independence`) проверяют разные симметрии одного и того же контура
вердикта, и корпус у них обязан быть один: иначе гвард, прошедший на своём наборе, ничего не
говорит про случаи соседнего.

Сценарии подобраны так, чтобы задевать разные ветки оценки: обход jump-сервера, дрожание опроса,
слепая команда на ПЛК, работа по наряду и событие с неполными данными. В полезной нагрузке
каждого лежат поля из `REDACTED_FIELD_NAMES` — они и есть калибровочные степени свободы,
относительно которых вердикт обязан быть неподвижен.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from takt.application.use_cases.assess_risk import demo_ticket_for_asset
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket

# Веса берутся литералом намеренно: гвард проверяет неподвижность вердикта под вариацией
# процедуры, а не текущие боевые веса. Привязка к `config/risk_weights.yaml` сделала бы падение
# гварда неотличимым от правки конфигурации администратором.
GUARD_WEIGHTS: dict[str, Any] = {
    "rhythm": 0.22,
    "graph": 0.22,
    "context": 0.18,
    "user": 0.18,
    "data_quality": 0.20,
    "mandelbrot_entropy_cap": 2.5,
    "eps_soft_cap": 100_000,
}

T0 = datetime(2026, 4, 30, 22, 0, tzinfo=UTC)

# Секреты, восстановленные из трафика: ровно те имена полей, которые маскирует коннектор.
# Значения выдуманы и в репозитории не используются больше нигде.
_SECRETS: dict[str, Any] = {
    "password": "hunter2-not-real",
    "session_key": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "cookie": "SESSIONID=synthetic-value-for-tests",
    "authorization": "Basic c3ludGhldGljOnNlY3JldA==",
    "community": "public-but-secret",
}


@dataclass(frozen=True, slots=True)
class Scenario:
    """Один вход конвейера целиком: событие и весь его контекст."""

    name: str
    event: NormalizedEvent
    recent_events: tuple[NormalizedEvent, ...]
    tickets: tuple[ServiceTicket, ...]
    graph_edges: tuple[GraphEdge, ...]
    polling_intervals_us: tuple[float, ...]
    plc_hosts: frozenset[str]


def _event(
    event_id: str,
    *,
    offset_sec: int,
    source: EventSource,
    protocol: str,
    operation: str,
    payload: dict[str, Any],
    payload_size: int = 64,
    with_secrets: bool = True,
) -> NormalizedEvent:
    body = dict(payload)
    if with_secrets:
        body.update(_SECRETS)
    return NormalizedEvent(
        event_id=event_id,
        observed_at=T0 + timedelta(seconds=offset_sec),
        source=source,
        protocol=protocol,
        operation=operation,
        payload_size=payload_size,
        payload=body,
    )


def scenarios() -> tuple[Scenario, ...]:
    """Корпус сценариев. Детерминирован: ни времени прогона, ни случайности внутри нет."""
    jump_bypass = Scenario(
        name="обход jump-сервера административным входом",
        event=_event(
            "gauge-jump-1",
            offset_sec=0,
            source=EventSource.AUTH_LOGS,
            protocol="SSH",
            operation="ADMIN_LOGIN",
            payload={"asset_id": "plc-99", "username": "root"},
        ),
        recent_events=(
            _event(
                "gauge-jump-0",
                offset_sec=-300,
                source=EventSource.AUTH_LOGS,
                protocol="SSH",
                operation="PING",
                payload={},
            ),
        ),
        tickets=(),
        graph_edges=(GraphEdge("ws-1", "plc-99", "ssh"),),
        polling_intervals_us=(1000.0, 1000.0, 4670.0, 21800.0),
        plc_hosts=frozenset({"plc-99"}),
    )

    polling_jitter = Scenario(
        name="дрожание периода опроса ПЛК",
        event=_event(
            "gauge-poll-1",
            offset_sec=0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="POLL",
            payload={"asset_id": "plc-99"},
            payload_size=8,
        ),
        recent_events=(),
        tickets=(),
        graph_edges=(GraphEdge("jump-01", "plc-99", "ssh"),),
        polling_intervals_us=(1000.0, 1020.0, 1060.0, 1120.0),
        plc_hosts=frozenset({"plc-99"}),
    )

    blind_command = Scenario(
        name="запись в катушку без предшествующего чтения",
        event=_event(
            "gauge-write-1",
            offset_sec=0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="WRITE_COIL",
            payload={"asset_id": "plc-01", "username": "eng.petrov"},
            payload_size=12,
        ),
        recent_events=(
            _event(
                "gauge-write-0",
                offset_sec=-60,
                source=EventSource.PLC_POLLING,
                protocol="MODBUS",
                operation="POLL",
                payload={"asset_id": "plc-01"},
                payload_size=8,
            ),
        ),
        tickets=(),
        graph_edges=(GraphEdge("ws-2", "plc-01", "modbus"),),
        polling_intervals_us=(1000.0, 1000.0, 1000.0, 1000.0),
        plc_hosts=frozenset({"plc-01"}),
    )

    # Наряд-допуск: тот же вход, но с организационным контекстом. Ветка сверки с нарядом —
    # отдельная, и вердикт по ней обязан быть так же неподвижен под маскированием.
    permitted = Scenario(
        name="та же запись, но по действующему наряду",
        event=_event(
            "gauge-permit-1",
            offset_sec=0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation="WRITE_COIL",
            payload={"asset_id": "plc-01", "username": "eng.petrov"},
            payload_size=12,
        ),
        recent_events=(),
        tickets=(
            demo_ticket_for_asset(
                "plc-01",
                start=T0 - timedelta(hours=1),
                end=T0 + timedelta(hours=1),
            ),
        ),
        graph_edges=(GraphEdge("ws-2", "plc-01", "modbus"),),
        polling_intervals_us=(1000.0, 1000.0, 1000.0, 1000.0),
        plc_hosts=frozenset({"plc-01"}),
    )

    degraded = Scenario(
        name="событие с неполными данными",
        event=_event(
            "gauge-dq-1",
            offset_sec=0,
            source=EventSource.SIEM,
            protocol="",
            operation="AUTH_FAILURE",
            payload={"asset_id": ""},
            payload_size=0,
        ),
        recent_events=(
            _event(
                "gauge-dq-0",
                offset_sec=-30,
                source=EventSource.SIEM,
                protocol="",
                operation="AUTH_FAILURE",
                payload={"asset_id": ""},
                payload_size=0,
            ),
        ),
        tickets=(),
        graph_edges=(),
        polling_intervals_us=(),
        plc_hosts=frozenset({"plc-01"}),
    )

    # Сценарий с непустыми наборами: перестановочный гвард (T2) на одноэлементных списках
    # тождественно зелен и ничего не проверяет, поэтому в корпусе обязан быть случай, где
    # переставлять действительно есть что.
    multi = Scenario(
        name="серия неуспешных аутентификаций с несколькими связями",
        event=_event(
            "gauge-multi-9",
            offset_sec=0,
            source=EventSource.AUTH_LOGS,
            protocol="SSH",
            operation="ADMIN_LOGIN",
            payload={"asset_id": "plc-01", "username": "admin.backup"},
        ),
        recent_events=tuple(
            _event(
                f"gauge-multi-{i}",
                offset_sec=-60 * (6 - i),
                source=EventSource.AUTH_LOGS,
                protocol="SSH",
                operation="AUTH_FAILURE",
                payload={"asset_id": "plc-01", "username": "admin.backup"},
            )
            for i in range(6)
        ),
        tickets=(
            demo_ticket_for_asset("plc-02", start=T0 - timedelta(hours=4), end=T0 - timedelta(hours=3)),
        ),
        graph_edges=(
            GraphEdge("ws-1", "plc-01", "ssh"),
            GraphEdge("ws-2", "plc-01", "modbus"),
            GraphEdge("jump-01", "ws-1", "rdp"),
        ),
        polling_intervals_us=(1000.0, 1000.0, 1000.0, 1000.0),
        plc_hosts=frozenset({"plc-01"}),
    )

    return (jump_bypass, polling_jitter, blind_command, permitted, degraded, multi)


def verdict_fingerprint(result: Any) -> dict[str, Any]:
    """Наблюдаемая часть вердикта, которая обязана быть инвариантна.

    Идентификатор дела и отметка создания сюда не входят: первый выдаёт `IdProviderPort`,
    вторая — `SystemClockPort`, и оба по определению меняются между прогонами. Проверяется
    то, что предъявляется как вывод: класс и балл риска, сработавшие инварианты, объяснение
    и качество данных.
    """
    case = result.suggested_case
    return {
        "risk_class": case.risk_class,
        # Балл округляется до девяти знаков: сравнение float на точное равенство ловило бы
        # перестановку слагаемых в сумме, а не изменение вердикта.
        "risk_score": round(float(result.risk_score), 9),
        "invariant_hits": sorted(result.invariant_hits),
        "xai_summary": case.xai_summary,
        "dq_score": round(float(result.data_quality.dq_score), 9),
        "dq_partial": bool(result.data_quality.partial_observability),
        "dq_reasons": sorted(result.data_quality.reasons),
        "trigger_operation": case.trigger_operation,
        "primary_asset_id": case.primary_asset_id,
    }
