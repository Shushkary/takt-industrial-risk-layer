"""«Новый узел в air-gap» срабатывает только при объявленном реестре адресов.

Прецедент: активная ветка правила сравнивала адрес события с адресами последних событий
буфера контекста (64 события). В изолированном сегменте из нескольких узлов это работает,
в обычной сети из сотен узлов — объявляет новым почти каждый адрес. На фикстуре INC-002
правило давало 82 срабатывания из 121 кейса: шумовой пол вместо признака.

Правило, которое нечем проверить, молчит. Путь по явному признаку от внешнего средства
обнаружения (`payload["new_node_airgap"]`) сохранён — им пользуется обогащение телеметрии.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import InvariantContext
from takt.domain.invariants.rule_predicates import PREDICATE_REGISTRY
from takt.domain.invariants.rule_spec import InvariantRuleSpec

_START = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)
_PREDICATE = PREDICATE_REGISTRY[InvariantId.NEW_NODE_AIRGAP.value]

_SPEC = InvariantRuleSpec(
    id=InvariantId.NEW_NODE_AIRGAP.value,
    block_key="topology",
    context_window_events=5,
    experimental=False,
    params={},
    predicate_ref=f"builtin:{InvariantId.NEW_NODE_AIRGAP.value}",
    inputs=(),
    severity_curve=None,
)


def _event(event_id: str, *, minutes: int = 0, payload: dict | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=_START + timedelta(minutes=minutes),
        source=EventSource.SIEM,
        protocol="siem",
        operation="LOGON_SUCCESS",
        payload_size=10,
        payload=payload or {},
    )


def _fires(event: NormalizedEvent, recent: list[NormalizedEvent], ctx: InvariantContext) -> bool:
    return bool(_PREDICATE(event, recent, ctx, _SPEC))


def test_silent_without_declared_registry() -> None:
    """Без реестра адресов правило молчит, даже если адрес не встречался раньше."""
    recent = [_event(f"bg-{i}", minutes=i, payload={"src_ip": f"10.10.1.{i}"}) for i in range(5)]
    event = _event("new", minutes=6, payload={"src_ip": "10.10.9.77"})
    assert _fires(event, recent, InvariantContext()) is False


def test_fires_for_address_outside_declared_registry() -> None:
    """С реестром правило работает по назначению: адрес вне реестра — новый узел."""
    ctx = InvariantContext(airgap_known_addresses=frozenset({"10.10.1.1", "10.10.1.2"}))
    assert _fires(_event("new", payload={"src_ip": "10.10.9.77"}), [], ctx) is True


def test_silent_for_address_inside_declared_registry() -> None:
    ctx = InvariantContext(airgap_known_addresses=frozenset({"10.10.1.1", "10.10.1.2"}))
    assert _fires(_event("known", payload={"src_ip": "10.10.1.2"}), [], ctx) is False


def test_mac_is_checked_against_the_same_registry() -> None:
    ctx = InvariantContext(airgap_known_addresses=frozenset({"aa:bb:cc:dd:ee:01"}))
    assert _fires(_event("known", payload={"mac": "aa:bb:cc:dd:ee:01"}), [], ctx) is False
    assert _fires(_event("new", payload={"mac": "aa:bb:cc:dd:ee:99"}), [], ctx) is True


def test_explicit_flag_from_detection_tool_still_works_without_registry() -> None:
    """Внешнее средство обнаружения уже вынесло вывод — реестр для этого не нужен."""
    event = _event("flagged", payload={"new_node_airgap": True, "src_ip": "10.10.9.77"})
    assert _fires(event, [], InvariantContext()) is True
