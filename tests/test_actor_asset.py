from __future__ import annotations

from datetime import UTC, datetime

from takt.domain.entities.actor import Actor
from takt.domain.entities.asset import Asset
from takt.domain.entities.event import EventSource, NormalizedEvent


def _ev(payload: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e1",
        observed_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="LOGIN",
        payload_size=1,
        payload=payload,
    )


def test_actor_from_event_prefers_actor_id_over_username():
    a = Actor.from_event(
        _ev({"actor_id": "svc-1", "username": "bob", "display_name": "Service"})
    )
    assert a.actor_id == "svc-1"
    assert a.display_name == "Service"
    assert a.attributes["username"] == "bob"


def test_actor_from_event_username_fallback():
    a = Actor.from_event(_ev({"username": "alice"}))
    assert a.actor_id == "alice"
    assert a.display_name == "alice"


def test_actor_from_event_unknown_without_identity():
    a = Actor.from_event(_ev({}))
    assert a.actor_id == "unknown"
    assert a.display_name == "unknown"


def test_asset_dataclass_fields():
    ast = Asset(
        asset_id="plc-7",
        segment="L2",
        is_air_gapped=True,
        metadata={"role": "plc"},
    )
    assert ast.asset_id == "plc-7"
    assert ast.is_air_gapped is True
    assert ast.metadata["role"] == "plc"
