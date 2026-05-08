from __future__ import annotations

from datetime import datetime, timezone

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.services.event_enrichment import apply_enrichment_rules
from takt.domain.services.telemetry_hints import apply_telemetry_hints


def _ev(payload: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="POLL",
        payload_size=1,
        payload=payload,
    )


def test_apply_enrichment_rules_disabled():
    ev = _ev({"segment": "AIR_GAP_L2", "is_new_peer": True})
    out = apply_enrichment_rules(ev, {"enabled": False, "air_gap_segments": ["AIR_GAP_L2"]})
    assert "new_node_airgap" not in out.payload


def test_apply_enrichment_rules_none_config():
    ev = _ev({})
    assert apply_enrichment_rules(ev, None) is ev


def test_apply_enrichment_segment_not_listed():
    rules = {"enabled": True, "air_gap_segments": ["OTHER"]}
    ev = _ev({"segment": "AIR_GAP_L2", "is_new_peer": True})
    out = apply_enrichment_rules(ev, rules)
    assert "new_node_airgap" not in out.payload


def test_apply_enrichment_new_peer_not_truthy():
    rules = {"enabled": True, "air_gap_segments": ["AIR_GAP_L2"]}
    ev = _ev({"segment": "air_gap_l2", "is_new_peer": "0"})
    out = apply_enrichment_rules(ev, rules)
    assert "new_node_airgap" not in out.payload


def test_apply_enrichment_is_new_peer_integer_one():
    rules = {"enabled": True, "air_gap_segments": ["SEG1"]}
    ev = _ev({"segment": "seg1", "is_new_peer": 1})
    out = apply_enrichment_rules(ev, rules)
    assert out.payload.get("new_node_airgap") is True


def test_apply_enrichment_is_new_peer_other_number_not_truthy():
    rules = {"enabled": True, "air_gap_segments": ["SEG1"]}
    ev = _ev({"segment": "seg1", "is_new_peer": 2})
    out = apply_enrichment_rules(ev, rules)
    assert "new_node_airgap" not in out.payload


def test_apply_enrichment_enabled_defaults_true_when_omitted():
    rules = {"air_gap_segments": ["AIR_GAP_L2"]}
    ev = _ev({"segment": "AIR_GAP_L2", "is_new_peer": "yes"})
    out = apply_enrichment_rules(ev, rules)
    assert out.payload.get("new_node_airgap") is True


def test_apply_enrichment_empty_air_gap_segments_list_noop():
    rules = {"enabled": True, "air_gap_segments": []}
    ev = _ev({"segment": "AIR_GAP_L2", "is_new_peer": True})
    out = apply_enrichment_rules(ev, rules)
    assert "new_node_airgap" not in out.payload


def test_telemetry_hints_noop_without_iec_fields():
    ev = _ev({"asset_id": "only-asset"})
    assert apply_telemetry_hints(ev) is ev


def test_telemetry_hints_coerces_existing_iec104_type_id():
    ev = _ev({"iec104_type_id": "45"})
    out = apply_telemetry_hints(ev)
    assert out.payload["iec104_type_id"] == 45


def test_telemetry_hints_drops_invalid_iec104_then_uses_alias():
    ev = _ev({"iec104_type_id": "n/a", "asdu_type": "13"})
    out = apply_telemetry_hints(ev)
    assert out.payload.get("iec104_type_id") == 13


def test_telemetry_hints_custom_alias_list():
    ev = _ev({"my_tid": "7"})
    rules = {"iec104_type_aliases": ["my_tid"]}
    out = apply_telemetry_hints(ev, enrichment_rules=rules)
    assert out.payload["iec104_type_id"] == 7


def test_telemetry_hints_skips_non_numeric_alias_then_uses_type_id():
    ev = _ev({"asdu_type": "nope", "type_id": "31"})
    out = apply_telemetry_hints(ev)
    assert out.payload.get("iec104_type_id") == 31


def test_telemetry_hints_skips_none_alias_value_then_coerces_next():
    ev = _ev({"asdu_type": None, "type_id": " 14 "})
    out = apply_telemetry_hints(ev)
    assert out.payload.get("iec104_type_id") == 14


def test_telemetry_hints_no_alias_match_returns_unchanged():
    ev = _ev({"foo": "bar"})
    out = apply_telemetry_hints(ev)
    assert "iec104_type_id" not in out.payload
