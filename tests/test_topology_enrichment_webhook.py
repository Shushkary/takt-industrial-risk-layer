from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import InvariantContext, collect_extended_invariants
from takt.domain.services.event_enrichment import apply_enrichment_rules
from takt.infrastructure.config.settings_helpers import (
    enrichment_from_weights,
    graph_edges_from_weights,
    siem_webhook_retries,
    topology_from_weights,
)
from takt.infrastructure.export.siem_webhook import post_case_to_webhook_sync


def test_topology_from_weights_custom():
    j, p = topology_from_weights(
        {"topology": {"jump_host": "jmp-prod", "plc_hosts": ["plc-a", "plc-b"]}}
    )
    assert j == "jmp-prod"
    assert p == frozenset({"plc-a", "plc-b"})


def test_topology_from_weights_defaults_when_missing_or_invalid():
    j, p = topology_from_weights({})
    assert j == "jump-01"
    assert p == frozenset({"plc-01", "plc-02"})
    j2, p2 = topology_from_weights({"topology": "not-a-dict"})
    assert (j2, p2) == (j, p)


def test_topology_from_weights_empty_plc_hosts_falls_back():
    j, p = topology_from_weights({"topology": {"jump_host": "j-only", "plc_hosts": []}})
    assert j == "j-only"
    assert p == frozenset({"plc-01", "plc-02"})


def test_graph_edges_from_weights_demo_list():
    w = {"topology": {"demo_graph_edges": [{"src": "a", "dst": "b", "kind": "ssh"}]}}
    assert graph_edges_from_weights(w, plc_hosts=frozenset({"z"})) == [
        GraphEdge(src="a", dst="b", kind="ssh")
    ]


def test_graph_edges_skips_invalid_rows_keeps_valid():
    w = {
        "topology": {
            "demo_graph_edges": [
                {"src": "", "dst": "b"},
                {"src": "x", "dst": "y"},
                "not-a-dict",
            ]
        }
    }
    assert graph_edges_from_weights(w, plc_hosts=frozenset()) == [
        GraphEdge(src="x", dst="y", kind="tcp")
    ]


def test_graph_edges_fallback_uses_lexicographically_first_plc():
    edges = graph_edges_from_weights({}, plc_hosts=frozenset({"zebra", "alpha"}))
    assert edges == [GraphEdge(src="eng-workstation", dst="alpha", kind="ssh")]


def test_enrichment_sets_new_node_flag():
    rules = {"enabled": True, "air_gap_segments": ["AIR_GAP_L2"]}
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.NETWORK,
        protocol="TCP",
        operation="HELLO",
        payload_size=1,
        payload={"segment": "air_gap_l2", "is_new_peer": "true"},
    )
    out = apply_enrichment_rules(ev, rules)
    assert out.payload["new_node_airgap"] is True


def test_enrichment_from_weights_none():
    assert enrichment_from_weights({}) is None


def test_enrichment_from_weights_returns_section():
    section = {"enabled": True, "air_gap_segments": ["S1"]}
    assert enrichment_from_weights({"enrichment": section}) is section


def test_siem_webhook_retry_defaults():
    r, b = siem_webhook_retries({})
    assert r == 3 and b == 0.35


def test_siem_webhook_retries_from_yaml_section():
    r, b = siem_webhook_retries({"siem_webhook": {"retries": 5, "backoff_sec": 1.25}})
    assert r == 5 and b == 1.25


def test_iec104_disallowed_type():
    ctx = InvariantContext(iec104_disallowed_type_ids=frozenset({9, 13}))
    ev = NormalizedEvent(
        event_id="1",
        observed_at=datetime.now(timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="IEC104",
        operation="DATA",
        payload_size=4,
        payload={"asset_id": "x", "iec104_type_id": 9},
    )
    hits = collect_extended_invariants(ev, (), ctx)
    assert InvariantId.ILLEGAL_FUNCTION_CODE.value in hits


def test_webhook_sync_retries(monkeypatch):
    case = Case(
        case_id="c1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    n = {"i": 0}

    def client_factory(*_a, **_kw):
        inst = MagicMock()

        def _post(*_a, **_kw):
            n["i"] += 1
            if n["i"] == 1:
                raise httpx.ConnectError("fail", request=MagicMock())
            ok = MagicMock()
            ok.status_code = 202
            ok.raise_for_status = MagicMock()
            return ok

        inst.post = _post
        cm = MagicMock()
        cm.__enter__.return_value = inst
        cm.__exit__.return_value = False
        return cm

    monkeypatch.setattr("takt.infrastructure.export.siem_webhook.httpx.Client", client_factory)
    monkeypatch.setattr("takt.infrastructure.export.siem_webhook.time.sleep", lambda *_: None)

    code = post_case_to_webhook_sync(case, "http://127.0.0.1/ingest", retries=3, backoff_sec=0.01)
    assert code == 202
    assert n["i"] == 2


def test_webhook_sync_retries_exhausted_raises(monkeypatch):
    case = Case(
        case_id="c-fail",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    n = {"i": 0}

    def client_factory(*_a, **_kw):
        inst = MagicMock()

        def _post(*_a, **_kw):
            n["i"] += 1
            raise httpx.ConnectError("fail", request=MagicMock())

        inst.post = _post
        cm = MagicMock()
        cm.__enter__.return_value = inst
        cm.__exit__.return_value = False
        return cm

    monkeypatch.setattr("takt.infrastructure.export.siem_webhook.httpx.Client", client_factory)
    monkeypatch.setattr("takt.infrastructure.export.siem_webhook.time.sleep", lambda *_: None)

    with pytest.raises(httpx.ConnectError):
        post_case_to_webhook_sync(case, "http://127.0.0.1/ingest", retries=2, backoff_sec=0.01)
    assert n["i"] == 2
