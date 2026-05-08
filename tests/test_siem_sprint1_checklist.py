"""
Интеграционные проверки чеклиста Спринта 1 (SIEM): структурный allowlist, DNS-rebinding в prod,
сегмент air-gap с внутренним webhook и записью в security_log.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import takt.interface_adapters.api.main as main_mod
from takt.infrastructure.config.weights_loader import load_risk_weights


def _patch_siem_allowlist(monkeypatch: pytest.MonkeyPatch, prefixes: list[str]) -> None:
    def _merged(path):
        w = dict(load_risk_weights(path))
        sw = dict(w.get("siem_webhook") or {})
        sw["allowed_url_prefixes"] = prefixes
        sw.setdefault("retries", 1)
        sw.setdefault("backoff_sec", 0.01)
        w["siem_webhook"] = sw
        return w

    monkeypatch.setattr(main_mod, "load_risk_weights", _merged)


def _demo_body() -> dict:
    return {
        "observed_at": "2026-05-03T12:00:00+00:00",
        "operation": "POLL",
        "asset_id": "plc-siem-check",
        "payload_size": 8,
    }


def test_forward_rejects_allowlist_suffix_attack_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "prod")
    _patch_siem_allowlist(monkeypatch, ["https://siem.internal.corp"])
    with TestClient(main_mod.create_app()) as client:
        cid = client.post("/assess", json=_demo_body()).json()["case_id"]
        r = client.post(
            "/integrations/siem/forward",
            json={
                "case_id": cid,
                "target_url": "https://siem.internal.corp.attacker.com/hook",
            },
        )
    assert r.status_code == 400


def test_forward_prod_rejects_dns_rebound_rfc1918(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "prod")
    _patch_siem_allowlist(monkeypatch, ["https://edge-siem.test"])
    monkeypatch.setattr(
        "takt.infrastructure.export.siem_webhook.default_resolve_tcp_addrs",
        lambda _h, _p: ["10.2.2.2"],
    )
    with TestClient(main_mod.create_app()) as client:
        cid = client.post("/assess", json=_demo_body()).json()["case_id"]
        r = client.post(
            "/integrations/siem/forward",
            json={"case_id": cid, "target_url": "https://edge-siem.test/hook"},
        )
    assert r.status_code == 400
    assert "10.2.2.2" in r.json()["detail"]


def test_forward_prod_rejects_dns_rebound_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "prod")
    _patch_siem_allowlist(monkeypatch, ["https://edge-siem.test"])
    monkeypatch.setattr(
        "takt.infrastructure.export.siem_webhook.default_resolve_tcp_addrs",
        lambda _h, _p: ["127.0.0.1"],
    )
    with TestClient(main_mod.create_app()) as client:
        cid = client.post("/assess", json=_demo_body()).json()["case_id"]
        r = client.post(
            "/integrations/siem/forward",
            json={"case_id": cid, "target_url": "https://edge-siem.test/hook"},
        )
    assert r.status_code == 400


def test_forward_airgap_internal_allowed_and_security_log_mutating(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "prod")
    monkeypatch.setenv("TAKT_PROFILE", "airgap")
    monkeypatch.setenv("TAKT_ALLOW_INTERNAL_WEBHOOK", "true")
    monkeypatch.setenv("TAKT_SECURITY_LOG_FILE", str(tmp_path / "sec.log"))
    _patch_siem_allowlist(monkeypatch, ["https://edge-siem.test"])
    monkeypatch.setattr(
        "takt.infrastructure.export.siem_webhook.default_resolve_tcp_addrs",
        lambda _h, _p: ["10.2.2.2"],
    )
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = lambda: None
    with patch("takt.infrastructure.export.siem_webhook.httpx.Client") as Client:
        inst = MagicMock()
        Client.return_value.__enter__.return_value = inst
        inst.post.return_value = ok
        with TestClient(main_mod.create_app()) as client:
            cid = client.post("/assess", json=_demo_body()).json()["case_id"]
            r = client.post(
                "/integrations/siem/forward",
                json={"case_id": cid, "target_url": "https://edge-siem.test/hook"},
            )
    assert r.status_code == 200
    lines = (tmp_path / "sec.log").read_text(encoding="utf-8").strip().splitlines()
    mut_paths: list[str] = []
    for line in lines:
        obj = json.loads(line)
        if obj.get("msgid") == "http_mutating":
            mut_paths.append(str(obj.get("structured_data", {}).get("path", "")))
    assert "/integrations/siem/forward" in mut_paths
