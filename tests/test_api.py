from __future__ import annotations

import os
import socket
import sys
from importlib.metadata import version
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from takt.domain.entities.event import EventSource
from takt.domain.invariants.catalog import InvariantId, invariant_titles_by_id
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.interface_adapters.api.main import create_app


def test_assess_persist_case_false_skips_repo():
    c = TestClient(create_app())
    assert c.get("/cases/stats").json()["total"] == 0
    body = {
        "observed_at": "2026-04-30T22:00:00+00:00",
        "operation": "READ",
        "asset_id": "plc-dry",
        "persist_case": False,
    }
    r = c.post("/assess", json=body)
    assert r.status_code == 200
    assert c.get("/cases/stats").json()["total"] == 0
    assert c.get(f"/cases/{r.json()['case_id']}").status_code == 404


def test_assess_persist_case_false_merge_leaves_repo_unchanged():
    c = TestClient(create_app())
    base = {
        "observed_at": "2026-04-30T21:00:00+00:00",
        "operation": "READ",
        "asset_id": "plc-merge-dry",
    }
    r1 = c.post("/assess", json=base)
    assert r1.status_code == 200
    cid = r1.json()["case_id"]
    d1 = c.get(f"/cases/{cid}").json()
    r2 = c.post("/assess", json={**base, "persist_case": False})
    assert r2.status_code == 200
    assert r2.json()["merged_into_existing"] is True
    assert r2.json()["case_id"] == cid
    d2 = c.get(f"/cases/{cid}").json()
    assert d2["event_ids"] == d1["event_ids"]


def test_assess_demo_deprecated_alias_merges_like_assess():
    c = TestClient(create_app())
    payload = {
        "observed_at": "2026-04-30T23:00:00+00:00",
        "operation": "POLL",
        "asset_id": "plc-alias-demo",
    }
    a = c.post("/assess", json=payload)
    d = c.post("/assess/demo", json=payload)
    assert a.status_code == d.status_code == 200
    assert d.json()["merged_into_existing"] is True
    assert a.json()["case_id"] == d.json()["case_id"]


def test_get_case_detail_invariant_hit_records_have_timestamps():
    """Спринт 2: карточка содержит **invariant_hit_records** с полем **ts** для каждого срабатывания."""
    c = TestClient(create_app())
    r = c.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-hit-ts",
        },
    )
    assert r.status_code == 200
    detail = c.get(f"/cases/{r.json()['case_id']}").json()
    for rec in detail["invariant_hit_records"]:
        assert rec.get("ts")


def test_merge_via_api_preserves_union_of_invariant_hit_records():
    """Спринт 2: после merge объединяются журналы **invariant_hit_records** (по паре invariant_id+event_ref)."""
    c = TestClient(create_app())
    base_asset = "plc-hit-merge"
    body1 = {"observed_at": "2026-05-10T10:00:00+00:00", "operation": "READ", "asset_id": base_asset}
    r1 = c.post("/assess", json=body1)
    cid = r1.json()["case_id"]
    keys1 = {(x["invariant_id"], x["event_ref"]) for x in c.get(f"/cases/{cid}").json()["invariant_hit_records"]}
    body2 = {**body1, "observed_at": "2026-05-10T10:00:30+00:00"}
    r2 = c.post("/assess", json=body2)
    assert r2.json()["merged_into_existing"] is True
    keys2 = {(x["invariant_id"], x["event_ref"]) for x in c.get(f"/cases/{cid}").json()["invariant_hit_records"]}
    assert keys2 >= keys1


def test_list_cases_filter_asset_and_fingerprint():
    client = TestClient(create_app())
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-filter-test",
        },
    )
    assert r.status_code == 200
    cid = r.json()["case_id"]
    detail = client.get(f"/cases/{cid}").json()
    fp = detail["fingerprint"]
    by_asset = client.get("/cases", params={"primary_asset_id": "PLC-FILTER-TEST"}).json()
    assert len(by_asset) == 1 and by_asset[0]["case_id"] == cid
    by_fp = client.get("/cases", params={"fingerprint": fp}).json()
    assert len(by_fp) == 1 and by_fp[0]["fingerprint"] == fp
    if len(fp) >= 4:
        by_pfx = client.get("/cases", params={"fingerprint_prefix": fp[:4].lower()}).json()
        assert any(c["case_id"] == cid for c in by_pfx)


def test_cases_stats_empty_and_after_assess():
    client = TestClient(create_app())
    empty = client.get("/cases/stats").json()
    assert empty["total"] == 0
    assert empty["open"] == 0
    assert empty["by_status"] == {}
    assert empty["by_risk_class"] == {}
    assert empty["avg_risk_score"] == 0.0
    assert empty["avg_dq_score"] == 0.0
    assert empty["dq_partial_count"] == 0
    assert empty["normalized_events_total"] == 0
    assert empty["distinct_invariant_hits"] == 0
    assert empty["invariant_hits_occurrences_total"] == 0
    assert empty["by_last_event_source"] == {}
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:30:00+00:00",
            "operation": "READ",
            "asset_id": "plc-stats",
        },
    )
    s = client.get("/cases/stats").json()
    assert s["total"] == 1
    assert s["open"] == 1
    assert s["by_status"].get("NEW") == 1
    assert s["by_risk_class"]
    assert sum(s["by_risk_class"].values()) == 1
    assert 0.0 <= s["avg_risk_score"] <= 1.0
    assert 0.0 <= s["avg_dq_score"] <= 1.0
    assert isinstance(s["dq_partial_count"], int)
    assert s["normalized_events_total"] == 1
    assert s["by_last_event_source"] == {"plc_polling": 1}
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:31:00+00:00",
            "operation": "READ",
            "asset_id": "plc-stats",
        },
    )
    s2 = client.get("/cases/stats").json()
    assert s2["total"] == 1
    assert s2["normalized_events_total"] == 2
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T21:32:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-stats-inv",
            "payload": {"trust_index_drop": 1},
        },
    )
    s3 = client.get("/cases/stats").json()
    assert s3["total"] == 2
    assert s3["distinct_invariant_hits"] >= 1
    assert s3["invariant_hits_occurrences_total"] >= 1
    assert s3["by_last_event_source"].get("plc_polling", 0) >= 1


def test_case_detail_and_siem_export_include_data_quality():
    client = TestClient(create_app())
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-dq-api",
        },
    )
    assert r.status_code == 200
    cid = r.json()["case_id"]
    detail = client.get(f"/cases/{cid}").json()
    assert "dq_score" in detail and 0.0 <= detail["dq_score"] <= 1.0
    assert "dq_partial" in detail
    assert "dq_reasons" in detail and isinstance(detail["dq_reasons"], list)
    assert detail["last_event_source"] == "plc_polling"
    siem = client.get(f"/cases/{cid}/export/siem.json").json()
    assert "data_quality" in siem
    assert siem["last_event_source"] == "plc_polling"
    assert siem["data_quality"]["dq_score"] == detail["dq_score"]
    assert siem["pdf_evidence"] is None
    pdf = client.get(f"/cases/{cid}/export.pdf")
    assert pdf.status_code == 200
    siem_after_pdf = client.get(f"/cases/{cid}/export/siem.json").json()
    assert siem_after_pdf["pdf_evidence"]["sha256"] == pdf.headers["x-takt-pdf-sha256"]
    assert siem_after_pdf["pdf_evidence"]["generated_at"]


def test_api_audit_ledger_verify_endpoint_for_case():
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-08T10:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-ledger-api",
        },
    )
    cid = created.json()["case_id"]
    check = client.get(f"/cases/{cid}/audit-ledger/verify")
    assert check.status_code == 501


def test_api_operation_audit_ledger_verify_endpoint():
    client = TestClient(create_app())
    check = client.get("/audit-ledger/operations/verify")
    assert check.status_code == 501


def test_health_includes_case_counts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TAKT_REQUEST_ID_HEADER", raising=False)
    monkeypatch.delenv("TAKT_FORENSIC_CRYPTO_MODE", raising=False)
    client = TestClient(create_app())
    h = client.get("/health").json()
    assert h["status"] == "ok"
    assert h["version"] == version("takt-industrial-risk-layer")
    assert h["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    assert h["python_implementation"] == sys.implementation.name
    assert h["process_id"] == os.getpid()
    assert h["hostname"] == socket.gethostname()
    assert h["platform"] == sys.platform
    assert h["python_executable"] == sys.executable
    assert h["working_directory"] == os.getcwd()
    assert h["api_log_level"] in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "NOTSET")
    assert h["uptime_seconds"] >= 0.0
    datetime.fromisoformat(h["booted_at_utc"])
    assert h["api_key_enabled"] is False
    assert h["auth"]["mode"] == "disabled"
    assert h["siem"]["allowlist_mode"] == "structural"
    assert h["siem"]["profile"] == "dev"
    assert h["proxy"]["trusted_count"] == 0
    assert h["cors_enabled"] is False
    assert h["hsts_enabled"] is False
    assert h["gzip_minimum_size_bytes"] == 512
    assert h["openapi_servers_count"] == 0
    assert h["case_storage"] == "memory"
    assert h["expected_behavior_storage"] == "memory"
    assert "sqlite_schema_version" not in h
    assert "sqlite_busy_timeout_ms" not in h
    assert "max_request_body_bytes" not in h
    assert "slow_request_log_threshold_sec" not in h
    assert h["cases_total"] == 0
    assert h["cases_open"] == 0
    assert h["event_window_len"] == 0
    assert h["ingest_trust_sources"] == 5
    assert h["ingest_trust_by_source"]["plc_polling"] == 1.0
    assert h["ingest_trust_by_source"]["unknown"] == 0.5
    assert h["full_json_max_cases"] == 10_000
    assert h["ingest_event_window_max"] == 64
    assert h["ingest_recent_for_context"] == 24
    assert h["ingest_batch_max_events"] == 100
    assert h["cases_list_max_limit"] == 1000
    assert h["cases_list_default_sort"] == "risk_score_desc"
    assert h["siem_webhook_retries"] == 3
    assert h["siem_webhook_backoff_sec"] == 0.35
    assert h["siem_webhook_allowlist_prefixes_count"] == 0
    assert h["export_pdf_unicode_font_configured"] is False
    assert h["prometheus_metrics_enabled"] is False
    assert h["forensic_crypto_mode"] == "mvp"
    assert h["forensic_strict_ready"] is True
    assert h["forensic_strict_missing"] == []
    assert "build_revision" not in h
    assert "request_id_alternate_header" not in h
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-z",
        },
    )
    h2 = client.get("/health").json()
    assert h2["uptime_seconds"] >= h["uptime_seconds"]
    assert h2["booted_at_utc"] == h["booted_at_utc"]
    assert h2["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    assert h2["python_implementation"] == sys.implementation.name == h["python_implementation"]
    assert h2["process_id"] == os.getpid() == h["process_id"]
    assert h2["hostname"] == socket.gethostname() == h["hostname"]
    assert h2["platform"] == sys.platform == h["platform"]
    assert h2["python_executable"] == sys.executable == h["python_executable"]
    assert h2["working_directory"] == os.getcwd() == h["working_directory"]
    assert h2["cases_total"] >= 1
    assert h2["cases_open"] >= 1
    assert h2["ingest_trust_sources"] == 5
    assert len(h2["ingest_trust_by_source"]) == 5
    assert h2["full_json_max_cases"] == 10_000
    assert h2["ingest_batch_max_events"] == 100
    assert h2["cases_list_max_limit"] == 1000
    assert h2["cases_list_default_sort"] == "risk_score_desc"
    assert h2["gzip_minimum_size_bytes"] == 512
    assert h2["openapi_servers_count"] == 0
    assert h2["siem_webhook_retries"] == 3
    assert h2["siem_webhook_backoff_sec"] == 0.35
    assert h2["siem_webhook_allowlist_prefixes_count"] == 0
    assert h2["export_pdf_unicode_font_configured"] is False
    assert h2["prometheus_metrics_enabled"] is False


def test_health_export_pdf_unicode_font_configured_when_yaml_has_font(tmp_path, monkeypatch):
    default_cfg = Path(__file__).resolve().parents[1] / "config" / "risk_weights.yaml"
    font_file = tmp_path / "font.ttf"
    font_file.write_bytes(b"x")

    def fake_load(_p):
        d = load_risk_weights(default_cfg)
        exp = dict(d.get("export") or {})
        exp["pdf_unicode_font"] = str(font_file)
        return {**d, "export": exp}

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    h = TestClient(create_app()).get("/health").json()
    assert h["export_pdf_unicode_font_configured"] is True


def test_live_endpoint_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TAKT_BUILD_REVISION", raising=False)
    client = TestClient(create_app())
    r = client.get("/live")
    assert r.status_code == 200
    j = r.json()
    assert j["live"] is True
    assert j["product"] == "TAKT-MVP"
    assert "version" in j
    assert "build_revision" not in j


def test_ready_endpoint_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TAKT_BUILD_REVISION", raising=False)
    monkeypatch.delenv("TAKT_FORENSIC_CRYPTO_MODE", raising=False)
    client = TestClient(create_app())
    r = client.get("/ready")
    assert r.status_code == 200
    j = r.json()
    assert j["ready"] is True
    assert j["case_storage"] == "memory"
    assert j["expected_behavior_storage"] == "memory"
    assert j["forensic_crypto_mode"] == "mvp"
    assert j["forensic_strict_ready"] is True
    assert j["forensic_strict_missing"] == []
    assert "build_revision" not in j


def test_ready_endpoint_fails_when_gost_strict_missing_signer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.delenv("TAKT_FORENSIC_SIGN_URL", raising=False)
    monkeypatch.delenv("TAKT_FORENSIC_VERIFY_URL", raising=False)
    client = TestClient(create_app())
    r = client.get("/ready")
    assert r.status_code == 503
    assert "forensic_strict_misconfigured" in r.json()["detail"]


def test_forensic_exports_return_503_when_strict_signer_unavailable(monkeypatch: pytest.MonkeyPatch):
    def _fake_post(url, json, timeout):  # noqa: ANN001
        if str(url).endswith("/sign"):
            raise RuntimeError("signer unavailable")
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "dev-secret")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    client = TestClient(create_app(), raise_server_exceptions=False)
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-01",
            "persist_case": True,
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]
    manifest = client.get(f"/cases/{case_id}/forensic-bundle/manifest")
    assert manifest.status_code == 503
    assert "forensic_signing_unavailable" in manifest.json()["detail"]
    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 503
    assert "forensic_signing_unavailable" in archive.json()["detail"]


def test_cases_export_full_json_matches_detail():
    client = TestClient(create_app())
    r_empty = client.get("/cases/export/full.json")
    empty = r_empty.json()
    assert r_empty.headers.get("x-total-count") == "0"
    assert empty["count"] == 0
    assert empty["total_in_repo"] == 0
    assert empty["offset"] == 0
    assert empty["cases"] == []
    assert "exported_at" in empty
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T21:40:00+00:00",
            "operation": "READ",
            "asset_id": "plc-export-full",
        },
    )
    r_body = client.get("/cases/export/full.json")
    body = r_body.json()
    assert r_body.headers.get("x-total-count") == str(body["total_in_repo"])
    assert body["count"] == 1
    assert body["total_in_repo"] == 1
    case = body["cases"][0]
    cid = case["case_id"]
    detail = client.get(f"/cases/{cid}").json()
    for key in (
        "case_id",
        "risk_class",
        "risk_score",
        "fingerprint",
        "last_event_source",
        "invariant_hits",
        "event_ids",
    ):
        assert case[key] == detail[key]


def test_cases_export_full_json_limit_and_offset():
    client = TestClient(create_app())
    for i, aid in enumerate(["plc-ex-a", "plc-ex-b"]):
        client.post(
            "/assess",
            json={
                "observed_at": f"2026-04-30T23:{i:02d}:00+00:00",
                "operation": "READ",
                "asset_id": aid,
            },
        )
    r_full = client.get("/cases/export/full.json")
    full = r_full.json()
    assert r_full.headers.get("link") is None
    assert r_full.headers.get("x-total-count") == "2"
    assert full["total_in_repo"] == 2
    assert full["count"] == 2
    r_one = client.get("/cases/export/full.json", params={"limit": 1})
    one = r_one.json()
    assert r_one.headers.get("x-total-count") == "2"
    assert one["total_in_repo"] == 2
    assert one["count"] == 1
    assert one["limit"] == 1
    r_page2 = client.get("/cases/export/full.json", params={"offset": 1, "limit": 1})
    page2 = r_page2.json()
    assert r_page2.headers.get("x-total-count") == "2"
    assert page2["total_in_repo"] == 2
    assert page2["count"] == 1
    assert page2["offset"] == 1
    assert one["cases"][0]["primary_asset_id"] != page2["cases"][0]["primary_asset_id"]


def test_cases_export_full_json_pagination_link():
    import re

    client = TestClient(create_app())
    for i, aid in enumerate(["plc-ex2-a", "plc-ex2-b"]):
        client.post(
            "/assess",
            json={
                "observed_at": f"2026-05-08T10:{i:02d}:00+00:00",
                "operation": "READ",
                "asset_id": aid,
            },
        )
    r0 = client.get("/cases/export/full.json", params={"limit": 1, "offset": 0})
    assert r0.status_code == 200
    link0 = r0.headers.get("link") or ""
    assert "/cases/export/full.json" in link0
    assert 'rel="next"' in link0
    assert "rel=\"prev\"" not in link0
    m = re.search(r"<([^>]+)>\s*;\s*rel=\"next\"", link0)
    assert m
    r1 = client.get(m.group(1))
    assert r1.status_code == 200
    assert r1.json()["total_in_repo"] == 2
    link1 = r1.headers.get("link") or ""
    assert 'rel="prev"' in link1
    assert 'rel="next"' not in link1


def test_cases_export_limit_exceeds_max_422():
    client = TestClient(create_app())
    assert client.get("/cases/export/full.json", params={"limit": 10001}).status_code == 422


def test_cases_import_full_json_roundtrip():
    c1 = TestClient(create_app())
    c1.post(
        "/assess",
        json={
            "observed_at": "2026-05-04T10:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-import-rt",
        },
    )
    exp = c1.get("/cases/export/full.json").json()
    assert exp["count"] >= 1
    c2 = TestClient(create_app())
    imp = c2.post("/cases/import/full.json", json={"cases": exp["cases"], "mode": "upsert"})
    assert imp.status_code == 200
    assert imp.json()["imported"] == exp["count"]
    assert imp.json()["skipped"] == 0
    listed = c2.get("/cases").json()
    assert len(listed) == exp["count"]
    cid = exp["cases"][0]["case_id"]
    d1 = exp["cases"][0]
    d2 = c2.get(f"/cases/{cid}").json()
    assert d2["primary_asset_id"] == d1["primary_asset_id"]
    assert d2["fingerprint"] == d1["fingerprint"]


def test_cases_import_skip_existing():
    c = TestClient(create_app())
    c.post(
        "/assess",
        json={
            "observed_at": "2026-05-04T11:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-skip",
        },
    )
    exp = c.get("/cases/export/full.json").json()
    r1 = c.post("/cases/import/full.json", json={"cases": exp["cases"], "mode": "skip_existing"})
    assert r1.json()["imported"] == 0
    assert r1.json()["skipped"] == 1


def test_cases_import_invalid_status_400():
    c = TestClient(create_app())
    bad = {
        "cases": [
            {
                "case_id": "x",
                "status": "NOT_A_STATUS",
                "title": "t",
                "risk_class": "LOW",
                "risk_score": 0.1,
                "event_ids": ["e1"],
                "invariant_hits": [],
                "invariant_details": [],
                "xai_summary": "",
                "audit_log": [],
                "fingerprint": "a|b|c",
                "primary_asset_id": "b",
                "trigger_operation": "c",
                "last_event_source": "plc_polling",
                "created_at": "2026-05-04T12:00:00+00:00",
                "dq_score": 1.0,
                "dq_partial": False,
                "dq_reasons": [],
            }
        ],
        "mode": "upsert",
    }
    r = c.post("/cases/import/full.json", json=bad)
    assert r.status_code == 400


def test_cases_import_cases_list_max_422():
    c = TestClient(create_app())
    # minimal valid CaseDetail-like dicts would be huge; rely on pydantic max_length by empty over-limit hack
    # Using explicit oversized list: 10001 minimal items
    stub = {
        "case_id": "a",
        "status": "NEW",
        "title": "t",
        "risk_class": "LOW",
        "risk_score": 0.0,
        "event_ids": [],
        "invariant_hits": [],
        "invariant_details": [],
        "xai_summary": "",
        "audit_log": [],
        "fingerprint": "",
        "primary_asset_id": "",
        "trigger_operation": "READ",
        "last_event_source": "",
        "created_at": "2026-05-04T12:00:00+00:00",
        "dq_score": 1.0,
        "dq_partial": False,
        "dq_reasons": [],
    }
    body = {"cases": [dict(stub, case_id=str(i)) for i in range(10001)], "mode": "upsert"}
    r = c.post("/cases/import/full.json", json=body)
    assert r.status_code == 422


def test_events_batch_ingest():
    client = TestClient(create_app())
    r = client.post(
        "/events/batch",
        json={
            "events": [
                {
                    "observed_at": "2026-04-30T10:00:00+00:00",
                    "operation": "POLL",
                    "asset_id": "plc-batch-a",
                },
                {
                    "observed_at": "2026-04-30T10:00:01+00:00",
                    "operation": "POLL",
                    "asset_id": "plc-batch-b",
                },
            ]
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert len(body["results"]) == 2
    assert all("case_id" in x for x in body["results"])
    assert client.get("/health").json()["event_window_len"] == 2


def test_invariants_catalog_http():
    client = TestClient(create_app())
    r = client.get("/invariants")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == len(InvariantId)
    ids = {x["id"] for x in body}
    assert ids == {m.value for m in InvariantId}
    assert all("block_key" in x and "title_ru" in x for x in body)
    assert all(x["experimental"] is False for x in body)


def test_invariants_catalog_filter_block_key():
    client = TestClient(create_app())
    r = client.get("/invariants", params={"block_key": "topology"})
    assert r.status_code == 200
    assert all(x["block_key"] == "topology" for x in r.json())
    assert client.get("/invariants", params={"block_key": "nope"}).status_code == 400


def test_catalog_event_sources():
    client = TestClient(create_app())
    r = client.get("/catalog/event-sources")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == len(EventSource)
    by_id = {x["id"] for x in rows}
    assert by_id == {s.value for s in EventSource}
    trust_by = {x["id"]: x["ingest_trust"] for x in rows}
    assert trust_by["plc_polling"] == 1.0
    assert trust_by["unknown"] == 0.5


def test_list_cases_title_contains():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T18:00:00+00:00",
            "operation": "UNIQUE_TITLE_MARKER_OP",
            "asset_id": "plc-title-q",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T18:01:00+00:00",
            "operation": "PING",
            "asset_id": "plc-other",
        },
    )
    q = client.get("/cases", params={"title_contains": "unique_title_marker"}).json()
    assert len(q) == 1
    assert q[0]["primary_asset_id"] == "plc-title-q"


def test_list_cases_case_id_prefix():
    client = TestClient(create_app())
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T19:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-prefix-test",
        },
    )
    assert r.status_code == 200
    cid = r.json()["case_id"]
    prefix = cid[:4]
    rows = client.get("/cases", params={"case_id_prefix": prefix}).json()
    assert any(row["case_id"] == cid for row in rows)
    assert client.get("/cases", params={"case_id_prefix": "zzzz"}).json() == []


def test_list_cases_trigger_operation_contains():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T17:00:00+00:00",
            "operation": "UNIQUE_TRIG_OP_XYZ",
            "asset_id": "plc-trig-a",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T17:01:00+00:00",
            "operation": "PING",
            "asset_id": "plc-trig-b",
        },
    )
    rows = client.get("/cases", params={"trigger_operation_contains": "unique_trig_op"}).json()
    assert len(rows) == 1
    assert rows[0]["trigger_operation"] == "UNIQUE_TRIG_OP_XYZ"
    assert rows[0]["primary_asset_id"] == "plc-trig-a"


def test_list_cases_min_invariant_hits_and_xai_contains():
    client = TestClient(create_app())
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T16:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-inv-xai",
            "payload": {"trust_index_drop": 1},
        },
    )
    one = client.get("/cases", params={"min_invariant_hits": 1}).json()
    assert len(one) >= 1
    assert all(c["invariant_hits_count"] >= 1 for c in one)
    assert client.get("/cases", params={"min_invariant_hits": 50}).json() == []

    # `xai_contains` ищет по тексту объяснения, а объяснение читает человек: с 2026-08-21
    # инварианты в нём называются, а не перечисляются кодами. Фильтр по идентификатору правила —
    # это отдельный `has_invariant`, и он остаётся точным способом отобрать дела по правилу.
    title = invariant_titles_by_id()["trust_index_drop"]
    xai_rows = client.get("/cases", params={"xai_contains": title}).json()
    assert len(xai_rows) >= 1
    assert all("plc-inv-xai" == c["primary_asset_id"] for c in xai_rows)
    assert client.get("/cases", params={"xai_contains": "trust_index_drop"}).json() == []

    by_id = client.get("/cases", params={"has_invariant": "trust_index_drop"}).json()
    assert len(by_id) >= 1
    assert all("plc-inv-xai" == c["primary_asset_id"] for c in by_id)


def test_list_cases_max_invariant_hits_and_sort_invariant_hits():
    client = TestClient(create_app())
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T10:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-light-inv",
            "payload": {"trust_index_drop": 1},
        },
    )
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T10:01:00+00:00",
            "operation": "PING",
            "asset_id": "plc-heavy-inv",
            "payload": {
                "trust_index_drop": 1,
                "new_node_airgap": True,
                "reply_without_prior_request": True,
            },
        },
    )
    desc = client.get("/cases", params={"sort": "invariant_hits_desc"}).json()
    counts = [c["invariant_hits_count"] for c in desc]
    assert counts == sorted(counts, reverse=True)
    asc = client.get("/cases", params={"sort": "invariant_hits_asc"}).json()
    asc_counts = [c["invariant_hits_count"] for c in asc]
    assert asc_counts == sorted(asc_counts)
    capped = client.get("/cases", params={"max_invariant_hits": 2}).json()
    assert all(c["invariant_hits_count"] <= 2 for c in capped)
    all_rows = client.get("/cases").json()
    heavy_count = next(
        c["invariant_hits_count"] for c in all_rows if c["primary_asset_id"] == "plc-heavy-inv"
    )
    hi = client.get("/cases", params={"min_invariant_hits": 3}).json()
    assert all(c["invariant_hits_count"] >= 3 for c in hi)
    if heavy_count >= 3:
        assert any(c["primary_asset_id"] == "plc-heavy-inv" for c in hi)


def test_list_cases_max_risk_score_and_event_count_filters():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T12:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-merge-ec",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T12:00:01+00:00",
            "operation": "POLL",
            "asset_id": "plc-merge-ec",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T13:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-single-ec",
        },
    )
    rows = client.get("/cases").json()
    assert len(rows) == 2
    merged = next(c for c in rows if c["primary_asset_id"] == "plc-merge-ec")
    assert merged["event_count"] == 2
    assert next(c for c in rows if c["primary_asset_id"] == "plc-single-ec")["event_count"] == 1
    doubles = client.get("/cases", params={"min_event_count": 2}).json()
    assert len(doubles) == 1 and doubles[0]["case_id"] == merged["case_id"]
    singles = client.get("/cases", params={"max_event_count": 1}).json()
    assert len(singles) == 1 and singles[0]["primary_asset_id"] == "plc-single-ec"
    assert all(c["risk_score"] <= 1.0 for c in client.get("/cases", params={"max_risk_score": 1.0}).json())
    risks = sorted({c["risk_score"] for c in rows})
    if len(risks) >= 2:
        mid = (risks[0] + risks[-1]) / 2
        low = client.get("/cases", params={"max_risk_score": mid}).json()
        assert all(c["risk_score"] <= mid for c in low)


def test_list_cases_audit_contains_and_sort_event_count():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T11:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-audit-sort",
        },
    )
    assert len(client.get("/cases", params={"audit_contains": "assessriskusecase"}).json()) >= 1
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T11:00:01+00:00",
            "operation": "POLL",
            "asset_id": "plc-audit-sort",
        },
    )
    assert len(client.get("/cases", params={"audit_contains": "merged"}).json()) >= 1
    assert client.get("/cases", params={"audit_contains": "zz_no_audit_zz"}).json() == []
    desc = client.get("/cases", params={"sort": "event_count_desc"}).json()
    assert [c["event_count"] for c in desc] == sorted(
        (c["event_count"] for c in desc),
        reverse=True,
    )
    asc = client.get("/cases", params={"sort": "event_count_asc"}).json()
    assert [c["event_count"] for c in asc] == sorted(c["event_count"] for c in asc)


def test_list_cases_created_after_and_before():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-05-01T08:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-early",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-05-01T20:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-late",
        },
    )
    after = client.get("/cases", params={"created_after": "2026-05-01T12:00:00+00:00"}).json()
    assert len(after) == 1 and after[0]["primary_asset_id"] == "plc-late"
    before = client.get("/cases", params={"created_before": "2026-05-01T12:00:00+00:00"}).json()
    assert len(before) == 1 and before[0]["primary_asset_id"] == "plc-early"


def test_list_cases_risk_classes_and_title_sort():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T10:00:00+00:00",
            "operation": "ZZZ_SORT_OP",
            "asset_id": "plc-z-title",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T10:01:00+00:00",
            "operation": "AAA_SORT_OP",
            "asset_id": "plc-a-title",
        },
    )
    asc = client.get("/cases", params={"sort": "title_asc"}).json()
    titles = [r["title"].lower() for r in asc]
    assert titles == sorted(titles)
    assert client.get("/cases", params={"risk_classes": "NOT_A_CLASS"}).status_code == 400
    subset = client.get("/cases", params={"risk_classes": "LOW,MEDIUM,HIGH,CRITICAL"}).json()
    assert len(subset) == len(asc)


def test_list_cases_sort_case_id_and_primary_asset():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T15:00:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-m-asset",
        },
    )
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T15:01:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-a-asset",
        },
    )
    by_asset = client.get("/cases", params={"sort": "primary_asset_id_asc"}).json()
    aids = [r["primary_asset_id"].lower() for r in by_asset]
    assert aids == sorted(aids)
    by_cid = client.get("/cases", params={"sort": "case_id_asc"}).json()
    cids = [r["case_id"].lower() for r in by_cid]
    assert cids == sorted(cids)


def test_list_cases_filter_event_source():
    client = TestClient(create_app())
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T18:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-es-filter",
            "source": "auth_logs",
        },
    )
    auth = client.get("/cases", params={"event_source": "auth_logs"}).json()
    assert len(auth) == 1 and auth[0]["last_event_source"] == "auth_logs"
    assert client.get("/cases", params={"event_source": "service_desk"}).json() == []


def test_list_cases_limit_above_max_returns_422():
    client = TestClient(create_app())
    assert client.get("/cases", params={"limit": 1001}).status_code == 422


def test_list_cases_filters_and_invariant_count():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T22:15:00+00:00",
            "operation": "ADMIN_LOGIN",
            "asset_id": "plc-01",
        },
    )
    r = client.get("/cases")
    assert r.status_code == 200
    body = r.json()
    assert len(body) >= 1
    assert "invariant_hits_count" in body[0]
    assert "created_at" in body[0]
    assert "dq_score" in body[0]
    assert "dq_partial" in body[0]
    assert "trigger_operation" in body[0]
    assert body[0]["last_event_source"] == "plc_polling"
    assert body[0]["event_count"] == 1
    assert body[0]["primary_asset_id"] == "plc-01"
    assert isinstance(body[0]["invariant_hits_count"], int)
    bad = client.get("/cases", params={"risk_class": "ULTRA"})
    assert bad.status_code == 400
    assert client.get("/cases", params={"status": "NOT_A_STATUS"}).status_code == 400
    assert client.get("/cases", params={"sort": "not_a_sort"}).status_code == 400
    st = client.get("/cases", params={"status": "NEW"})
    assert st.status_code == 200
    assert all(x["status"] == "NEW" for x in st.json())
    asc = client.get("/cases", params={"sort": "risk_score_asc"})
    assert asc.status_code == 200
    scores = [row["risk_score"] for row in asc.json()]
    assert scores == sorted(scores)
    dqs = client.get("/cases", params={"sort": "dq_score_asc"})
    assert dqs.status_code == 200
    dq_vals = [row["dq_score"] for row in dqs.json()]
    assert dq_vals == sorted(dq_vals)
    partial = client.get("/cases", params={"dq_partial": "false"})
    assert partial.status_code == 200
    assert all(row["dq_partial"] is False for row in partial.json())


def test_openapi_cases_list_documents_x_total_count_header():
    client = TestClient(create_app())
    spec = client.get("/openapi.json").json()
    get_cases = spec["paths"]["/cases"]["get"]
    headers_200 = get_cases["responses"]["200"].get("headers", {})
    assert "X-Total-Count" in headers_200
    assert "schema" in headers_200["X-Total-Count"]
    assert "Link" in headers_200


def test_openapi_export_full_documents_x_total_count_header():
    client = TestClient(create_app())
    spec = client.get("/openapi.json").json()
    get_exp = spec["paths"]["/cases/export/full.json"]["get"]
    headers_200 = get_exp["responses"]["200"].get("headers", {})
    assert "X-Total-Count" in headers_200
    assert "schema" in headers_200["X-Total-Count"]
    assert "Link" in headers_200


def test_list_cases_x_total_count_filters_and_pagination():
    client = TestClient(create_app())
    for aid in ("plc-xcnt-a", "plc-xcnt-b"):
        client.post(
            "/assess",
            json={
                "observed_at": "2026-05-06T10:00:00+00:00",
                "operation": "READ",
                "asset_id": aid,
            },
        )
    r = client.get("/cases")
    assert r.status_code == 200
    assert r.headers.get("x-total-count") == "2"
    assert len(r.json()) == 2
    r_page = client.get("/cases", params={"limit": 1, "offset": 0})
    assert r_page.status_code == 200
    assert len(r_page.json()) == 1
    assert r_page.headers.get("x-total-count") == "2"
    r_one_asset = client.get("/cases", params={"primary_asset_id": "plc-xcnt-a"})
    assert r_one_asset.status_code == 200
    assert r_one_asset.headers.get("x-total-count") == "1"
    assert len(r_one_asset.json()) == 1


def test_list_cases_pagination_link_next_prev_and_no_link_without_limit():
    import re
    from urllib.parse import parse_qs, urlparse

    client = TestClient(create_app())
    for i in range(3):
        client.post(
            "/assess",
            json={
                "observed_at": f"2026-05-07T14:{i:02d}:00+00:00",
                "operation": "READ",
                "asset_id": f"plc-link-{i}",
            },
        )
    r_all = client.get("/cases")
    assert r_all.headers.get("link") is None
    r0 = client.get("/cases", params={"limit": 1, "sort": "created_at_asc"})
    assert r0.status_code == 200
    link0 = r0.headers.get("link") or ""
    assert 'rel="next"' in link0
    assert "rel=\"prev\"" not in link0
    m_next = re.search(r"<([^>]+)>\s*;\s*rel=\"next\"", link0)
    assert m_next
    q0 = parse_qs(urlparse(m_next.group(1)).query)
    assert q0.get("limit") == ["1"]
    assert q0.get("offset") == ["1"]
    assert q0.get("sort") == ["created_at_asc"]
    r1 = client.get(m_next.group(1))
    assert r1.status_code == 200
    link1 = r1.headers.get("link") or ""
    assert 'rel="next"' in link1
    assert 'rel="prev"' in link1
    m_last = re.search(r"<([^>]+)>\s*;\s*rel=\"next\"", link1)
    assert m_last
    q1 = parse_qs(urlparse(m_last.group(1)).query)
    assert q1.get("offset") == ["2"]
    r2 = client.get(m_last.group(1))
    link2 = r2.headers.get("link") or ""
    assert 'rel="next"' not in link2
    assert 'rel="prev"' in link2


def test_list_cases_filter_has_dq_reason():
    client = TestClient(create_app())
    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T20:00:00+00:00",
            "operation": "PING",
            "asset_id": "plc-high-trust",
        },
    )
    client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T20:01:00+00:00",
            "operation": "PING",
            "asset_id": "plc-low-trust",
            "source": "unknown",
        },
    )
    drift = client.get("/cases", params={"has_dq_reason": "source_reputation"}).json()
    assert len(drift) >= 1
    assert all(c["primary_asset_id"] == "plc-low-trust" for c in drift)
    none = client.get("/cases", params={"has_dq_reason": "nonexistent_reason_xyz"}).json()
    assert none == []


def test_assess_invariant_details_and_pagination():
    client = TestClient(create_app())
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T22:15:00+00:00",
            "operation": "ADMIN_LOGIN",
            "asset_id": "plc-01",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "invariant_details" in body
    assert len(body["invariant_details"]) == len(body["invariant_hits"])
    if body["invariant_hits"]:
        row = body["invariant_details"][0]
        assert row["id"] == body["invariant_hits"][0]
        assert row["title_ru"]
    cid = body["case_id"]
    detail = client.get(f"/cases/{cid}").json()
    assert detail["risk_score"] == body["risk_score"]
    assert detail["risk_class"] == body["risk_class"]

    client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T22:16:00+00:00",
            "operation": "POLL",
            "asset_id": "plc-99",
        },
    )
    full = client.get("/cases", params={"sort": "created_at_asc"}).json()
    assert len(full) >= 2
    page = client.get("/cases", params={"sort": "created_at_asc", "limit": 1, "offset": 0}).json()
    assert len(page) == 1
    page1 = client.get("/cases", params={"sort": "created_at_asc", "limit": 1, "offset": 1}).json()
    assert len(page1) == 1
    assert page[0]["case_id"] != page1[0]["case_id"]


def test_health_and_assess_flow():
    app = create_app()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T22:15:00+00:00",
            "operation": "ADMIN_LOGIN",
            "asset_id": "plc-01",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "case_id" in body
    cases = client.get("/cases").json()
    assert len(cases) >= 1
    rid = body["case_id"]
    d = client.get(f"/cases/{rid}").json()
    assert d["case_id"] == rid
    assert "invariant_details" in d
    assert len(d["invariant_details"]) == len(d["invariant_hits"])
    assert "created_at" in d
    dq = client.get("/data-quality")
    assert dq.status_code == 200


def test_post_events_ingest_and_data_quality():
    app = create_app()
    client = TestClient(app)
    r = client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T23:00:00+00:00",
            "operation": "DATA",
            "asset_id": "plc-02",
            "source": "plc_polling",
            "payload": {"type_id": "100"},
        },
    )
    assert r.status_code == 200
    assert "case_id" in r.json()
    assert client.get("/data-quality").status_code == 200


def test_post_events_invalid_source():
    client = TestClient(create_app())
    r = client.post(
        "/events",
        json={
            "observed_at": "2026-04-30T23:00:00+00:00",
            "operation": "PING",
            "asset_id": "x",
            "source": "not-a-real-source",
        },
    )
    assert r.status_code == 400


def test_backtest_fixture_ok():
    client = TestClient(create_app())
    r = client.post("/backtest/fixture")
    assert r.status_code == 200
    body = r.json()
    assert body["events_processed"] >= 1
    assert "risk_class_histogram" in body


def test_run_backtest_forwards_trust_by_source():
    from takt.application.use_cases.backtest import RunBacktestUseCase
    from takt.domain.entities.event import EventSource, NormalizedEvent

    process = MagicMock()
    process.recent_context_event_count = 5
    uc = RunBacktestUseCase(process)
    ev = NormalizedEvent(
        event_id="t",
        observed_at=datetime(2026, 4, 30, tzinfo=timezone.utc),
        source=EventSource.PLC_POLLING,
        protocol="demo",
        operation="PING",
        payload_size=0,
        payload={},
    )
    trust = {"plc_polling": 0.99}
    uc.execute([ev], trust_by_source=trust)
    kw = process.execute.call_args[1]
    assert kw["trust_by_source"] == trust


def test_topology_demo_graph():
    client = TestClient(create_app())
    r = client.get("/topology/demo-graph")
    assert r.status_code == 200
    body = r.json()
    assert body["jump_host"] == "jump-01"
    assert "plc-01" in body["plc_hosts"]
    assert len(body["edges"]) >= 1
    assert body["edges"][0]["src"]
    assert body["edges"][0]["dst"]
    assert body["has_jump_bypass_pattern"] is True


def test_siem_forward_sync_and_async():
    app = create_app()
    client = TestClient(app)
    r = client.post(
        "/assess",
        json={
            "observed_at": "2026-04-30T22:15:00+00:00",
            "operation": "ADMIN_LOGIN",
            "asset_id": "plc-01",
        },
    )
    assert r.status_code == 200
    case_id = r.json()["case_id"]
    body = {"case_id": case_id, "target_url": "http://127.0.0.1/ingest"}
    with patch(
        "takt.interface_adapters.api.main.post_case_to_webhook_sync",
        return_value=204,
    ) as sync_mock:
        fr = client.post("/integrations/siem/forward", json=body)
        assert fr.status_code == 200
        assert fr.json() == {"ok": True, "http_status": 204}
        assert "async" not in fr.json()
        sync_mock.assert_called_once()
    with patch(
        "takt.interface_adapters.api.main.post_case_to_webhook",
        new=AsyncMock(return_value=202),
    ) as async_mock:
        fr = client.post("/integrations/siem/forward/async", json=body)
        assert fr.status_code == 200
        assert fr.json() == {"ok": True, "http_status": 202, "async": True}
        async_mock.assert_called_once()
