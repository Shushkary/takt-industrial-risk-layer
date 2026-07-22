from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from fastapi.testclient import TestClient

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.export.forensic_bundle import ZipForensicBundleBuilder, ZipForensicBundleVerifier
from takt.infrastructure.export.gossopka import case_to_gossopka_card, case_to_gossopka_transport_payload
from takt.interface_adapters.api.main import create_app


def _case() -> Case:
    c = Case(
        case_id="fb-1",
        status=CaseStatus.TRIAGE,
        title="Risk HIGH: WRITE_COIL",
        risk_class="HIGH",
        risk_score=0.81,
        created_at=datetime(2026, 5, 5, 10, 0, tzinfo=UTC),
        normalized_event_ids=["ev-1"],
        xai_summary="why",
        audit_log=["2026-05-05T10:00:00+00:00 | case created"],
        burst_fingerprint="plc-01|WRITE_COIL|5927148",
        primary_asset_id="plc-01",
        trigger_operation="WRITE_COIL",
        invariant_hits=["blind_command"],
        dq_score=0.92,
        dq_partial=False,
        last_event_source="plc_polling",
    )
    return c


def test_zip_forensic_bundle_contains_manifest_and_evidence() -> None:
    builder = ZipForensicBundleBuilder()
    meta, raw = builder.build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert raw[:2] == b"PK"
    assert meta.signature_status == "unsigned_mvp"
    assert meta.process_suitability == "machine_readable_evidence_bundle_without_qualified_signature"
    assert meta.suitability_label == "требует дополнительной проверки"
    assert len(meta.root_hash_sha256) == 64

    with ZipFile(BytesIO(raw)) as zf:
        names = set(zf.namelist())
        assert names == {
            "manifest.json", "case.json", "siem.json", "gossopka-card.json", "audit.txt",
            "findings.json", "artifacts.json",
        }
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
        gossopka = json.loads(zf.read("gossopka-card.json").decode("utf-8"))

    assert manifest["case_id"] == "fb-1"
    assert manifest["package_id"] == meta.package_id
    assert manifest["package_id"].startswith("takt-fb-1-")
    assert manifest["root_hash_sha256"] == meta.root_hash_sha256
    assert manifest["suitability_label"] == "требует дополнительной проверки"
    checks = {item["code"]: item for item in manifest["suitability_checks"]}
    assert checks["normalized_event"]["ok"] is True
    assert checks["formal_verdict"]["ok"] is True
    assert checks["operator_history"]["ok"] is False
    assert checks["organizational_context_checksum"]["ok"] is False
    assert checks["aggregate_checksum"]["ok"] is True
    assert checks["signature"]["ok"] is False
    assert [item["path"] for item in manifest["items"]] == [
        "case.json", "siem.json", "gossopka-card.json", "audit.txt", "findings.json", "artifacts.json"
    ]
    assert manifest["items"][0]["element_type"] == "дело"
    assert manifest["items"][0]["source"] == "реестр дел ТАКТ"
    assert manifest["items"][0]["role"] == "основная карточка дела"
    assert manifest["items"][0]["checksum_algorithm"] == "SHA-256"
    assert manifest["items"][0]["included_at"] == "2026-05-05T11:00:00+00:00"
    assert all("element_type" in item for item in manifest["items"])
    assert all("source" in item for item in manifest["items"])
    assert all("role" in item for item in manifest["items"])
    assert all(item["checksum_algorithm"] == "SHA-256" for item in manifest["items"])
    assert all("included_at" in item for item in manifest["items"])
    assert manifest["root_hash_sha256"] == manifest["items"][-1]["chain_sha256"]
    assert all(len(item["chain_sha256"]) == 64 for item in manifest["items"])
    assert case_payload["primary_asset_id"] == "plc-01"
    assert case_payload["action_class"] == "управляющее воздействие"
    assert case_payload["invariant_hits"] == ["blind_command"]
    assert case_payload["remediation_attempts"] == []
    assert case_payload["formal_verdict"]["value"] == "неопределённое"
    assert case_payload["formal_verdict"]["context_match"]["matched"] is False
    assert case_payload["formal_verdict"]["context_match"]["score"] == 0.0
    assert gossopka["format"] == "TAKT-GosSOPKA-MVP"
    assert gossopka["incident"]["category"] == "industrial_process_disruption_risk"
    assert gossopka["incident"]["formal_verdict"] == "неопределённое"
    assert gossopka["incident"]["context_match"]["matched"] is False


def test_api_forensic_bundle_manifest_and_zip() -> None:
    app = create_app()
    client = TestClient(app)
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
    assert manifest.status_code == 200
    root_hash = manifest.json()["root_hash_sha256"]
    assert len(root_hash) == 64
    assert manifest.json()["package_id"].startswith(f"takt-{case_id}-")
    assert manifest.json()["signature_status"] == "unsigned_mvp"
    assert manifest.json()["suitability_label"] == "требует дополнительной проверки"
    assert "suitability_checks" in manifest.json()
    assert manifest.json()["items"][0]["element_type"] == "дело"
    assert manifest.json()["items"][0]["checksum_algorithm"] == "SHA-256"
    assert manifest.json()["items"][-1]["chain_sha256"] == root_hash

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200
    assert archive.headers["content-type"] == "application/zip"
    assert archive.headers["x-takt-forensic-root-hash"] == root_hash
    assert archive.headers["x-takt-forensic-signature-status"] == manifest.json()["signature_status"]
    with ZipFile(BytesIO(archive.content)) as zf:
        assert "manifest.json" in zf.namelist()
        assert "gossopka-card.json" in zf.namelist()
        assert "compliance-data-quality-report.json" in zf.namelist()
        assert "forensic-readiness-report.json" in zf.namelist()
        assert "case-evidence-checklist.json" in zf.namelist()
        assert json.loads(zf.read("manifest.json").decode("utf-8"))["root_hash_sha256"] == root_hash
        compliance = json.loads(zf.read("compliance-data-quality-report.json").decode("utf-8"))
        readiness = json.loads(zf.read("forensic-readiness-report.json").decode("utf-8"))
        checklist = json.loads(zf.read("case-evidence-checklist.json").decode("utf-8"))
        assert compliance["format"] == "TAKT Compliance Data Quality Report"
        assert compliance["total_cases"] == 1
        assert "remediation_attempts_by_kind" in compliance
        assert "remediation_attempts_by_status" in compliance
        assert readiness["format"] == "TAKT Forensic Readiness Report"
        assert readiness["cases"][0]["case_id"] == case_id
        assert "missing_by_code" in readiness
        assert checklist["format"] == "TAKT Case Evidence Checklist"
        assert checklist["case_id"] == case_id
        assert "remediation_summary" in checklist
        assert "remediation_kind" in checklist["items"][0]
        assert "remediation_action" in checklist["items"][0]
        assert "remediation_attempted" in checklist["items"][0]
        assert "latest_remediation_status" in checklist["items"][0]
    detail = client.get(f"/cases/{case_id}").json()
    assert any(f"forensic bundle generated root_hash={root_hash}" in line for line in detail["audit_log"])


def test_api_gossopka_export() -> None:
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
    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-GS-1",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "executor": "Иванов И.И.",
            "approver": "Петров П.П.",
            "valid_from": "2026-05-05T09:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
        },
    )
    assert permit.status_code == 200
    decision = client.post(
        f"/cases/{case_id}/decision",
        json={"status": "TRIAGE", "reason": "operator acknowledged"},
    )
    assert decision.status_code == 200
    remediation = client.post(
        f"/cases/{case_id}/compliance/remediations",
        json={"kind": "generate_forensic_bundle", "status": "recorded", "note": "ready for export"},
    )
    assert remediation.status_code == 200

    r = client.get(f"/cases/{case_id}/export/gossopka.json")
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "TAKT-GosSOPKA-MVP"
    assert body["legal_context"]["uk_rf_article"] == "274.1"
    assert body["incident"]["formal_verdict"] == "легитимное"
    assert body["incident"]["context_match"]["matched"] is True
    assert body["critical_information_infrastructure"]["action_class"] == "управляющее воздействие"
    assert len(body["evidence"]["manual_permits"][0]["organizational_context_sha256"]) == 64
    assert body["evidence"]["manual_permits"][0]["organizational_context"]["checksum_algorithm"] == "SHA-256"
    assert body["operator_actions"]["formal_verdict"] == "легитимное"
    assert body["evidence"]["manual_permits"][0]["work_order_number"] == "WO-GS-1"
    assert body["operator_actions"]["remediation_attempts"][0]["kind"] == "generate_forensic_bundle"
    assert body["operator_actions"]["decision_records"][0]["reason"] == "operator acknowledged"
    transport = client.get(f"/cases/{case_id}/export/gossopka-transport.json")
    assert transport.status_code == 200
    t_body = transport.json()
    assert t_body["contract"] == "TAKT-GosSOPKA-Transport"
    assert t_body["exchange"]["mode"] == "pull_http_json"
    assert t_body["payload"]["incident"]["case_id"] == case_id
    assert t_body["payload"]["incident"]["formal_verdict"] == "легитимное"
    official = client.get(f"/cases/{case_id}/export/gossopka-official.json")
    assert official.status_code == 200
    off_body = official.json()
    assert off_body["format"] == "GOSSOPKA-INCIDENT-CARD"
    assert off_body["exchange_profile"]["profile"] == "official_operator_interop"
    official_t = client.get(f"/cases/{case_id}/export/gossopka-official-transport.json")
    assert official_t.status_code == 200
    off_t_body = official_t.json()
    assert off_t_body["contract"] == "GOSSOPKA-TRANSPORT-INTEROP"
    assert off_t_body["payload"]["incident"]["case_id"] == case_id
    assert off_t_body["payload"]["incident"]["formal_verdict"] == "легитимное"


def test_zip_forensic_bundle_verifier_accepts_valid_archive() -> None:
    _meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    result = ZipForensicBundleVerifier().verify_bundle(raw)
    assert result.ok is True
    assert result.case_id == "fb-1"
    assert result.checked_items == 6
    assert result.issues == ()


def test_zip_forensic_bundle_verifier_rejects_tampered_archive() -> None:
    _meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    out = BytesIO()
    with ZipFile(BytesIO(raw)) as src, ZipFile(out, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "case.json":
                data = data.replace(b"plc-01", b"plc-99")
            zi = ZipInfo(name)
            zi.compress_type = ZIP_DEFLATED
            dst.writestr(zi, data)
    result = ZipForensicBundleVerifier().verify_bundle(out.getvalue())
    assert result.ok is False
    assert any(i.code == "sha256_mismatch" for i in result.issues)
    assert any(i.code == "chain_mismatch" for i in result.issues)


def test_zip_forensic_bundle_verifier_rejects_path_traversal_entry() -> None:
    out = BytesIO()
    with ZipFile(out, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("../evil.txt", "x")

    result = ZipForensicBundleVerifier().verify_bundle(out.getvalue())

    assert result.ok is False
    assert any(i.code == "invalid_path" for i in result.issues)


def test_zip_forensic_bundle_verifier_rejects_too_many_files() -> None:
    out = BytesIO()
    with ZipFile(out, "w") as zf:
        zf.writestr("manifest.json", "{}")
        for i in range(129):
            zf.writestr(f"extra-{i}.txt", "x")

    result = ZipForensicBundleVerifier().verify_bundle(out.getvalue())

    assert result.ok is False
    assert any(i.code == "too_many_files" for i in result.issues)


def test_zip_forensic_bundle_verifier_rejects_high_compression_ratio() -> None:
    out = BytesIO()
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("payload.bin", b"0" * 200_000)

    result = ZipForensicBundleVerifier().verify_bundle(out.getvalue())

    assert result.ok is False
    assert any(i.code == "compression_ratio_exceeded" for i in result.issues)


def test_zip_forensic_bundle_verifier_rejects_archive_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "takt.infrastructure.export.forensic_bundle._VERIFY_MAX_ARCHIVE_BYTES",
        16,
    )

    result = ZipForensicBundleVerifier().verify_bundle(b"not-a-zip-but-too-large")

    assert result.ok is False
    assert any(i.code == "archive_size_exceeded" for i in result.issues)


def test_api_forensic_bundle_verify_endpoint() -> None:
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
    case_id = created.json()["case_id"]
    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    verify = client.post(
        "/forensic-bundle/verify",
        content=archive.content,
        headers={"content-type": "application/zip"},
    )
    assert verify.status_code == 200
    body = verify.json()
    assert body["ok"] is True
    assert body["case_id"] == case_id
    assert body["checked_items"] == 9


def test_forensic_bundle_contains_raw_evidence_from_events_ingest() -> None:
    client = TestClient(create_app())
    ingested = client.post(
        "/events",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-raw-1",
            "source": "network_events",
            "payload": {"original_record": "<34>1 test raw line"},
        },
    )
    assert ingested.status_code == 200
    case_id = ingested.json()["case_id"]
    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200
    with ZipFile(BytesIO(archive.content)) as zf:
        names = set(zf.namelist())
        assert "evidence-index.json" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
        evidence_index = json.loads(zf.read("evidence-index.json").decode("utf-8"))
        raw_items = [name for name in names if name.startswith("raw/") and name.endswith(".bin")]
    assert len(raw_items) >= 1
    assert evidence_index["format"] == "TAKT Raw Evidence Index"
    assert len(evidence_index["items"]) >= 1
    assert case_payload["raw_evidence_refs"][0]["path"].startswith("raw/")
    assert any(item["path"] == "evidence-index.json" for item in manifest["items"])


def test_forensic_bundle_includes_audit_engagement_when_requested() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/events",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-eng-1",
            "source": "network_events",
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]
    engagement = client.post(
        "/audit-engagements",
        json={
            "customer": "Plant B",
            "scope": "Forensic audit service",
            "case_ids": [case_id],
            "nda_signed": True,
            "evidence_intake_checklist": ["nda"],
        },
    )
    assert engagement.status_code == 200
    engagement_id = engagement.json()["engagement_id"]
    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip", params={"engagement_id": engagement_id})
    assert archive.status_code == 200
    with ZipFile(BytesIO(archive.content)) as zf:
        names = set(zf.namelist())
        assert "engagement.json" in names
        engagement_json = json.loads(zf.read("engagement.json").decode("utf-8"))
        assert engagement_json["engagement_id"] == engagement_id
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert any(item["path"] == "engagement.json" for item in manifest["items"])


def test_forensic_bundle_rejects_unknown_audit_engagement() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/events",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-eng-missing",
            "source": "network_events",
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip", params={"engagement_id": "missing-engagement"})

    assert archive.status_code == 404
    assert archive.json()["detail"] == "engagement not found"


def test_forensic_bundle_rejects_unlinked_audit_engagement() -> None:
    client = TestClient(create_app())
    first = client.post(
        "/events",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-eng-a",
            "source": "network_events",
        },
    )
    second = client.post(
        "/events",
        json={
            "observed_at": "2026-05-05T10:01:00+00:00",
            "operation": "READ_COIL",
            "asset_id": "plc-eng-b",
            "source": "network_events",
        },
    )
    assert first.status_code == 200
    assert second.status_code == 200
    linked_case_id = first.json()["case_id"]
    requested_case_id = second.json()["case_id"]
    engagement = client.post(
        "/audit-engagements",
        json={
            "customer": "Plant C",
            "scope": "Forensic audit service",
            "case_ids": [linked_case_id],
            "nda_signed": True,
            "evidence_intake_checklist": ["nda"],
        },
    )
    assert engagement.status_code == 200

    archive = client.get(
        f"/cases/{requested_case_id}/forensic-bundle.zip",
        params={"engagement_id": engagement.json()["engagement_id"]},
    )

    assert archive.status_code == 400
    assert archive.json()["detail"] == "engagement is not linked to case"


def test_forensic_bundle_hmac_signature_when_secret_is_set(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "test-secret")
    meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert meta.signature_status == "hmac_sha256_mvp"
    assert meta.suitability_label == "условно пригоден"
    assert meta.signature_ref == "root-hash-signature.json"
    with ZipFile(BytesIO(raw)) as zf:
        assert "root-hash-signature.json" in zf.namelist()
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    assert manifest["signature_status"] == "hmac_sha256_mvp"
    assert manifest["suitability_label"] == "условно пригоден"
    assert manifest["signature_ref"] == "root-hash-signature.json"

    ok = ZipForensicBundleVerifier().verify_bundle(raw)
    assert ok.ok is True

    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "wrong-secret")
    bad = ZipForensicBundleVerifier().verify_bundle(raw)
    assert bad.ok is False
    assert any(i.code == "signature_mismatch" for i in bad.issues)


def test_api_forensic_manifest_reports_hmac_signature(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "api-secret")
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-01",
            "persist_case": True,
        },
    )
    case_id = created.json()["case_id"]
    manifest = client.get(f"/cases/{case_id}/forensic-bundle/manifest")
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["signature_status"] == "hmac_sha256_mvp"
    assert body["signature_ref"] == "root-hash-signature.json"


def test_gossopka_transport_payload_contract() -> None:
    payload = case_to_gossopka_transport_payload(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
        exchange_mode="smev_like_push",
    )
    assert payload["contract"] == "TAKT-GosSOPKA-Transport"
    assert payload["contract_version"] == "0.1"
    assert payload["exchange"]["mode"] == "smev_like_push"
    assert payload["payload"]["format"] == "TAKT-GosSOPKA-MVP"


def test_gossopka_signature_status_defaults_to_gost_in_strict_mode(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.delenv("TAKT_GOSSOPKA_SIGNATURE_STATUS", raising=False)
    payload = case_to_gossopka_card(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert payload["legal_context"]["signature_status"] == "external_gost2012_detached"


def test_gossopka_signature_status_does_not_fallback_to_hmac_in_strict_mode(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.delenv("TAKT_FORENSIC_SIGN_URL", raising=False)
    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "dev-secret")
    monkeypatch.delenv("TAKT_GOSSOPKA_SIGNATURE_STATUS", raising=False)
    payload = case_to_gossopka_card(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert payload["legal_context"]["signature_status"] == "unsigned_mvp"


def test_forensic_bundle_external_signature_adapter_roundtrip(monkeypatch) -> None:
    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "algorithm": "GOST-R-34.10-2012",
                    "signature": "BASE64SIG",
                    "key_id": "kzp-1",
                },
            )
        if str(url).endswith("/verify"):
            assert json["signature"]["signature"] == "BASE64SIG"
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"ok": True},
            )
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert meta.signature_status == "external_qualified_detached"
    assert meta.process_suitability == "qualified_signature_attached_for_procedural_actions"
    assert meta.suitability_label == "пригоден"
    ok = ZipForensicBundleVerifier().verify_bundle(raw)
    assert ok.ok is True


def test_forensic_bundle_external_signature_requires_verify_endpoint(monkeypatch) -> None:
    def _fake_post(url, json, timeout):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "algorithm": "GOST-R-34.10-2012",
                "signature": "BASE64SIG",
                "key_id": "kzp-1",
            },
        )

    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.delenv("TAKT_FORENSIC_VERIFY_URL", raising=False)
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    _meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    result = ZipForensicBundleVerifier().verify_bundle(raw)
    assert result.ok is False
    assert any(i.code == "signature_verifier_unconfigured" for i in result.issues)


def test_forensic_bundle_strict_mode_requires_gost_signature(monkeypatch) -> None:
    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "algorithm": "GOST-R-34.10-2012",
                    "signature": "BASE64SIG",
                    "key_id": "kzp-1",
                },
            )
        if str(url).endswith("/verify"):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"ok": True})
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case(),
        generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
    )
    assert meta.signature_status == "external_gost2012_detached"
    assert meta.suitability_label == "пригоден"
    verified = ZipForensicBundleVerifier().verify_bundle(raw)
    assert verified.ok is True


def test_forensic_bundle_strict_mode_does_not_fallback_when_signer_fails(monkeypatch) -> None:
    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            raise RuntimeError("signer unavailable")
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_HMAC_SECRET", "dev-secret")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    with pytest.raises(RuntimeError, match="strict crypto mode requires successful external signer response"):
        ZipForensicBundleBuilder().build_case_bundle(
            _case(),
            generated_at=datetime(2026, 5, 5, 11, 0, tzinfo=UTC),
        )


def test_api_forensic_bundle_strict_mode_returns_503_when_signer_fails(monkeypatch) -> None:
    def _fake_post(url, json, timeout):
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

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 503
    assert "forensic_signing_unavailable" in archive.json()["detail"]

    manifest = client.get(f"/cases/{case_id}/forensic-bundle/manifest")
    assert manifest.status_code == 503
    assert "forensic_signing_unavailable" in manifest.json()["detail"]
