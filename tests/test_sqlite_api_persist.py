from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.interface_adapters.api.main import create_app


def test_health_reports_sqlite_when_configured(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "api.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        h = client.get("/health").json()
        assert h["case_storage"] == "sqlite"
        assert h["expected_behavior_storage"] == "sqlite"
        assert h["sqlite_schema_version"] == 6
        assert h["sqlite_busy_timeout_ms"] == 5000
        assert client.get("/ready").status_code == 200


def test_cases_survive_new_app_instance(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "persist.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": "data/would_be_default.db"}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(db))
    with TestClient(create_app()) as c1:
        r = c1.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-sqlite-persist",
            },
        )
        assert r.status_code == 200
        cid = r.json()["case_id"]

    with TestClient(create_app()) as c2:
        detail = c2.get(f"/cases/{cid}").json()
        assert detail["case_id"] == cid
        assert detail["primary_asset_id"] == "plc-sqlite-persist"


def test_sqlite_x_total_count_cases_and_export(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "xcount.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        for aid in ("plc-xc-1", "plc-xc-2"):
            assert (
                client.post(
                    "/assess",
                    json={
                        "observed_at": "2026-05-07T12:00:00+00:00",
                        "operation": "READ",
                        "asset_id": aid,
                    },
                ).status_code
                == 200
            )
        r_list = client.get("/cases", params={"limit": 1})
        assert r_list.headers.get("x-total-count") == "2"
        assert len(r_list.json()) == 1
        r_exp = client.get("/cases/export/full.json", params={"limit": 1})
        body = r_exp.json()
        assert r_exp.headers.get("x-total-count") == "2"
        assert 'rel="next"' in (r_exp.headers.get("link") or "")
        assert body["total_in_repo"] == 2
        assert body["count"] == 1


def test_expected_behavior_survives_after_sqlite_api(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "eb_api.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as c:
        r = c.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T23:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-eb-api",
            },
        )
        assert r.status_code == 200
        cid = r.json()["case_id"]
        dec = c.post(f"/cases/{cid}/decision", json={"status": "EXPECTED_BEHAVIOR"})
        assert dec.status_code == 200

    from takt.infrastructure.stores.sqlite_store import SqliteExpectedBehavior

    eb = SqliteExpectedBehavior(db)
    assert eb.is_expected("plc-eb-api", "READ")
    eb.close()


def test_sqlite_import_full_json_uses_transaction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "import_tx.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    case = {
        "case_id": "sqlite-import-1",
        "status": "NEW",
        "title": "t",
        "risk_class": "LOW",
        "risk_score": 0.25,
        "event_ids": ["e1"],
        "invariant_hits": [],
        "invariant_details": [],
        "xai_summary": "x",
        "audit_log": [],
        "fingerprint": "f|f|f",
        "primary_asset_id": "plc-imp",
        "trigger_operation": "READ",
        "last_event_source": "plc_polling",
        "created_at": "2026-05-04T12:00:00+00:00",
        "dq_score": 1.0,
        "dq_partial": False,
        "dq_reasons": [],
    }
    with TestClient(create_app()) as c:
        r = c.post("/cases/import/full.json", json={"cases": [case], "mode": "upsert"})
        assert r.status_code == 200
        assert r.json() == {"imported": 1, "skipped": 0, "mode": "upsert"}
    with TestClient(create_app()) as c2:
        assert c2.get("/cases/sqlite-import-1").status_code == 200


def test_sqlite_operation_ledger_verify_for_decision_flow(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "decision-ledger.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        created = client.post(
            "/assess",
            json={
                "observed_at": "2026-05-11T10:00:00+00:00",
                "operation": "READ",
                "asset_id": "plc-decision-ledger",
            },
        )
        assert created.status_code == 200
        cid = created.json()["case_id"]
        decision = client.post(
            f"/cases/{cid}/decision",
            json={"status": "TRIAGE", "reason": "operator triage for immutable ledger test"},
        )
        assert decision.status_code == 200
        verified = client.get("/audit-ledger/operations/verify", params={"stream_key": f"decision:{cid}"})
        assert verified.status_code == 200
        body = verified.json()
        assert body["ok"] is True
        assert body["checked_entries"] >= 1


def test_sqlite_operation_ledger_verify_for_import_flow(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "import-ledger.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        case_id = "sqlite-import-ledger-1"
        payload = {
            "cases": [
                {
                    "case_id": case_id,
                    "status": "NEW",
                    "title": "Risk LOW: READ",
                    "risk_class": "LOW",
                    "risk_score": 0.21,
                    "event_ids": ["e-ledger-1"],
                    "invariant_hits": [],
                    "invariant_details": [],
                    "xai_summary": "import for operation ledger chain",
                    "audit_log": [],
                    "fingerprint": "fp|ledger|1",
                    "primary_asset_id": "plc-import-ledger",
                    "trigger_operation": "READ",
                    "created_at": "2026-05-11T11:00:00+00:00",
                    "dq_score": 1.0,
                    "dq_partial": False,
                    "dq_reasons": [],
                    "last_event_source": "plc_polling",
                }
            ],
            "mode": "upsert",
        }
        imported = client.post("/cases/import/full.json", json=payload)
        assert imported.status_code == 200
        assert imported.json()["imported"] == 1
        verified = client.get("/audit-ledger/operations/verify", params={"stream_key": f"import:{case_id}"})
        assert verified.status_code == 200
        body = verified.json()
        assert body["ok"] is True
        assert body["checked_entries"] >= 1


def test_audit_engagements_survive_new_app_instance_with_sqlite(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "audit-engagement.sqlite"

    def fake_load(p):
        d = load_risk_weights(p)
        d["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return d

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as c1:
        created = c1.post(
            "/audit-engagements",
            json={
                "customer": "Plant A",
                "scope": "5-10 day forensic audit service",
                "case_ids": ["cid-1"],
                "nda_signed": True,
                "evidence_intake_checklist": ["nda", "logs"],
            },
        )
        assert created.status_code == 200
        eid = created.json()["engagement_id"]
        assert c1.post(f"/audit-engagements/{eid}/findings", json={"finding": "log retention gap"}).status_code == 200

    with TestClient(create_app()) as c2:
        got = c2.get("/audit-engagements").json()
        assert len(got) == 1
        assert got[0]["engagement_id"] == eid
        assert "log retention gap" in got[0]["findings"]
