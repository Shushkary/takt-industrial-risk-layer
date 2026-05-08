from __future__ import annotations

import json
from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_manual_permit_attaches_to_case_and_audit() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-01",
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-2026-0007",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "note": "field engineer confirmed planned maintenance",
        },
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["work_order_number"] == "WO-2026-0007"
    assert payload["verdict"] == "legitimate"
    assert payload["confidence"] == 0.85
    assert "совпадают" in payload["rationale"]
    assert "нелегитимным" in payload["counterfactual"]

    detail = client.get(f"/cases/{case_id}").json()
    assert detail["manual_permits"][0]["work_order_number"] == "WO-2026-0007"
    assert detail["manual_permits"][0]["rationale"] == payload["rationale"]
    assert any("manual permit WO-2026-0007 attached" in line for line in detail["audit_log"])


def test_manual_permit_is_in_forensic_bundle_case_json() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-01",
        },
    )
    case_id = created.json()["case_id"]
    r = client.post(
        f"/cases/{case_id}/manual-permits",
        json={"work_order_number": "WO-2026-0008", "asset_id": "plc-02", "operation": "WRITE_COIL"},
    )
    assert r.status_code == 200
    assert r.json()["permit"]["verdict"] == "illegitimate"
    assert "не совпадает" in r.json()["permit"]["rationale"]
    assert "Вывод стал бы легитимным" in r.json()["permit"]["counterfactual"]

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    assert case_payload["manual_permits"][0]["work_order_number"] == "WO-2026-0008"
    assert case_payload["manual_permits"][0]["verdict"] == "illegitimate"
    assert "counterfactual" in case_payload["manual_permits"][0]


def test_manual_permit_persists_in_sqlite(tmp_path, monkeypatch) -> None:
    from takt.infrastructure.config.weights_loader import load_risk_weights

    db = tmp_path / "manual-permits.sqlite"

    def fake_load(path):
        cfg = load_risk_weights(path)
        cfg["storage"] = {"backend": "sqlite", "sqlite_path": str(db)}
        return cfg

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        created = client.post(
            "/assess",
            json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
        )
        case_id = created.json()["case_id"]
        r = client.post(f"/cases/{case_id}/manual-permits", json={"work_order_number": "WO-SQLITE"})
        assert r.status_code == 200

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        detail = client.get(f"/cases/{case_id}").json()
        assert detail["manual_permits"][0]["work_order_number"] == "WO-SQLITE"


def test_case_decision_record_is_in_case_and_forensic_bundle() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    decision = client.post(
        f"/cases/{case_id}/decision",
        json={"status": "TRIAGE", "reason": "manual review started"},
    )
    assert decision.status_code == 200
    detail = client.get(f"/cases/{case_id}").json()
    assert detail["decision_records"][0]["prev_status"] == "NEW"
    assert detail["decision_records"][0]["next_status"] == "TRIAGE"
    assert detail["decision_records"][0]["reason"] == "manual review started"
    assert detail["decision_records"][0]["request_id"]

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    assert case_payload["decision_records"][0]["reason"] == "manual review started"
