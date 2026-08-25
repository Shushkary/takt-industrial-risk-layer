from __future__ import annotations

import json
from datetime import UTC
from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_manual_permit_exposes_organizational_document_model() -> None:
    from datetime import datetime

    from takt.domain.entities.case import ManualPermit, OrganizationalContextDocument

    permit = ManualPermit(
        permit_id="permit-1",
        case_id="case-1",
        work_order_number="WO-1",
        actor="operator",
        created_at=datetime(2026, 5, 5, 10, 0, tzinfo=UTC),
        asset_id="plc-01",
        operation="WRITE_COIL",
        verdict="legitimate",
        confidence=0.95,
        rationale="ok",
        counterfactual="no",
        action_class="управляющее воздействие",
        executor="Иванов И.И.",
        approver="Петров П.П.",
        valid_from="2026-05-05T09:00:00+00:00",
        valid_to="2026-05-05T12:00:00+00:00",
        document_status="утверждён",
        organizational_context_sha256="a" * 64,
    )
    doc = permit.organizational_document()
    assert isinstance(doc, OrganizationalContextDocument)
    assert doc.document_id == "WO-1"
    assert doc.document_type == "ручной наряд"
    assert doc.checksum_algorithm == "SHA-256"
    assert doc.checksum == "a" * 64


def test_manual_permit_attaches_to_case_and_audit() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-2026-0007",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "executor": "Иванов И.И.",
            "approver": "Петров П.П.",
            "valid_from": "2026-05-05T09:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
            "note": "подтвержденные плановые работы",
        },
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["work_order_number"] == "WO-2026-0007"
    assert payload["verdict"] == "legitimate"
    assert payload["confidence"] == 0.95
    assert payload["action_class"] == "управляющее воздействие"
    assert len(payload["organizational_context_sha256"]) == 64
    assert payload["executor"] == "Иванов И.И."
    assert payload["approver"] == "Петров П.П."
    assert "совпадают" in payload["rationale"]
    assert "нелегитимным" in payload["counterfactual"]

    detail = client.get(f"/cases/{case_id}").json()
    assert detail["manual_permits"][0]["work_order_number"] == "WO-2026-0007"
    assert detail["manual_permits"][0]["rationale"] == payload["rationale"]
    assert detail["manual_permits"][0]["organizational_context_sha256"] == payload["organizational_context_sha256"]
    assert detail["formal_verdict"]["value"] == "легитимное"
    assert detail["formal_verdict"]["context_match"]["matched"] is True
    assert detail["formal_verdict"]["context_match"]["score"] == 0.95
    assert detail["formal_verdict_records"][0]["prev"] == "неопределённое"
    assert detail["formal_verdict_records"][0]["next"] == "легитимное"
    assert detail["formal_verdict_records"][0]["score"] == 0.95
    assert detail["formal_verdict_records"][0]["source"] == "manual_permit"
    assert any("manual permit WO-2026-0007 attached" in line for line in detail["audit_log"])
    assert any("formal verdict change prev=неопределённое next=легитимное" in line for line in detail["audit_log"])

    verdict_history = client.get(f"/cases/{case_id}/formal-verdict/history")
    assert verdict_history.status_code == 200
    entries = verdict_history.json()["entries"]
    assert entries[0]["prev"] == "неопределённое"
    assert entries[0]["next"] == "легитимное"
    assert entries[0]["score"] == 0.95
    assert entries[0]["source"] == "manual_permit"

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    assert case_payload["formal_verdict_history"][0]["prev"] == "неопределённое"
    assert case_payload["formal_verdict_history"][0]["next"] == "легитимное"
    assert case_payload["formal_verdict_history"][0]["score"] == 0.95
    assert case_payload["formal_verdict_records"][0]["permit_id"] == payload["permit_id"]
    checks = {item["code"]: item for item in manifest["suitability_checks"]}
    assert checks["operator_history"]["ok"] is True
    assert checks["organizational_context_checksum"]["ok"] is True


def test_manual_permit_with_partial_org_context_is_undetermined() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={"work_order_number": "WO-PARTIAL", "asset_id": "plc-01", "operation": "WRITE_COIL"},
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["verdict"] == "undetermined"
    assert payload["confidence"] == 0.7
    assert "организационный контекст неполный" in payload["rationale"]
    detail = client.get(f"/cases/{case_id}").json()
    assert detail["formal_verdict"]["value"] == "неопределённое"
    assert detail["formal_verdict"]["context_match"]["score"] == 0.7


def test_manual_permit_rejects_event_outside_work_window() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-WINDOW",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "executor": "Иванов И.И.",
            "approver": "Петров П.П.",
            "valid_from": "2026-05-05T11:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
        },
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["verdict"] == "undetermined"
    assert "событие вне окна работ" in payload["rationale"]
    detail = client.get(f"/cases/{case_id}").json()
    assert detail["formal_verdict"]["value"] == "неопределённое"


def test_manual_permit_rejects_mismatched_action_class() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-ACTION-CLASS",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "action_class": "администрирование",
            "executor": "Иванов И.И.",
            "approver": "Петров П.П.",
            "valid_from": "2026-05-05T09:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
        },
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["verdict"] == "illegitimate"
    assert "класс действия наряда" in payload["rationale"]


def test_manual_permit_rejects_mismatched_operator_id() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-05T10:00:00+00:00",
            "operation": "WRITE_COIL",
            "asset_id": "plc-01",
            "operator_id": "operator-a",
        },
    )
    case_id = created.json()["case_id"]
    detail = client.get(f"/cases/{case_id}").json()
    assert detail["operator_id"] == "operator-a"

    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-OPERATOR",
            "asset_id": "plc-01",
            "operation": "WRITE_COIL",
            "executor": "operator-b",
            "approver": "supervisor",
            "valid_from": "2026-05-05T09:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
        },
    )
    assert permit.status_code == 200
    payload = permit.json()["permit"]
    assert payload["verdict"] == "illegitimate"
    assert "исполнитель наряда" in payload["rationale"]


def test_manual_permit_is_in_forensic_bundle_case_json() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    r = client.post(
        f"/cases/{case_id}/manual-permits",
        json={
            "work_order_number": "WO-2026-0008",
            "asset_id": "plc-02",
            "operation": "WRITE_COIL",
            "executor": "Иванов И.И.",
            "approver": "Петров П.П.",
            "valid_from": "2026-05-05T09:00:00+00:00",
            "valid_to": "2026-05-05T12:00:00+00:00",
            "document_status": "утверждён",
        },
    )
    assert r.status_code == 200
    assert r.json()["permit"]["verdict"] == "illegitimate"
    assert "не совпадает" in r.json()["permit"]["rationale"]
    assert "Вывод стал бы легитимным" in r.json()["permit"]["counterfactual"]

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    org_context = case_payload["manual_permits"][0]["organizational_context"]
    assert "operator_id" in case_payload
    assert org_context["document_id"] == "WO-2026-0008"
    assert org_context["action_class"] == "управляющее воздействие"
    assert org_context["checksum_algorithm"] == "SHA-256"
    assert org_context["checksum"] == case_payload["manual_permits"][0]["organizational_context_sha256"]
    assert len(org_context["checksum"]) == 64
    assert org_context["executor"] == "Иванов И.И."
    assert org_context["approver"] == "Петров П.П."
    assert case_payload["manual_permits"][0]["verdict"] == "illegitimate"
    assert "counterfactual" in case_payload["manual_permits"][0]
    assert case_payload["formal_verdict"]["value"] == "нелегитимное"
    assert case_payload["formal_verdict"]["context_match"]["matched"] is False
    assert case_payload["formal_verdict"]["context_match"]["score"] == 0.65


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
        r = client.post(
            f"/cases/{case_id}/manual-permits",
            json={
                "work_order_number": "WO-SQLITE",
                "asset_id": "plc-01",
                "operation": "WRITE_COIL",
                "executor": "Иванов И.И.",
                "approver": "Петров П.П.",
                "valid_from": "2026-05-05T09:00:00+00:00",
                "valid_to": "2026-05-05T12:00:00+00:00",
                "document_status": "утверждён",
            },
        )
        assert r.status_code == 200

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)
    with TestClient(create_app()) as client:
        detail = client.get(f"/cases/{case_id}").json()
        assert detail["manual_permits"][0]["work_order_number"] == "WO-SQLITE"
        assert detail["manual_permits"][0]["executor"] == "Иванов И.И."
        assert len(detail["manual_permits"][0]["organizational_context_sha256"]) == 64
        assert detail["formal_verdict"]["value"] == "легитимное"


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


def test_operator_action_history_records_view_and_additional_review() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]

    viewed = client.post(
        f"/cases/{case_id}/operator-actions/viewed",
        json={"note": "оператор открыл дело"},
    )
    assert viewed.status_code == 200
    assert viewed.json()["action"] == "viewed"

    review = client.post(
        f"/cases/{case_id}/operator-actions/additional-review",
        json={"reason": "требуется подтверждение начальника смены"},
    )
    assert review.status_code == 200
    assert review.json()["action"] == "additional_review"

    history = client.get(f"/cases/{case_id}/operator-actions/history")
    assert history.status_code == 200
    entries = history.json()["entries"]
    assert [entry["action"] for entry in entries] == ["viewed", "additional_review"]
    assert entries[0]["note"] == "оператор открыл дело"
    assert entries[1]["reason"] == "требуется подтверждение начальника смены"

    detail = client.get(f"/cases/{case_id}").json()
    assert any("operator action viewed" in line for line in detail["audit_log"])
    assert any("operator action additional_review" in line for line in detail["audit_log"])

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    assert [entry["action"] for entry in case_payload["operator_action_history"]] == ["viewed", "additional_review"]
    assert case_payload["operator_action_history"][0]["note"] == "оператор открыл дело"
    assert case_payload["operator_action_history"][1]["reason"] == "требуется подтверждение начальника смены"


def test_operator_additional_review_requires_reason() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]
    response = client.post(f"/cases/{case_id}/operator-actions/additional-review", json={})
    assert response.status_code == 400
    assert response.json()["detail"] == "reason is required"


def test_operator_can_confirm_formal_verdict_without_manual_permit() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/assess",
        json={"observed_at": "2026-05-05T10:00:00+00:00", "operation": "WRITE_COIL", "asset_id": "plc-01"},
    )
    case_id = created.json()["case_id"]

    confirmed = client.post(
        f"/cases/{case_id}/formal-verdict/confirmation",
        json={
            "verdict": "нелегитимное",
            "confidence": 0.9,
            "reason": "начальник смены подтвердил отсутствие наряда",
            "note": "активное управление не выполнялось",
        },
    )
    assert confirmed.status_code == 200
    record = confirmed.json()["record"]
    assert record["prev"] == "неопределённое"
    assert record["next"] == "нелегитимное"
    assert record["score"] == 0.9
    assert record["source"] == "operator_confirmation"

    detail = client.get(f"/cases/{case_id}").json()
    assert detail["formal_verdict"]["value"] == "нелегитимное"
    assert detail["formal_verdict"]["source"] == "ручное подтверждение оператора"
    assert detail["formal_verdict"]["context_match"]["source"] == "operator_confirmation"
    assert detail["formal_verdict_records"][0]["reason"] == "начальник смены подтвердил отсутствие наряда"

    verdict_history = client.get(f"/cases/{case_id}/formal-verdict/history").json()["entries"]
    assert verdict_history[0]["next"] == "нелегитимное"

    operator_history = client.get(f"/cases/{case_id}/operator-actions/history").json()["entries"]
    assert operator_history[0]["action"] == "formal_verdict_confirmation"
    assert operator_history[0]["reason"] == "начальник смены подтвердил отсутствие наряда"

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    with ZipFile(BytesIO(archive.content)) as zf:
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    assert case_payload["formal_verdict"]["value"] == "нелегитимное"
    assert case_payload["formal_verdict_records"][0]["source"] == "operator_confirmation"
    assert case_payload["operator_action_history"][0]["action"] == "formal_verdict_confirmation"
