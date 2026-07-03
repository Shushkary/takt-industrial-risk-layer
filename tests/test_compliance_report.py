from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from takt.domain.entities.case import Case, CaseDecisionRecord, CaseStatus, ManualPermit
from takt.interface_adapters.api.main import create_app


def test_compliance_data_quality_report_counts_case_readiness() -> None:
    app = create_app()
    case_id = "comp-1"
    app.state.repo.save(
        Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title="Risk HIGH: WRITE_COIL",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
            normalized_event_ids=["ev-comp-1"],
            xai_summary="why",
            burst_fingerprint="plc-01|WRITE_COIL|5927148",
            primary_asset_id="plc-01",
            trigger_operation="WRITE_COIL",
            invariant_hits=["blind_command"],
            dq_score=0.92,
            dq_partial=False,
            last_event_source="plc_polling",
        )
    )
    client = TestClient(app)

    early_report = client.get("/compliance/data-quality-report")
    assert early_report.status_code == 200
    early_body = early_report.json()
    assert early_body["total_cases"] == 1
    assert early_body["cases_without_manual_permit"] == 1
    assert early_body["high_risk_without_decision"] == 1
    assert early_body["cases_with_forensic_bundle_audit"] == 0
    assert early_body["remediation_attempts_by_kind"] == {}
    assert early_body["remediation_attempts_by_status"] == {}
    assert early_body["audit_engagements"] == {"total": 0, "active": 0, "completed": 0, "with_final_report": 0}
    early_flags = {f["code"]: f for f in early_body["readiness_flags"]}
    assert early_flags["high_risk_has_hitl_decision"]["ok"] is False
    assert early_flags["forensic_bundle_generated_for_all_cases"]["ok"] is False
    early_readiness = client.get("/compliance/forensic-readiness")
    assert early_readiness.status_code == 200
    early_readiness_body = early_readiness.json()
    assert early_readiness_body["ready_cases"] == 0
    assert early_readiness_body["not_ready_cases"] == 1
    assert early_readiness_body["allowed_missing_codes"] == [
        "complete_observability",
        "forensic_bundle_audit",
        "hitl_decision",
        "invariant_evidence",
        "manual_permit",
    ]
    assert early_readiness_body["missing_by_code"] == {
        "forensic_bundle_audit": 1,
        "hitl_decision": 1,
        "manual_permit": 1,
    }
    assert early_readiness_body["cases"][0]["case_id"] == case_id
    assert early_readiness_body["cases"][0]["ready"] is False
    assert early_readiness_body["cases"][0]["missing"] == [
        "hitl_decision",
        "manual_permit",
        "forensic_bundle_audit",
    ]
    early_checklist = client.get(f"/cases/{case_id}/compliance/evidence-checklist")
    assert early_checklist.status_code == 200
    early_checklist_body = early_checklist.json()
    assert early_checklist_body["case_id"] == case_id
    assert early_checklist_body["ready"] is False
    assert early_checklist_body["remediation_summary"] == {
        "attach_manual_permit": 1,
        "generate_forensic_bundle": 1,
        "submit_decision": 1,
    }
    early_items = {item["code"]: item for item in early_checklist_body["items"]}
    assert early_items["complete_observability"]["ok"] is True
    assert early_items["invariant_evidence"]["ok"] is True
    assert early_items["hitl_decision"]["ok"] is False
    assert early_items["hitl_decision"]["remediation_kind"] == "submit_decision"
    assert early_items["hitl_decision"]["remediation_action"] == f"POST /cases/{case_id}/decision с основанием оператора"
    assert early_items["manual_permit"]["ok"] is False
    assert early_items["manual_permit"]["remediation_kind"] == "attach_manual_permit"
    assert early_items["manual_permit"]["remediation_action"] == (
        f"POST /cases/{case_id}/manual-permits с номером наряда"
    )
    assert early_items["manual_permit"]["remediation_attempted"] is False
    assert early_items["manual_permit"]["latest_remediation_status"] == ""
    assert early_items["forensic_bundle_audit"]["ok"] is False
    assert early_items["forensic_bundle_audit"]["remediation_kind"] == "generate_forensic_bundle"
    assert early_items["forensic_bundle_audit"]["remediation_action"] == f"GET /cases/{case_id}/forensic-bundle.zip"

    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={"work_order_number": "WO-COMP-1", "asset_id": "plc-01", "operation": "WRITE_COIL"},
    )
    assert permit.status_code == 200
    decision = client.post(
        f"/cases/{case_id}/decision",
        json={"status": "CONFIRMED", "reason": "reviewed for compliance report"},
    )
    assert decision.status_code == 200
    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200

    report = client.get("/compliance/data-quality-report")
    assert report.status_code == 200
    body = report.json()
    assert body["total_cases"] == 1
    assert body["open_cases"] == 0
    assert body["by_status"] == {"CONFIRMED": 1}
    assert body["by_risk_class"]["HIGH"] == 1
    assert body["cases_without_manual_permit"] == 0
    assert body["high_risk_without_decision"] == 0
    assert body["cases_with_forensic_bundle_audit"] == 1
    assert body["invariant_hits"]
    assert body["audit_engagements"]["total"] == 0
    flags = {f["code"]: f for f in body["readiness_flags"]}
    assert flags["high_risk_has_hitl_decision"]["ok"] is True
    assert flags["forensic_bundle_generated_for_all_cases"]["ok"] is True
    readiness = client.get("/compliance/forensic-readiness")
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready_cases"] == 1
    assert readiness_body["not_ready_cases"] == 0
    assert readiness_body["missing_by_code"] == {}
    assert readiness_body["cases"][0]["case_id"] == case_id
    assert readiness_body["cases"][0]["ready"] is True
    assert readiness_body["cases"][0]["missing"] == []
    checklist = client.get(f"/cases/{case_id}/compliance/evidence-checklist")
    assert checklist.status_code == 200
    checklist_body = checklist.json()
    assert checklist_body["ready"] is True
    assert checklist_body["remediation_summary"] == {}
    assert all(item["ok"] for item in checklist_body["items"])
    assert all(item["remediation_kind"] == "" for item in checklist_body["items"])
    assert all(item["remediation_action"] == "" for item in checklist_body["items"])


def test_case_evidence_checklist_returns_404_for_unknown_case() -> None:
    client = TestClient(create_app())
    r = client.get("/cases/missing/compliance/evidence-checklist")
    assert r.status_code == 404
    assert r.json()["detail"] == "case not found"


def test_remediation_kinds_catalog_lists_machine_readable_actions() -> None:
    client = TestClient(create_app())
    r = client.get("/compliance/remediation-kinds")
    assert r.status_code == 200
    kinds = {item["kind"]: item["description"] for item in r.json()["kinds"]}
    assert set(kinds) == {
        "attach_manual_permit",
        "generate_forensic_bundle",
        "ingest_telemetry",
        "rerun_assessment",
        "submit_decision",
    }
    assert all(kinds.values())
    assert kinds["attach_manual_permit"] == "Прикрепить ручной наряд к делу."
    assert "доказательный ZIP-пакет" in kinds["generate_forensic_bundle"]
    assert "решение оператора" in kinds["submit_decision"]


def test_compliance_mode_report_exposes_boundaries_and_operator_control(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_COMPLIANCE_MODE", "1")
    app = create_app()
    case_id = "compliance-mode-1"
    app.state.repo.save(
        Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title="Risk HIGH: WRITE_COIL",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
            invariant_hits=["blind_command"],
            dq_partial=True,
        )
    )
    client = TestClient(app)

    r = client.get("/compliance/mode")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "compliance"
    assert body["compliance_enabled"] is True
    assert body["product_boundary"]["is_crypto_tool"] is False
    assert body["product_boundary"]["has_active_control"] is False
    assert body["product_boundary"]["requires_operator_final_decision"] is True
    assert "не является СКЗИ" in body["product_boundary"]["crypto_note"]
    assert "не выполняет блокировку" in body["product_boundary"]["active_control_note"]
    assert body["manual_confirmation"] == {
        "required_for_high_risk": True,
        "decision_endpoint": "/cases/{case_id}/decision",
        "permit_endpoint": "/cases/{case_id}/manual-permits",
        "reason_required": True,
    }
    assert body["service_desk_context"]["supported"] is True
    assert "утверждающий" in body["service_desk_context"]["fields"]
    assert body["readiness"]["total_cases"] == 1
    assert body["readiness"]["not_ready_cases"] == 1
    assert body["readiness"]["dq_partial_count"] == 1
    assert body["readiness"]["high_risk_without_decision"] == 1
    assert body["reports"]["forensic_readiness"] == "/compliance/forensic-readiness"


def test_record_remediation_attempt_updates_case_and_audit() -> None:
    app = create_app()
    case_id = "remed-1"
    app.state.repo.save(
        Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title="Risk HIGH: WRITE_COIL",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
            invariant_hits=["blind_command"],
        )
    )
    client = TestClient(app)

    r = client.post(
        f"/cases/{case_id}/compliance/remediations",
        json={
            "kind": "attach_manual_permit",
            "status": "started",
            "action": "opened_work_order",
            "result": "work order WO-77 created",
            "note": "operator opened work order",
        },
    )
    assert r.status_code == 200
    attempt = r.json()["attempt"]
    assert attempt["case_id"] == case_id
    assert attempt["kind"] == "attach_manual_permit"
    assert attempt["status"] == "started"
    assert attempt["action"] == "opened_work_order"
    assert attempt["result"] == "work order WO-77 created"
    assert attempt["readiness_before"] is False
    assert attempt["readiness_after"] is False
    assert attempt["note"] == "operator opened work order"

    detail = client.get(f"/cases/{case_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["remediation_attempts"][0]["attempt_id"] == attempt["attempt_id"]
    assert any("remediation attempt kind=attach_manual_permit status=started" in line for line in body["audit_log"])

    checklist = client.get(f"/cases/{case_id}/compliance/evidence-checklist")
    assert checklist.status_code == 200
    items = {item["code"]: item for item in checklist.json()["items"]}
    assert items["manual_permit"]["remediation_kind"] == "attach_manual_permit"
    assert items["manual_permit"]["remediation_attempted"] is True
    assert items["manual_permit"]["latest_remediation_status"] == "started"

    listing = client.get("/compliance/remediations", params={"case_id": case_id, "kind": "attach_manual_permit"})
    assert listing.status_code == 200
    assert [item["attempt_id"] for item in listing.json()["attempts"]] == [attempt["attempt_id"]]
    filtered_out = client.get("/compliance/remediations", params={"case_id": case_id, "status": "completed"})
    assert filtered_out.status_code == 200
    assert filtered_out.json()["attempts"] == []
    report = client.get("/compliance/data-quality-report")
    assert report.status_code == 200
    assert report.json()["remediation_attempts_by_kind"] == {"attach_manual_permit": 1}
    assert report.json()["remediation_attempts_by_status"] == {"started": 1}

    invalid = client.post(f"/cases/{case_id}/compliance/remediations", json={"kind": "typo"})
    assert invalid.status_code == 400
    assert "invalid remediation kind" in invalid.json()["detail"]
    invalid_list = client.get("/compliance/remediations", params={"kind": "typo"})
    assert invalid_list.status_code == 400
    assert "invalid remediation kind" in invalid_list.json()["detail"]


def test_remediation_readiness_recheck_updates_attempt_and_audit() -> None:
    app = create_app()
    case_id = "remed-recheck-1"
    app.state.repo.save(
        Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title="Risk HIGH: WRITE_COIL",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
            invariant_hits=["blind_command"],
        )
    )
    client = TestClient(app)
    created = client.post(
        f"/cases/{case_id}/compliance/remediations",
        json={"kind": "attach_manual_permit", "status": "started", "action": "open_wo"},
    )
    assert created.status_code == 200
    attempt_id = created.json()["attempt"]["attempt_id"]

    recheck = client.post(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness",
        json={"attempt_id": attempt_id, "note": "checked after execution"},
    )
    assert recheck.status_code == 200
    body = recheck.json()
    assert body["case_id"] == case_id
    assert body["ready"] is False
    assert "manual_permit" in body["missing_codes"]
    assert body["attempt"]["attempt_id"] == attempt_id
    assert body["attempt"]["status"] == "failed"
    assert body["attempt"]["readiness_after"] is False
    assert "checked after execution" in body["attempt"]["note"]

    detail = client.get(f"/cases/{case_id}")
    assert detail.status_code == 200
    assert any("remediation readiness recheck ready=False" in line for line in detail.json()["audit_log"])
    history = client.get(f"/cases/{case_id}/compliance/remediations/recheck-readiness/history")
    assert history.status_code == 200
    assert history.headers["x-total-count"] == "1"
    history_body = history.json()
    assert history_body["case_id"] == case_id
    assert history_body["total_matched"] == 1
    assert len(history_body["entries"]) == 1
    assert history_body["entries"][0]["attempt_id"] == attempt_id
    assert history_body["entries"][0]["ready"] is False
    assert "manual_permit" in history_body["entries"][0]["missing_codes"]
    assert history_body["entries"][0]["actor"]
    history_by_attempt = client.get(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness/history",
        params={"attempt_id": attempt_id},
    )
    assert history_by_attempt.status_code == 200
    assert history_by_attempt.json()["total_matched"] == 1
    assert len(history_by_attempt.json()["entries"]) == 1
    history_ready_false = client.get(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness/history",
        params={"ready": "false"},
    )
    assert history_ready_false.status_code == 200
    assert history_ready_false.json()["total_matched"] == 1
    assert len(history_ready_false.json()["entries"]) == 1

    permit = client.post(
        f"/cases/{case_id}/manual-permits",
        json={"work_order_number": "WO-RR-1", "asset_id": "plc-01", "operation": "WRITE_COIL"},
    )
    assert permit.status_code == 200
    decision = client.post(
        f"/cases/{case_id}/decision",
        json={"status": "CONFIRMED", "reason": "ready after remediation"},
    )
    assert decision.status_code == 200
    bundle = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert bundle.status_code == 200
    recheck_ready = client.post(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness",
        json={"attempt_id": attempt_id},
    )
    assert recheck_ready.status_code == 200
    assert recheck_ready.json()["ready"] is True
    history_ready_true = client.get(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness/history",
        params={"ready": "true"},
    )
    assert history_ready_true.status_code == 200
    assert history_ready_true.json()["total_matched"] == 1
    ready_entries = history_ready_true.json()["entries"]
    assert len(ready_entries) == 1
    assert ready_entries[0]["attempt_id"] == attempt_id
    assert ready_entries[0]["ready"] is True

    not_found = client.post(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness",
        json={"attempt_id": "missing-id"},
    )
    assert not_found.status_code == 404
    assert not_found.json()["detail"] == "remediation attempt not found"
    history_missing = client.get("/cases/missing/compliance/remediations/recheck-readiness/history")
    assert history_missing.status_code == 404
    assert history_missing.json()["detail"] == "case not found"
    history_limit = client.get(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness/history",
        params={"limit": 1},
    )
    assert history_limit.status_code == 200
    assert history_limit.headers["x-total-count"] == "2"
    assert 'rel="next"' in history_limit.headers["link"]
    assert history_limit.json()["total_matched"] == 2
    assert len(history_limit.json()["entries"]) == 1
    history_offset = client.get(
        f"/cases/{case_id}/compliance/remediations/recheck-readiness/history",
        params={"limit": 1, "offset": 1},
    )
    assert history_offset.status_code == 200
    assert history_offset.headers["x-total-count"] == "2"
    assert 'rel="prev"' in history_offset.headers["link"]
    assert history_offset.json()["total_matched"] == 2
    assert len(history_offset.json()["entries"]) == 1
    assert history_offset.json()["entries"][0]["ready"] is False


def test_forensic_readiness_can_return_only_not_ready_cases() -> None:
    app = create_app()
    app.state.repo.save(
        Case(
            case_id="ready-1",
            status=CaseStatus.CONFIRMED,
            title="Ready case",
            risk_class="HIGH",
            risk_score=0.82,
            created_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
            invariant_hits=["blind_command"],
            audit_log=["2026-05-05T10:00:00+00:00 | forensic bundle generated root_hash=abc signature_status=unsigned_mvp"],
            manual_permits=[
                ManualPermit(
                    permit_id="permit-ready-1",
                    case_id="ready-1",
                    work_order_number="WO-READY-1",
                    actor="test",
                    created_at=datetime(2026, 5, 5, 10, 1, tzinfo=timezone.utc),
                    asset_id="plc-01",
                    operation="WRITE_COIL",
                    verdict="legitimate",
                    confidence=0.9,
                    rationale="planned maintenance",
                    counterfactual="would be suspicious without permit",
                )
            ],
            decision_records=[
                CaseDecisionRecord(
                    ts=datetime(2026, 5, 5, 10, 2, tzinfo=timezone.utc),
                    actor="test",
                    prev_status="TRIAGE",
                    next_status="CONFIRMED",
                    reason="reviewed",
                )
            ],
        )
    )
    client = TestClient(app)
    app.state.repo.save(
        Case(
            case_id="blocked-1",
            status=CaseStatus.TRIAGE,
            title="Blocked case",
            risk_class="HIGH",
            risk_score=0.83,
            created_at=datetime(2026, 5, 5, 11, 0, tzinfo=timezone.utc),
            invariant_hits=["blind_command"],
        )
    )

    r = client.get("/compliance/forensic-readiness", params={"only_not_ready": "true"})
    assert r.status_code == 200
    body = r.json()
    assert body["total_cases"] == 2
    assert body["ready_cases"] == 1
    assert body["not_ready_cases"] == 1
    assert [item["case_id"] for item in body["cases"]] == ["blocked-1"]
    by_code = client.get("/compliance/forensic-readiness", params={"missing_code": "manual_permit"})
    assert by_code.status_code == 200
    assert [item["case_id"] for item in by_code.json()["cases"]] == ["blocked-1"]
    no_match = client.get("/compliance/forensic-readiness", params={"missing_code": "complete_observability"})
    assert no_match.status_code == 200
    assert no_match.json()["cases"] == []
    invalid = client.get("/compliance/forensic-readiness", params={"missing_code": "typo"})
    assert invalid.status_code == 400
    assert "invalid missing_code" in invalid.json()["detail"]
