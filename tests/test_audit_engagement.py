from __future__ import annotations

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_audit_engagement_workflow_create_advance_finalize() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/audit-engagements",
        json={
            "customer": "ACME Plant",
            "scope": "ICS forensic audit for risk-layer evidence quality",
            "case_ids": ["case-1", "case-2"],
            "nda_signed": True,
            "evidence_intake_checklist": ["nda", "asset_inventory", "log_sources"],
        },
    )
    assert created.status_code == 200
    body = created.json()
    eid = body["engagement_id"]
    assert eid.startswith("ae-")
    assert body["status"] == "active"
    assert body["stages"][0]["status"] == "in_progress"
    assert body["stages"][1]["status"] == "pending"

    add_finding = client.post(f"/audit-engagements/{eid}/findings", json={"finding": "Missing Syslog retention policy"})
    assert add_finding.status_code == 200
    assert "Missing Syslog retention policy" in add_finding.json()["findings"]

    adv1 = client.post(f"/audit-engagements/{eid}/advance-stage", json={"note": "intake completed"})
    assert adv1.status_code == 200
    assert adv1.json()["stages"][0]["status"] == "completed"
    assert adv1.json()["stages"][1]["status"] == "in_progress"

    finalized = client.post(
        f"/audit-engagements/{eid}/final-report",
        json={
            "title": "Forensic Audit Service Report",
            "uri": "s3://forensic/reports/eid.pdf",
            "summary": "30-page structured report generated",
        },
    )
    assert finalized.status_code == 200
    fbody = finalized.json()
    assert fbody["status"] == "completed"
    assert fbody["final_report"]["title"] == "Forensic Audit Service Report"
    assert all(stage["status"] == "completed" for stage in fbody["stages"])


def test_audit_engagement_list_and_not_found() -> None:
    client = TestClient(create_app())
    assert client.get("/audit-engagements").status_code == 200
    assert client.get("/audit-engagements").json() == []
    assert client.get("/audit-engagements/missing").status_code == 404


def test_audit_engagement_export_report_json() -> None:
    client = TestClient(create_app())
    created = client.post(
        "/audit-engagements",
        json={
            "customer": "Plant Export",
            "scope": "Audit report export",
            "case_ids": ["case-z"],
            "nda_signed": True,
            "evidence_intake_checklist": ["nda"],
        },
    )
    eid = created.json()["engagement_id"]
    client.post(
        f"/audit-engagements/{eid}/final-report",
        json={"title": "Final", "uri": "s3://r/final.pdf", "summary": "done"},
    )
    report = client.get(f"/audit-engagements/{eid}/export/report.json")
    assert report.status_code == 200
    body = report.json()
    assert body["format"] == "TAKT Audit Engagement Report"
    assert body["engagement"]["engagement_id"] == eid
    assert body["has_final_report"] is True
    assert body["stages_completed"] == body["stages_total"]
