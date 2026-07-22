from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from takt.application.use_cases.case_findings import ArtifactInput, CaseFindingsUseCase
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.export.forensic_bundle import ZipForensicBundleBuilder
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore
from takt.interface_adapters.api.main import create_app


def test_finding_with_two_artifacts_is_append_only_and_visible() -> None:
    with TestClient(create_app()) as client:
        created = client.post(
            "/assess",
            json={"observed_at": "2026-06-01T10:00:00Z", "operation": "READ", "asset_id": "plc-find"},
        ).json()
        case_id = created["case_id"]
        event_id = client.get(f"/cases/{case_id}").json()["event_ids"][0]
        response = client.post(
            f"/cases/{case_id}/findings",
            json={
                "text": "Malicious loader contacted C2",
                "event_ids": [event_id],
                "artifacts": [
                    {"type": "hash", "value": "abc"},
                    {"type": "domain", "value": "evil.example"},
                ],
            },
        )
        assert response.status_code == 200
        assert len(response.json()["artifacts"]) == 2
        assert client.get(f"/cases/{case_id}/findings").json()[0]["text"] == "Malicious loader contacted C2"
        assert len(client.get(f"/cases/{case_id}/artifacts").json()) == 2


def test_sqlite_persists_findings_and_hash_chain(tmp_path) -> None:
    path = tmp_path / "cases.sqlite3"
    repo = SqliteCaseStore(path)
    now = datetime(2026, 6, 1, 10, tzinfo=UTC)
    try:
        repo.save(Case(
            case_id="case-1", status=CaseStatus.NEW, title="case", risk_class="LOW",
            risk_score=0.1, created_at=now, normalized_event_ids=["event-1"], burst_fingerprint="fp",
        ))
        use_case = CaseFindingsUseCase(repo)
        use_case.add_finding(
            "case-1", "analyst conclusion", ["event-1"],
            [ArtifactInput("hash", "abc"), ArtifactInput("domain", "evil.example")],
            actor="alice", clock=now,
        )
        assert repo.verify_audit_ledger("case-1")["ok"] is True
        assert repo.verify_operation_ledger()["ok"] is True
    finally:
        repo.close()
    reopened = SqliteCaseStore(path)
    try:
        case = reopened.get("case-1")
        assert case is not None and case.findings[0].text == "analyst conclusion"
        assert len(case.artifacts) == 2
        _, archive = ZipForensicBundleBuilder().build_case_bundle(case, generated_at=now)
        with ZipFile(BytesIO(archive)) as bundle:
            assert "findings.json" in bundle.namelist()
            assert "artifacts.json" in bundle.namelist()
    finally:
        reopened.close()
