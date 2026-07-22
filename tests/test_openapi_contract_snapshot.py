from __future__ import annotations

from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


EXPECTED_ROUTE_CONTRACTS = [
    ("POST", "/assess", ("Ingest",), "AssessResponse"),
    ("POST", "/assess/demo", ("Ingest",), "AssessResponse"),
    ("GET", "/audit-engagements", ("Analytics",), "AuditEngagementOut"),
    ("POST", "/audit-engagements", ("Analytics",), "AuditEngagementOut"),
    ("GET", "/audit-engagements/{engagement_id}", ("Analytics",), "AuditEngagementOut"),
    ("POST", "/audit-engagements/{engagement_id}/advance-stage", ("Analytics",), "AuditEngagementOut"),
    ("GET", "/audit-engagements/{engagement_id}/export/report.json", ("Analytics",), "AuditEngagementReportOut"),
    ("POST", "/audit-engagements/{engagement_id}/final-report", ("Analytics",), "AuditEngagementOut"),
    ("POST", "/audit-engagements/{engagement_id}/findings", ("Analytics",), "AuditEngagementOut"),
    ("GET", "/audit-ledger/operations/verify", ("Analytics",), None),
    ("POST", "/backtest/fixture", ("Analytics",), "BacktestFixtureResponse"),
    ("GET", "/cases", ("Cases",), "CaseSummary"),
    ("GET", "/cases/export/full.json", ("Export",), "CasesFullExportResponse"),
    ("POST", "/cases/import/full.json", ("Export",), "CasesImportResponse"),
    ("GET", "/cases/stats", ("Cases",), "CasesStatsResponse"),
    ("GET", "/cases/{case_id}", ("Cases",), "CaseDetail"),
    ("GET", "/cases/{case_id}/attack-chain", ("Cases",), None),
    ("GET", "/cases/{case_id}/workspace", ("Cases",), None),
    ("GET", "/cases/{case_id}/audit-ledger/verify", ("Analytics",), None),
    ("GET", "/cases/{case_id}/compliance/evidence-checklist", ("Analytics",), None),
    ("POST", "/cases/{case_id}/compliance/remediations", ("Analytics",), None),
    ("POST", "/cases/{case_id}/compliance/remediations/recheck-readiness", ("Analytics",), None),
    ("GET", "/cases/{case_id}/compliance/remediations/recheck-readiness/history", ("Analytics",), None),
    ("POST", "/cases/{case_id}/decision", ("Cases",), "CaseDecisionResponse"),
    ("POST", "/cases/{case_id}/events/attach", ("Cases",), None),
    ("POST", "/cases/{case_id}/events/{event_id}/detach", ("Cases",), None),
    ("GET", "/cases/{case_id}/findings", ("Cases",), None),
    ("POST", "/cases/{case_id}/findings", ("Cases",), None),
    ("GET", "/cases/{case_id}/export.pdf", ("Export",), None),
    ("GET", "/cases/{case_id}/export/gossopka-official-transport.json", ("Export",), None),
    ("GET", "/cases/{case_id}/export/gossopka-official.json", ("Export",), None),
    ("GET", "/cases/{case_id}/export/gossopka-transport.json", ("Export",), None),
    ("GET", "/cases/{case_id}/export/gossopka.json", ("Export",), None),
    ("GET", "/cases/{case_id}/export/siem.json", ("Export",), "SiemCaseExportPayload"),
    ("GET", "/cases/{case_id}/forensic-bundle.zip", ("Export",), None),
    ("GET", "/cases/{case_id}/forensic-bundle/manifest", ("Export",), None),
    ("POST", "/cases/{case_id}/formal-verdict/confirmation", ("Cases",), None),
    ("GET", "/cases/{case_id}/formal-verdict/history", ("Cases",), None),
    ("POST", "/cases/{case_id}/manual-permits", ("Cases",), None),
    ("GET", "/cases/{case_id}/artifacts", ("Cases",), None),
    ("POST", "/cases/{case_id}/artifacts", ("Cases",), None),
    ("POST", "/cases/{case_id}/merge", ("Cases",), None),
    ("POST", "/cases/{case_id}/operator-actions/additional-review", ("Cases",), None),
    ("GET", "/cases/{case_id}/operator-actions/history", ("Cases",), None),
    ("POST", "/cases/{case_id}/operator-actions/viewed", ("Cases",), None),
    ("POST", "/cases/{case_id}/split", ("Cases",), None),
    ("GET", "/catalog/event-sources", ("Catalog",), "EventSourceCatalogItem"),
    ("GET", "/compliance/data-quality-report", ("Analytics",), None),
    ("GET", "/compliance/forensic-readiness", ("Analytics",), None),
    ("GET", "/compliance/mode", ("Analytics",), None),
    ("GET", "/compliance/remediation-kinds", ("Analytics",), None),
    ("GET", "/compliance/remediations", ("Analytics",), None),
    ("GET", "/data-quality", ("System",), "DataQualityResponse"),
    ("POST", "/events", ("Ingest",), "AssessResponse"),
    ("POST", "/events/batch", ("Ingest",), "BatchAssessResponse"),
    ("GET", "/entities/{entity_type}/{entity_id}/card", ("Entities",), None),
    ("GET", "/events/search", ("Events",), None),
    ("POST", "/forensic-bundle/verify", ("Export",), None),
    ("GET", "/health", ("System",), "HealthResponse"),
    ("HEAD", "/health", ("System",), None),
    ("POST", "/integrations/ingest/ipfix", ("Ingest",), "AssessResponse"),
    ("POST", "/integrations/ingest/netflow", ("Ingest",), "AssessResponse"),
    ("POST", "/integrations/ingest/snmp/trap", ("Ingest",), "AssessResponse"),
    ("POST", "/integrations/ingest/syslog/rfc5424", ("Ingest",), "AssessResponse"),
    ("POST", "/integrations/siem/forward", ("Integrations",), "SiemForwardResponse"),
    ("POST", "/integrations/siem/forward/async", ("Integrations",), "SiemForwardAsyncResponse"),
    ("GET", "/invariants", ("Catalog",), "InvariantCatalogItem"),
    ("GET", "/live", ("System",), "LiveResponse"),
    ("HEAD", "/live", ("System",), None),
    ("GET", "/ready", ("System",), "ReadyResponse"),
    ("HEAD", "/ready", ("System",), None),
    ("GET", "/topology/demo-graph", ("Catalog",), "DemoTopologyResponse"),
]


def _route_contracts_from_openapi(client: TestClient) -> list[tuple[str, str, tuple[str, ...], str | None]]:
    spec = client.get("/openapi.json").json()
    contracts: list[tuple[str, str, tuple[str, ...], str | None]] = []
    for path, path_item in spec["paths"].items():
        for method, operation in path_item.items():
            if method not in {"get", "head", "post", "put", "patch", "delete"}:
                continue
            response_model = _first_schema_name(operation.get("responses", {}).get("200", {}))
            contracts.append((method.upper(), path, tuple(operation.get("tags", [])), response_model))
    return sorted(contracts, key=lambda item: (item[1], item[0]))


def _first_schema_name(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    if "$ref" in value and isinstance(value["$ref"], str):
        return value["$ref"].split("/")[-1]
    for key in ("schema", "items"):
        found = _first_schema_name(value.get(key))
        if found:
            return found
    content = value.get("content")
    if isinstance(content, dict):
        for media_type in sorted(content):
            found = _first_schema_name(content[media_type])
            if found:
                return found
    return None


def test_openapi_route_contract_snapshot() -> None:
    """Sprint 0 baseline: method/path/tag/200-schema must not drift during API split."""
    client = TestClient(create_app())
    assert _route_contracts_from_openapi(client) == sorted(EXPECTED_ROUTE_CONTRACTS, key=lambda item: (item[1], item[0]))


def test_sprint0_backend_public_smoke_contracts() -> None:
    client = TestClient(create_app())
    for path in ("/live", "/ready", "/health", "/invariants", "/cases", "/cases/stats", "/compliance/mode", "/topology/demo-graph"):
        assert client.get(path).status_code == 200, path
    assert client.get("/audit-ledger/operations/verify").status_code in {200, 501}

    created = client.post(
        "/assess",
        json={
            "observed_at": "2026-05-20T10:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-sprint0-smoke",
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]
    assert client.get(f"/cases/{case_id}/forensic-bundle/manifest").status_code == 200

    archive = client.get(f"/cases/{case_id}/forensic-bundle.zip")
    assert archive.status_code == 200
    verify = client.post(
        "/forensic-bundle/verify",
        files={"bundle": ("bundle.zip", archive.content, "application/zip")},
    )
    assert verify.status_code == 200

    with ZipFile(BytesIO(archive.content)) as zf:
        assert "manifest.json" in zf.namelist()
