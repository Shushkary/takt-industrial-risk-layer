from __future__ import annotations

from fastapi.testclient import TestClient

from takt.infrastructure.security.api_keys import ApiKeyEntry, api_key_entries_from_env, resolve_api_key
from takt.infrastructure.security.rbac import required_role_for_route, role_satisfies
from takt.interface_adapters.api.main import create_app

OPERATOR_KEY = "op-secret-key-32chars-long!!!!"
AUDITOR_KEY = "aud-secret-key-32chars-long!!!"
ADMIN_KEY = "adm-secret-key-32chars-long!!!"

_KEYS_ENV = f"{OPERATOR_KEY}:alice:operator,{AUDITOR_KEY}:bob:auditor,{ADMIN_KEY}:carol:admin"


def _headers(key: str) -> dict[str, str]:
    return {"X-TAKT-API-Key": key}


def _post_event(client: TestClient, key: str) -> object:
    return client.post(
        "/events",
        json={
            "observed_at": "2026-05-03T12:00:00+00:00",
            "operation": "READ",
            "asset_id": "plc-rbac",
            "source": "plc_polling",
        },
        headers=_headers(key),
    )


def test_api_key_entries_parses_roles_and_rejects_unknown_role(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_API_KEYS", f"{OPERATOR_KEY}:alice:operator,badkey:eve:superuser")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    entries = api_key_entries_from_env()
    assert entries == (ApiKeyEntry(key=OPERATOR_KEY, actor_id="alice", role="operator"),)


def test_legacy_single_key_maps_to_admin_role(monkeypatch) -> None:
    monkeypatch.delenv("TAKT_API_KEYS", raising=False)
    monkeypatch.setenv("TAKT_API_KEY", ADMIN_KEY)
    entries = api_key_entries_from_env()
    assert entries == (ApiKeyEntry(key=ADMIN_KEY, actor_id="legacy-api-key", role="admin"),)


def test_resolve_api_key_no_match_returns_none() -> None:
    entries = (ApiKeyEntry(key="abc", actor_id="alice", role="operator"),)
    assert resolve_api_key(entries, "not-abc") is None
    assert resolve_api_key(entries, "") is None


def test_rbac_table_read_routes_allow_any_role() -> None:
    assert required_role_for_route("GET", "/cases") is None
    assert role_satisfies("auditor", required_role_for_route("GET", "/cases"))


def test_rbac_table_admin_only_prefixes() -> None:
    assert required_role_for_route("POST", "/cases/import/full.json") == "admin"
    assert required_role_for_route("POST", "/integrations/siem/forward") == "admin"
    assert required_role_for_route("POST", "/audit-engagements") == "admin"
    assert not role_satisfies("operator", "admin")
    assert role_satisfies("admin", "admin")


def test_rbac_table_write_routes_default_to_operator() -> None:
    assert required_role_for_route("POST", "/cases/abc/decision") == "operator"
    assert role_satisfies("operator", "operator")
    assert role_satisfies("admin", "operator")
    assert not role_satisfies("auditor", "operator")


def test_rbac_forensic_verify_is_read_equivalent() -> None:
    assert required_role_for_route("POST", "/forensic-bundle/verify") is None


def test_auditor_cannot_ingest_events(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = _post_event(client, AUDITOR_KEY)
        assert r.status_code == 403
        assert "auditor" in r.json()["detail"]


def test_operator_can_ingest_events(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = _post_event(client, OPERATOR_KEY)
        assert r.status_code == 200


def test_auditor_can_read_cases(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = client.get("/cases", headers=_headers(AUDITOR_KEY))
        assert r.status_code == 200


def test_operator_cannot_import_full_json(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = client.post(
            "/cases/import/full.json",
            json={"cases": []},
            headers=_headers(OPERATOR_KEY),
        )
        assert r.status_code == 403


def test_admin_can_import_full_json(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = client.post(
            "/cases/import/full.json",
            json={"cases": []},
            headers=_headers(ADMIN_KEY),
        )
        assert r.status_code == 200


def test_decision_records_actor_from_named_api_key(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        posted = _post_event(client, OPERATOR_KEY)
        assert posted.status_code == 200
        case_id = posted.json()["case_id"]
        r = client.post(
            f"/cases/{case_id}/decision",
            json={"status": "TRIAGE", "reason": "rbac test"},
            headers=_headers(OPERATOR_KEY),
        )
        assert r.status_code == 200
        detail = client.get(f"/cases/{case_id}", headers=_headers(ADMIN_KEY)).json()
        records = detail["decision_records"]
        assert records
        assert records[-1]["actor"] == "alice"


def test_health_reports_roles_configured(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_API_KEYS", _KEYS_ENV)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    with TestClient(create_app()) as client:
        r = client.get("/health")
        assert r.status_code == 200
        auth = r.json()["auth"]
        assert auth["roles_configured"] == 3
        assert auth["role_counts"] == {"operator": 1, "auditor": 1, "admin": 1}


def test_no_auth_configured_defaults_to_admin_role(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "false")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    monkeypatch.delenv("TAKT_API_KEYS", raising=False)
    with TestClient(create_app()) as client:
        r = client.post(
            "/cases/import/full.json",
            json={"cases": []},
        )
        assert r.status_code == 200
