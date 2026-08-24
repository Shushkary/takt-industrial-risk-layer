from __future__ import annotations

import logging
import subprocess
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from takt.domain.entities.case import Case, CaseStatus
from takt.interface_adapters.api.main import (
    _CASE_LIST_SORT,
    _as_utc_boundary,
    _parse_import_created_at,
    _patch_openapi_with_takt_api_key,
    _read_installed_package_version,
    _sort_cases_copy,
    create_app,
    openapi_server_entries_from_env,
)


def test_package_version_fallback_when_distribution_metadata_fails() -> None:
    code = """
from unittest import mock
import importlib

def boom(*args, **kwargs):
    raise RuntimeError("no distribution")

with mock.patch("importlib.metadata.version", boom):
    import takt.interface_adapters.api.main as m
    importlib.reload(m)
    assert m._PACKAGE_VERSION == "0.6.23"
"""
    subprocess.check_call([sys.executable, "-c", code], cwd=None)


def test_read_installed_package_version_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> str:
        raise RuntimeError("no distribution")

    monkeypatch.setattr("importlib.metadata.version", boom)
    assert _read_installed_package_version() == "0.6.23"


def test_openapi_server_entries_skips_bad_schemes_and_missing_host(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(
        "TAKT_OPENAPI_SERVER_URL",
        "ftp://bad.example, http://, https://ok.example/v1",
    )
    caplog.set_level(logging.WARNING)
    entries = openapi_server_entries_from_env()
    assert entries == [
        {"url": "https://ok.example/v1", "description": "From TAKT_OPENAPI_SERVER_URL"}
    ]
    assert any("scheme" in r.message.lower() for r in caplog.records)
    assert any("missing host" in r.message.lower() for r in caplog.records)


def test_create_app_warns_when_metrics_enabled_without_prometheus_client(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("TAKT_METRICS", "1")
    monkeypatch.setattr(
        "takt.infrastructure.http.prometheus_metrics.prometheus_client_available",
        lambda: False,
    )
    caplog.set_level(logging.WARNING)
    create_app()
    assert any(
        "prometheus-client is not installed" in r.message for r in caplog.records
    )


def test_event_window_trims_after_many_assess_calls() -> None:
    with TestClient(create_app()) as client:
        for i in range(65):
            r = client.post(
                "/assess",
                json={
                    "observed_at": f"2026-04-30T12:{i % 60:02d}:00+00:00",
                    "operation": "POLL",
                    "asset_id": f"asset-{i}",
                    "payload_size": 8,
                },
            )
            assert r.status_code == 200
        app = client.app
        assert len(app.state.event_window) <= 64


@pytest.mark.parametrize("sort_key", sorted(_CASE_LIST_SORT))
def test_sort_cases_copy_accepts_each_catalog_key(sort_key: str) -> None:
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 1, 2, 10, 0, tzinfo=timezone.utc)
    a = Case(
        case_id="zzz",
        status=CaseStatus.NEW,
        title="Zebra",
        risk_class="HIGH",
        risk_score=0.9,
        created_at=t1,
        primary_asset_id="plc-b",
        normalized_event_ids=["e1", "e2"],
        invariant_hits=["a", "b"],
        dq_score=0.4,
    )
    b = Case(
        case_id="aaa",
        status=CaseStatus.NEW,
        title="Alpha",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        primary_asset_id="plc-a",
        normalized_event_ids=["e1"],
        invariant_hits=["z"],
        dq_score=0.95,
    )
    out = _sort_cases_copy([a, b], sort_key)
    assert len(out) == 2


def test_sort_cases_copy_unknown_raises() -> None:
    c = Case(
        case_id="x",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.5,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(RuntimeError, match="unsupported sort"):
        _sort_cases_copy([c], "not-a-real-sort")


def test_sort_cases_copy_created_at_treats_naive_as_utc() -> None:
    naive = Case(
        case_id="naive",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime(2026, 1, 1, 12, 0),
    )
    aware = Case(
        case_id="aware",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc),
    )

    rows = _sort_cases_copy([naive, aware], "created_at_asc")

    assert [row.case_id for row in rows] == ["naive", "aware"]


def test_as_utc_boundary_naive_and_aware() -> None:
    naive = datetime(2026, 6, 1, 12, 0)
    assert _as_utc_boundary(naive).tzinfo == timezone.utc
    aware = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    assert _as_utc_boundary(aware).hour == 15


def test_parse_import_created_at_z_suffix() -> None:
    dt = _parse_import_created_at("2026-03-01T08:00:00Z")
    assert dt.tzinfo == timezone.utc
    assert dt.isoformat(timespec="seconds") == "2026-03-01T08:00:00+00:00"


def test_parse_import_created_at_naive_gets_utc() -> None:
    dt = _parse_import_created_at(" 2026-03-01T08:00:00 ")
    assert dt.tzinfo == timezone.utc


def test_head_openapi_json_probe() -> None:
    with TestClient(create_app()) as client:
        r = client.head("/openapi.json")
    assert r.status_code == 200
    assert (r.content or b"") == b""


def test_data_quality_404_before_any_ingest() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/data-quality").status_code == 404


def test_get_case_export_404() -> None:
    with TestClient(create_app()) as c:
        assert c.get("/cases/does-not-exist").status_code == 404
        assert c.get("/cases/does-not-exist/export.pdf").status_code == 404
        assert c.get("/cases/does-not-exist/export/siem.json").status_code == 404


def test_assess_demo_bad_timestamp_400() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/assess",
            json={
                "observed_at": "",
                "operation": "POLL",
                "asset_id": "plc-x",
                "payload_size": 4,
            },
        )
    assert r.status_code == 400


def test_events_batch_item_error_includes_index() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/events/batch",
            json={
                "events": [
                    {
                        "observed_at": "2026-04-30T12:00:00+00:00",
                        "operation": "POLL",
                        "asset_id": "a",
                        "payload_size": 4,
                        "source": "plc_polling",
                    },
                    {
                        "observed_at": "",
                        "operation": "POLL",
                        "asset_id": "b",
                        "payload_size": 4,
                        "source": "plc_polling",
                    },
                ]
            },
        )
    assert r.status_code == 400
    assert "events[1]" in r.json()["detail"]


def test_list_cases_invalid_sort_400() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/cases", params={"sort": "bad_sort"}).status_code == 400


def test_ready_503_when_list_all_fails() -> None:
    app = create_app()
    app.state.repo.list_all = MagicMock(side_effect=RuntimeError("store offline"))
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 503


def test_post_decision_unknown_case_400() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/cases/nope/decision",
            json={"status": "TRIAGE"},
        )
    assert r.status_code == 400
    assert "unknown case" in r.json()["detail"].lower()


def test_post_decision_invalid_transition_400() -> None:
    with TestClient(create_app()) as client:
        cid = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-z",
                "payload_size": 10,
            },
        ).json()["case_id"]
        assert (
            client.post(
                f"/cases/{cid}/decision", json={"status": "CONFIRMED"}
            ).status_code
            == 200
        )
        r = client.post(f"/cases/{cid}/decision", json={"status": "TRIAGE"})
    assert r.status_code == 400
    assert "недопустимый переход статуса" in r.json()["detail"]


def test_siem_forward_case_not_found() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/integrations/siem/forward",
            json={"case_id": "missing", "target_url": "http://127.0.0.1/hook"},
        )
    assert r.status_code == 404


def test_siem_forward_rejects_disallowed_url() -> None:
    with TestClient(create_app()) as client:
        cid = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-z",
                "payload_size": 10,
            },
        ).json()["case_id"]
        r = client.post(
            "/integrations/siem/forward",
            json={"case_id": cid, "target_url": "http://198.51.100.1/hook"},
        )
    assert r.status_code == 400


def test_siem_forward_sync_webhook_http_error_502(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(create_app()) as client:
        cid = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-z",
                "payload_size": 10,
            },
        ).json()["case_id"]

        def boom(*_a, **_k):
            raise httpx.ConnectError("down", request=MagicMock())

        monkeypatch.setattr(
            "takt.interface_adapters.api.main.post_case_to_webhook_sync",
            boom,
        )
        r = client.post(
            "/integrations/siem/forward",
            json={"case_id": cid, "target_url": "http://127.0.0.1/hook"},
        )
    assert r.status_code == 502


@pytest.mark.anyio
async def test_siem_forward_async_webhook_http_error_502(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        r0 = await ac.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-z",
                "payload_size": 10,
            },
        )
        cid = r0.json()["case_id"]

        async def boom(*_a, **_k):
            raise httpx.ConnectError("down", request=MagicMock())

        monkeypatch.setattr(
            "takt.interface_adapters.api.main.post_case_to_webhook",
            boom,
        )
        r = await ac.post(
            "/integrations/siem/forward/async",
            json={"case_id": cid, "target_url": "http://127.0.0.1/hook"},
        )
        assert r.status_code == 502


def test_export_pdf_runtime_error_returns_501(monkeypatch: pytest.MonkeyPatch) -> None:
    with TestClient(create_app()) as client:
        cid = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-z",
                "payload_size": 10,
            },
        ).json()["case_id"]
        monkeypatch.setattr(
            "takt.interface_adapters.api.main.render_case_pdf",
            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("no fpdf")),
        )
        r = client.get(f"/cases/{cid}/export.pdf")
    assert r.status_code == 501
    assert "fpdf" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_siem_forward_async_case_not_found() -> None:
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        r = await ac.post(
            "/integrations/siem/forward/async",
            json={"case_id": "nope", "target_url": "http://127.0.0.1/h"},
        )
        assert r.status_code == 404


def test_backtest_fixture_missing_returns_500(monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    import takt.interface_adapters.api.main as main_mod

    monkeypatch.setattr(main_mod, "_ROOT", Path("/__no_such_takt_root__"))
    with TestClient(main_mod.create_app()) as client:
        assert client.post("/backtest/fixture").status_code == 500


def test_patch_openapi_adds_security_but_skips_non_operation_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAKT_API_KEY", "secret-token-32chars-long!!!!")
    schema: dict = {
        "paths": {
            "/private/ping": {
                "get": {"summary": "g"},
                "parameters": [],
            },
        },
    }
    _patch_openapi_with_takt_api_key(schema)
    sec = schema["paths"]["/private/ping"]["get"].setdefault("security", [])
    assert {"TaktApiKey": []} in sec


def test_head_openapi_json_via_request() -> None:
    with TestClient(create_app()) as c:
        r = c.request("HEAD", "/openapi.json")
    assert r.status_code == 200
    assert (r.content or b"") == b""


def test_post_events_invalid_timestamp_400() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/events",
            json={
                "observed_at": "",
                "operation": "POLL",
                "asset_id": "plc-e",
                "payload_size": 4,
                "source": "plc_polling",
            },
        )
    assert r.status_code == 400


def test_post_events_batch_merges_payload_into_row() -> None:
    with TestClient(create_app()) as client:
        r = client.post(
            "/events/batch",
            json={
                "events": [
                    {
                        "observed_at": "2026-04-30T12:00:00+00:00",
                        "operation": "POLL",
                        "asset_id": "plc-payload",
                        "payload_size": 8,
                        "source": "plc_polling",
                        "payload": {"telemetry_value": 9, "extra_flag": True},
                    },
                ]
            },
        )
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_list_cases_applies_numeric_and_substring_filters() -> None:
    with TestClient(create_app()) as c:
        assert (
            c.post(
                "/assess",
                json={
                    "observed_at": "2026-04-30T22:00:00+00:00",
                    "operation": "PORT_SCAN",
                    "asset_id": "plc-filter",
                    "payload_size": 10,
                },
            ).status_code
            == 200
        )
        assert (
            c.get(
                "/cases", params={"min_risk_score": 0.0, "max_risk_score": 1.0}
            ).status_code
            == 200
        )
        assert (
            c.get(
                "/cases", params={"min_dq_score": 0.0, "max_dq_score": 1.0}
            ).status_code
            == 200
        )
        assert c.get("/cases", params={"risk_class": "LOW"}).status_code == 200
        assert c.get("/cases", params={"has_invariant": "recon"}).status_code == 200
        assert c.get("/cases", params={"has_dq_reason": "telemetry"}).status_code == 200


@pytest.mark.anyio
async def test_siem_forward_async_rejects_external_url() -> None:
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        r0 = await ac.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T22:00:00+00:00",
                "operation": "POLL",
                "asset_id": "plc-async-bad-url",
                "payload_size": 10,
            },
        )
        cid = r0.json()["case_id"]
        r = await ac.post(
            "/integrations/siem/forward/async",
            json={"case_id": cid, "target_url": "http://198.51.100.2/hook"},
        )
        assert r.status_code == 400
