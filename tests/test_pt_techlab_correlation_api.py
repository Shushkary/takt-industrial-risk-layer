from __future__ import annotations

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def _case(client: TestClient, asset: str) -> tuple[str, str]:
    response = client.post(
        "/assess",
        json={"observed_at": "2026-06-01T10:00:00Z", "operation": "READ", "asset_id": asset},
    )
    assert response.status_code == 200
    case_id = response.json()["case_id"]
    event_id = client.get(f"/cases/{case_id}").json()["event_ids"][0]
    return case_id, event_id


def test_manual_correlation_routes_attach_detach_merge_and_split() -> None:
    with TestClient(create_app()) as client:
        first_id, first_event = _case(client, "plc-corr-a")
        second_id, second_event = _case(client, "plc-corr-b")

        attach = client.post(
            f"/cases/{first_id}/events/attach",
            json={"event_id": "external-event", "reason": "analyst confirmed relation"},
            headers={"X-Request-ID": "attach-1"},
        )
        assert attach.status_code == 200
        assert attach.json()["event_ids"] == [first_event, "external-event"]

        detach = client.post(
            f"/cases/{first_id}/events/external-event/detach",
            json={"reason": "later disproved"},
            headers={"X-Request-ID": "detach-1"},
        )
        assert detach.status_code == 200
        assert detach.json()["event_ids"] == [first_event]
        detail = client.get(f"/cases/{first_id}").json()
        assert detail["correlation_evidence"][-1]["rule"] == "manual_detach"
        assert detail["correlation_evidence"][-1]["reason"] == "later disproved"

        merge = client.post(
            f"/cases/{first_id}/merge",
            json={"source_case_id": second_id, "reason": "same campaign"},
            headers={"X-Request-ID": "merge-1"},
        )
        assert merge.status_code == 200
        assert merge.json()["event_ids"] == [first_event, second_event]
        assert client.get(f"/cases/{second_id}").json()["status"] == "MERGED"

        repeated = client.post(
            f"/cases/{first_id}/merge",
            json={"source_case_id": second_id, "reason": "same campaign"},
            headers={"X-Request-ID": "merge-1"},
        )
        assert repeated.status_code == 200
        assert repeated.json()["event_ids"] == [first_event, second_event]

        split = client.post(
            f"/cases/{first_id}/split",
            json={"event_ids": [second_event], "reason": "separate incident"},
            headers={"X-Request-ID": "split-1"},
        )
        assert split.status_code == 200
        assert split.json()["case_id"] != first_id
        assert split.json()["event_ids"] == [second_event]


def test_manual_correlation_requires_reason() -> None:
    with TestClient(create_app()) as client:
        case_id, event_id = _case(client, "plc-corr-validation")
        response = client.post(f"/cases/{case_id}/events/{event_id}/detach", json={"reason": ""})
        assert response.status_code == 422
