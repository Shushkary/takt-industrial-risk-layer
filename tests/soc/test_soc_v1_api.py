"""Интеграционные тесты surface ``/api/v1`` (изолированный sub-app).

Тестируем на изолированном под-приложении ``build_subapp()``: у него нет
родительского middleware аутентификации, поэтому роль задаётся заголовком
``X-Role`` (в проде роль приходит из ``request.state.takt_role``).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from starlette.testclient import TestClient

from takt.interface_adapters.api.v1.wiring import build_subapp

_TS = datetime(2026, 7, 1, 10, 0, 0, tzinfo=UTC).isoformat()


def _event(ref: str = "ref-1", host: str = "HOST-1") -> dict:
    return {
        "source_class": "edr",
        "host_id": host,
        "user_id": "u1",
        "process": "p.exe",
        "address": "10.0.0.1",
        "artifact": "a1",
        "ts": _TS,
        "raw_ref": ref,
    }


@pytest.fixture()
def client() -> TestClient:
    return TestClient(build_subapp())


def _l1(headers: dict | None = None) -> dict:
    h = {"X-Role": "analyst_l1"}
    if headers:
        h.update(headers)
    return h


def test_ingest_is_idempotent(client: TestClient) -> None:
    r1 = client.post("/events", json=_event(), headers=_l1())
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["created"] is True
    r2 = client.post("/events", json=_event(), headers=_l1())
    assert r2.status_code == 200
    body2 = r2.json()
    # Тот же content_hash → тот же кейс, created=False (идемпотентность).
    assert body2["created"] is False
    assert body2["case_id"] == body1["case_id"]
    assert body2["content_hash"] == body1["content_hash"]


def test_invalid_event_goes_to_dead_letter_and_returns_problem_json(client: TestClient) -> None:
    bad = _event()
    bad["source_class"] = "BOGUS"
    r = client.post("/events", json=bad, headers=_l1())
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 422
    assert "type" in body and "title" in body and "detail" in body
    # Запись попала в dead-letter стор (виден только admin).
    dl = client.get("/admin/dead-letters", headers={"X-Role": "admin"})
    assert dl.status_code == 200
    assert len(dl.json()) == 1
    assert dl.json()[0]["error_type"] == "ConstructionError"


def test_cursor_pagination(client: TestClient) -> None:
    for i in range(5):
        r = client.post("/events", json=_event(ref=f"ref-{i}", host=f"HOST-{i}"), headers=_l1())
        assert r.status_code == 200
    # Первая страница из 2.
    p1 = client.get("/events/search?limit=2", headers=_l1()).json()
    assert len(p1["items"]) == 2
    assert p1["total_count"] == 5
    assert p1["next_cursor"] is not None
    # Вторая страница по курсору.
    p2 = client.get(f"/events/search?limit=2&cursor={p1['next_cursor']}", headers=_l1()).json()
    assert len(p2["items"]) == 2
    seqs1 = {it["seq"] for it in p1["items"]}
    seqs2 = {it["seq"] for it in p2["items"]}
    assert seqs1.isdisjoint(seqs2)  # без пересечений между страницами


def test_limit_is_capped_at_200(client: TestClient) -> None:
    # limit > 200 отвергается валидацией схемы (422 problem+json).
    r = client.get("/events/search?limit=500", headers=_l1())
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/problem+json")


def test_bad_cursor_returns_400(client: TestClient) -> None:
    r = client.get("/events/search?cursor=@@@notbase64@@@", headers=_l1())
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/problem+json")


def test_rbac_missing_role_401(client: TestClient) -> None:
    r = client.get("/admin/dead-letters")  # без X-Role
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")


def test_rbac_insufficient_role_403(client: TestClient) -> None:
    r = client.get("/admin/dead-letters", headers=_l1())  # analyst_l1 на admin-маршруте
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("application/problem+json")


def test_rbac_alias_operator_maps_to_l2(client: TestClient) -> None:
    # operator → analyst_l2: доступ к write-маршруту L1 разрешён по рангу.
    r = client.post("/events", json=_event(ref="op-1"), headers={"X-Role": "operator"})
    assert r.status_code == 200


def test_case_card_404(client: TestClient) -> None:
    r = client.get("/cases/NOPE/card", headers=_l1())
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")


def test_case_card_and_hints_after_ingest(client: TestClient) -> None:
    created = client.post("/events", json=_event(ref="c-1"), headers=_l1()).json()
    case_id = created["case_id"]
    card = client.get(f"/cases/{case_id}/card", headers=_l1())
    assert card.status_code == 200
    assert card.json()["case_id"] == case_id
    hints = client.get(f"/cases/{case_id}/hints", headers=_l1())
    assert hints.status_code == 200
    # Новый кейс со статусом new → есть подсказка первичной квалификации.
    assert any(h["rule_id"] == "new-case-triage" for h in hints.json())


def test_decision_write_requires_l1(client: TestClient) -> None:
    created = client.post("/events", json=_event(ref="d-1"), headers=_l1()).json()
    case_id = created["case_id"]
    # manager (read-only) не может принимать решение.
    r = client.post(f"/cases/{case_id}/decision", json={"decision": "confirm"}, headers={"X-Role": "manager"})
    assert r.status_code == 403
    ok = client.post(f"/cases/{case_id}/decision", json={"decision": "confirm"}, headers=_l1())
    assert ok.status_code == 200
    assert "entry_hash" in ok.json()


def test_sse_replay_buffered_events(client: TestClient) -> None:
    # Создаём кейс → публикуется SSE-событие в кольцевой буфер.
    client.post("/events", json=_event(ref="sse-1"), headers=_l1())
    # replay из буфера + close_after=1 гарантирует завершение потока (для теста).
    with client.stream("GET", "/stream/cases?replay=5&close_after=1", headers=_l1()) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        body = "".join(chunk for chunk in resp.iter_text())
    assert "data:" in body
    assert '"status": "new"' in body or '"status":"new"' in body
