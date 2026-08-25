"""`GET /session`: кто работает в текущей сессии.

До появления этого маршрута рабочее место не могло назвать автора действия — в журнале кейса
оставался IP-адрес клиента, а для доказательного пакета это не автор. Здесь закреплены два
свойства: маршрут возвращает тот же `actor_id`, что уходит в журнал, и он **не публичный** —
без ключа отвечает 401, чтобы интерфейс отличал «требуется ключ доступа» от «нет связи».
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


@pytest.fixture()
def _named_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", "k-l1:ivanov:analyst_l1,k-adm:root:admin")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)


def test_session_names_the_actor_behind_the_key(_named_key: None) -> None:
    with TestClient(create_app()) as client:
        body = client.get("/session", headers={"X-TAKT-API-Key": "k-l1"}).json()

    assert body["actor_id"] == "ivanov"
    assert body["role"] == "analyst_l1"
    assert body["auth_mode"] == "required"
    assert body["permissions"] == {"case_write": True, "case_relink": False, "administration": False}


def test_session_without_a_key_is_rejected(_named_key: None) -> None:
    """Отдельный код ответа — единственный способ отличить отсутствие ключа от отсутствия связи."""
    with TestClient(create_app()) as client:
        assert client.get("/session").status_code == 401


def test_session_is_readable_by_every_role(_named_key: None) -> None:
    with TestClient(create_app()) as client:
        assert client.get("/session", headers={"X-TAKT-API-Key": "k-adm"}).json()["role"] == "admin"


def test_session_reports_the_open_mode_when_auth_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Без ключей роль в ответе — `admin`, и режим назван честно: это стенд, а не эксплуатация."""
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "false")
    monkeypatch.delenv("TAKT_API_KEYS", raising=False)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)

    with TestClient(create_app()) as client:
        body = client.get("/session").json()

    assert body["auth_mode"] == "disabled"
    assert body["actor_id"] == "no-auth"


def test_permissions_repeat_the_matrix_that_guards_the_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Своя копия матрицы в интерфейсе разошлась бы с `rbac.py` молча."""
    monkeypatch.setenv("TAKT_AUTH_REQUIRED", "true")
    monkeypatch.setenv("TAKT_API_KEYS", "k-mgr:petrov:manager,k-l2:sidorov:analyst_l2")
    monkeypatch.delenv("TAKT_API_KEY", raising=False)

    with TestClient(create_app()) as client:
        manager = client.get("/session", headers={"X-TAKT-API-Key": "k-mgr"}).json()
        l2 = client.get("/session", headers={"X-TAKT-API-Key": "k-l2"}).json()
        # Матрица не пересказана, а проверена: руководитель действительно получает 403.
        denied = client.post(
            "/cases/INC-404/findings",
            headers={"X-TAKT-API-Key": "k-mgr"},
            json={"comment": "проверка роли"},
        )

    assert manager["permissions"]["case_write"] is False
    assert l2["permissions"] == {"case_write": True, "case_relink": True, "administration": False}
    assert denied.status_code == 403
