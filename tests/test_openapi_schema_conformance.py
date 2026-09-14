"""Схема OpenAPI описывает то, что приложение действительно отдаёт.

Схема — это контракт: по ней генерируют клиентов и по ней же проверяют совместимость. Пока
она расходится с поведением, клиент готовится к одному, а получает другое, и обнаруживается
это у потребителя, а не у нас.

Расхождения найдены прогоном `schemathesis run --checks all` (шаг `Schemathesis gate` в CI).
До этого ворота падали при старте приложения и ни разу не проверяли схему по существу, поэтому
долг копился незаметно. Тесты ниже закрепляют разобранные случаи, чтобы они не вернулись.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app
from takt.interface_adapters.api.openapi import drop_null_from_parameter_schemas


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


@pytest.fixture(scope="module")
def schema(client: TestClient) -> dict:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize(
    "path",
    ["/events", "/events/batch", "/cases/import/full.json"],
)
def test_invalid_json_body_answers_422_not_500(client: TestClient, path: str) -> None:
    """Невалидное тело — отказ 422, а не внутренняя ошибка.

    Эти обработчики читают тело сырым и сами разбирают его pydantic. Отчёт `e.errors()`
    содержит поле `input` с исходным телом: при пустом или битом JSON туда попадают `bytes`,
    ответ 422 не сериализуется, и клиент получал 500 вместо внятного отказа.
    """
    response = client.post(path, content=b"", headers={"Content-Type": "application/json"})

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail, response.text


@pytest.mark.parametrize(
    "path",
    ["/events", "/events/batch", "/cases/import/full.json"],
)
def test_validation_report_does_not_echo_the_request_body(client: TestClient, path: str) -> None:
    """Тело запроса не возвращается клиенту в отчёте об ошибке.

    Помимо поломки сериализации, поле `input` отражало присланное обратно. Для приёма событий
    это лишнее: в теле могут быть данные источника, а для разбора ошибки хватает типа, пути
    до поля и сообщения.
    """
    response = client.post(
        path,
        content=b'{"broken": ',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    for item in response.json()["detail"]:
        assert "input" not in item
        assert "url" not in item
        assert {"type", "loc", "msg"} <= set(item)


@pytest.mark.parametrize("path", ["/health", "/live", "/ready"])
def test_head_operations_promise_no_body(schema: dict, path: str) -> None:
    """У HEAD в схеме нет описания тела: по RFC 9110 §9.3.2 тела у него и не бывает.

    FastAPI описывал `@app.head(...)` как GET, и в схему попадал `content: application/json`.
    Клиент по такой схеме ждал JSON, получал пустой ответ и спотыкался на разборе.
    """
    head = schema["paths"][path]["head"]

    for status, response in head["responses"].items():
        assert "content" not in response, f"{path} HEAD {status} обещает тело"


def test_get_operations_still_describe_their_body(schema: dict) -> None:
    """Обратная сторона: у GET описание тела осталось на месте."""
    ok = schema["paths"]["/health"]["get"]["responses"]["200"]

    assert "content" in ok
    assert "application/json" in ok["content"]


@pytest.mark.parametrize("code", ["400", "404"])
def test_common_refusals_are_documented_everywhere(schema: dict, code: str) -> None:
    """Отказы, возможные на любой операции, объявлены на каждой.

    Гвард сообщал «Undocumented HTTP status code» на 33 операциях для 400 и на 28 для 404:
    коды отдавались всегда, а в схеме их не было.
    """
    missing = [
        f"{method.upper()} {path}"
        for path, item in schema["paths"].items()
        for method, operation in item.items()
        if method in {"get", "post", "put", "patch", "delete"}
        and code not in operation.get("responses", {})
    ]

    assert not missing, f"код {code} не объявлен на операциях: {missing[:10]}"


@pytest.mark.parametrize(
    ("path", "method", "code"),
    [
        ("/events", "post", "422"),
        ("/events/batch", "post", "422"),
        ("/cases/import/full.json", "post", "422"),
        ("/cases/assemble/auto", "post", "409"),
        ("/cases/assemble/pivot", "post", "409"),
        ("/cases/{case_id}/simulation", "get", "409"),
        ("/audit-ledger/operations/verify", "get", "501"),
        ("/cases/{case_id}/audit-ledger/verify", "get", "501"),
    ],
)
def test_route_specific_refusals_are_documented(schema: dict, path: str, method: str, code: str) -> None:
    """Коды, которые отдают конкретные обработчики, объявлены на этих маршрутах.

    422 на приёме автоматически не появляется: тело читается сырым, схемы тела в сигнатуре
    нет. 409 — состояние дела не позволяет операцию. 501 — журнал с хэш-цепочкой живёт в
    SQLite и при хранилище в памяти недоступен вовсе.
    """
    assert code in schema["paths"][path][method]["responses"]


def test_allow_header_lists_every_method_of_the_path(client: TestClient) -> None:
    """`Allow` в ответе 405 перечисляет все методы пути, а не методы одного маршрута.

    GET и PUT на `/config/risk-weights` объявлены раздельно, и Starlette перечислял методы
    только первого совпавшего маршрута: клиент, читающий `Allow`, не узнавал о половине
    интерфейса. RFC 9110 §10.2.1 требует перечислить методы целевого ресурса.
    """
    response = client.delete("/config/risk-weights")

    assert response.status_code == 405
    allowed = {m.strip() for m in response.headers["allow"].split(",")}
    assert {"GET", "PUT"} <= allowed, response.headers["allow"]


def test_allow_header_is_left_alone_on_normal_responses(client: TestClient) -> None:
    """Посредник трогает только 405: на обычном ответе заголовка он не выдумывает."""
    response = client.get("/health")

    assert response.status_code == 200
    assert "allow" not in {k.lower() for k in response.headers}


def test_weights_rewrite_documents_both_shapes_of_422(schema: dict) -> None:
    """422 на правке весов бывает двух форм, и описаны обе.

    Строка — нарушено правило конфигурации («сумма весов должна равняться 1.000»). Список —
    обычный отчёт валидации тела от FastAPI. Описание только одной формы роняло проверку
    соответствия ответа схеме.
    """
    responses = schema["paths"]["/config/risk-weights"]["put"]["responses"]
    ref = responses["422"]["content"]["application/json"]["schema"]["$ref"]
    name = ref.rsplit("/", 1)[-1]
    detail = schema["components"]["schemas"][name]["properties"]["detail"]

    kinds = {option.get("type") for option in detail.get("anyOf", [])}
    assert {"string", "array"} <= kinds, detail


def test_no_query_parameter_promises_null(schema: dict) -> None:
    """Ни один параметр запроса не объявлен допускающим `null`.

    Необязательный параметр FastAPI описывает как `anyOf: [<тип>, null]` — так выглядит
    аннотация `int | None`. По проводу же значения `null` не существует: в строке запроса
    едет только текст, и «не задано» выражается отсутствием параметра, а не словом `null`.
    Клиент, читающий схему буквально, шлёт `limit=null` и получает 422 на запросе, который
    схеме соответствует. Прогон schemathesis сообщал об этом на шести операциях
    (`/cases`, `/cases/groups`, `/cases/export/full.json`, `/events/search`,
    `/cases/{case_id}/simulation`, история перепроверки готовности).
    """
    promising = [
        f"{method.upper()} {path} ?{parameter.get('name')}"
        for path, item in schema["paths"].items()
        for method, operation in item.items()
        if isinstance(operation, dict)
        for parameter in operation.get("parameters", []) or []
        if any(
            option.get("type") == "null"
            for option in parameter.get("schema", {}).get("anyOf", [])
        )
    ]

    assert not promising, f"параметры обещают null: {promising[:10]}"


@pytest.mark.parametrize(
    ("path", "name", "expected"),
    [
        ("/cases/export/full.json", "limit", {"type": "integer", "minimum": 1, "maximum": 10_000}),
        ("/cases/{case_id}/simulation", "seconds_per_action", {"type": "number", "minimum": 0.0, "maximum": 3600.0}),
        (
            "/cases/{case_id}/compliance/remediations/recheck-readiness/history",
            "ready",
            {"type": "boolean"},
        ),
        ("/events/search", "observed_to", {"type": "string", "format": "date-time"}),
        ("/cases", "status", {"type": "string"}),
    ],
)
def test_optional_parameter_keeps_its_type_and_bounds(
    schema: dict, path: str, name: str, expected: dict
) -> None:
    """Убрана только ветка `null`: тип и границы значения остались на месте.

    Иначе лечение было бы хуже болезни: параметр без `minimum`/`maximum` перестал бы
    описывать то, что обработчик проверяет.
    """
    parameter = next(
        p
        for p in schema["paths"][path]["get"]["parameters"]
        if p["name"] == name
    )

    assert parameter["required"] is False
    assert "anyOf" not in parameter["schema"]
    assert expected.items() <= parameter["schema"].items(), parameter["schema"]


@pytest.mark.parametrize(
    "url",
    [
        "/cases/export/full.json",
        "/cases",
        "/cases/groups",
        "/events/search",
    ],
)
def test_optional_parameter_may_still_be_omitted(client: TestClient, url: str) -> None:
    """Необязательность параметра сохранена: запрос без него по-прежнему проходит.

    Это и есть штатный способ сказать «значение не задано» — вместо `null`.
    """
    assert client.get(url).status_code == 200


def test_null_branch_is_dropped_without_collapsing_the_rest() -> None:
    """Из нескольких веток убирается только `null`, остальные остаются перечислением.

    В приложении сейчас таких параметров нет — все двухветочные. Проверка держит поведение
    на случай, когда параметр будет описан несколькими типами: схлопнуть его до одного типа
    значило бы соврать в другую сторону.
    """
    schema = {
        "paths": {
            "/x": {
                "get": {
                    "parameters": [
                        {
                            "name": "mixed",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "anyOf": [{"type": "integer"}, {"type": "string"}, {"type": "null"}],
                                "title": "Mixed",
                            },
                        }
                    ]
                }
            }
        }
    }

    drop_null_from_parameter_schemas(schema)

    parameter = schema["paths"]["/x"]["get"]["parameters"][0]
    assert parameter["schema"]["anyOf"] == [{"type": "integer"}, {"type": "string"}]
    assert parameter["schema"]["title"] == "Mixed"
