"""Граф дела в рабочем столе: вершины и связи по событиям инцидента.

Прецедент, с которого написан модуль. Все связи графа требовали процесса или пары адресов:
`учётная запись → процесс`, `родительский процесс → процесс`, `узел → процесс`,
`адрес → адрес`. Событие промышленного источника — запись в регистр ПЛК учётной записью,
без процесса и без адреса назначения — не давало ни одной связи. Узел `plc-line-3`,
на котором остановилась линия розлива, висел на графе отдельной точкой, хотя событие прямо
называет, кто на нём действовал. На демонстрационном деле таких вершин было две.

Проверяется здесь не отрисовка, а модель: какие сущности продукт называет вершинами и когда
считает их связанными. Рисунок берёт это готовым, и ошибка модели превращается в картинку,
которая молчит о связи, названной в самом событии.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.domain.vocabulary import GRAPH_EDGE_KIND_RU
from takt.interface_adapters.api.routers.workspace import _case_graph

NOW = datetime(2026, 3, 17, 10, 45, tzinfo=UTC)


def _event(event_id: str, *, minute: int = 0, source: EventSource = EventSource.OT,
           operation: str = "WRITE_REGISTER", **entities: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id, NOW + timedelta(minutes=minute), source, "modbus", operation, 1, {},
        entities=EventEntities(**entities),
    )


def _kinds(graph: dict) -> set[tuple[str, str, str]]:
    return {(edge["source"], edge["target"], edge["type"]) for edge in graph["edges"]}


def _hanging(graph: dict) -> set[str]:
    """Вершины, не попавшие ни в одну связь."""
    values = {node["value"] for node in graph["nodes"]}
    linked = {end for edge in graph["edges"] for end in (edge["source"], edge["target"])}
    return values - linked


def test_account_acting_on_a_node_is_a_link() -> None:
    """Событие называет узел и учётную запись — этого достаточно для связи.

    Промышленный источник процесса не знает: запись в регистр выполняет учётная запись
    системы сбора данных. Пока связи «действует на» не было, такое событие давало две
    вершины и ни одной линии между ними.
    """
    graph = _case_graph([_event("e-1", host_id="plc-line-3", user_id="svc-scada", src_address="10.20.0.60")])

    assert ("svc-scada", "plc-line-3", "acts_on") in _kinds(graph)
    assert not _hanging(graph) - {"10.20.0.60"}


def test_no_entity_of_an_industrial_event_hangs_alone() -> None:
    """Ни один узел цепочки не остаётся точкой без связей.

    Набор повторяет хвост демонстрационного сценария: запись в регистр ПЛК и остановка
    линии. До исправления `plc-line-3` не имел ни одной связи.
    """
    events = [
        _event("e-1", minute=0, host_id="plc-line-3", user_id="svc-scada", src_address="10.20.0.60"),
        _event("e-2", minute=5, operation="LINE_STOP", host_id="plc-line-3", user_id="svc-scada"),
        _event("e-3", minute=-45, source=EventSource.SIEM, operation="REMOTE_SERVICE_START",
               host_id="hist-01", user_id="svc-scada", src_address="10.20.0.15", dst_address="10.20.0.60"),
    ]

    assert _hanging(_case_graph(events)) == set()


def test_the_parent_process_is_a_vertex_of_its_own() -> None:
    """Связь «породил» указывает на родительский процесс — значит, он вершина.

    Вершины собирались без него, и рисунок такую связь молча терял: концы линии не
    находили своих точек. В списке связей она при этом была — два представления одного
    дела расходились.
    """
    graph = _case_graph([
        _event("e-1", source=EventSource.EDR, operation="PROCESS_START",
               host_id="ws-17", user_id="ivanov", process_id="powershell.exe", parent_process_id="explorer.exe"),
    ])

    values = {node["value"] for node in graph["nodes"]}
    assert "explorer.exe" in values
    assert ("explorer.exe", "powershell.exe", "spawned") in _kinds(graph)
    assert not _hanging(graph)


def test_every_edge_kind_has_a_russian_name() -> None:
    """Вид связи без названия в словаре приходит в интерфейс кодом.

    Словарь — источник правды и для API, и для АРМ: интерфейс не придумывает названий
    сам. Новый вид связи, забытый в словаре, показался бы аналитику как `acts_on`.
    """
    events = [
        _event("e-1", host_id="plc-line-3", user_id="svc-scada"),
        _event("e-2", source=EventSource.EDR, operation="PROCESS_START",
               host_id="ws-17", user_id="ivanov", process_id="powershell.exe", parent_process_id="explorer.exe"),
        _event("e-3", source=EventSource.NDR, operation="CONNECT",
               host_id="ws-17", src_address="10.20.0.15", dst_address="10.20.0.60"),
    ]
    graph = _case_graph(events)

    used = {edge["type"] for edge in graph["edges"]}
    assert used, "события не дали ни одной связи"
    assert used <= set(GRAPH_EDGE_KIND_RU), sorted(used - set(GRAPH_EDGE_KIND_RU))


def test_an_address_is_not_tied_to_the_node_that_observed_it() -> None:
    """Адрес источника к узлу не подтягивается — и это решение, а не пробел.

    В событии рабочей станции `src_address` часто адрес самого узла. Связь «адрес обратился
    к узлу» означала бы, что узел обращался к себе, и такое утверждение ушло бы в
    доказательный материал.
    """
    graph = _case_graph([
        _event("e-1", source=EventSource.EDR, operation="PROCESS_START",
               host_id="ws-17", src_address="10.20.0.17"),
    ])

    assert ("10.20.0.17", "ws-17", "network") not in _kinds(graph)
