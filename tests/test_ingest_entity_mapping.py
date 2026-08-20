"""Сущности события доживают от приёма до расследования.

Два дефекта, найденные сквозной проверкой конвейера на четырёх источниках:

1. `raw_row_to_normalized` не заполнял `entities` вовсе. Через него проходит весь HTTP-приём —
   `/integrations/ingest/netflow`, `ipfix`, `syslog`, `snmp/trap` и ручной `/events`. Такие
   события формально принимались, но в корреляцию по сущностям, в граф кейса и в поиск по узлу
   не попадали: источник числился подключённым и при этом не участвовал в разборе.
2. `SqliteRecentEventStore.list_recent_events` читал окно контекста из таблицы `recent_events`,
   где колонок под сущности и артефакты нет. Предикаты инвариантов получали события с
   `entities = None`, то есть при `TAKT_STORAGE=sqlite` работали вслепую, а при хранилище
   в памяти — нет.

Смежное: `tests/test_source_verdict_mapping.py`, `tests/test_assemble_incident.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.domain.entities.event import EventSource
from takt.infrastructure.importers.csv_events import raw_row_to_normalized
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore


def _normalized(row: dict[str, str], source: EventSource = EventSource.NETWORK):
    return raw_row_to_normalized(row, source=source, event_id="e-1")


def test_netflow_row_carries_host_and_both_addresses() -> None:
    """Поток netflow приходит с узлом и обоими адресами — иначе пивот по адресу невозможен."""
    event = _normalized(
        {
            "timestamp": "2026-08-17T06:01:04Z",
            "operation": "C2_SUSPECT",
            "protocol": "DNS",
            "asset_id": "ws-17",
            "flow_src_ip": "10.10.1.41",
            "flow_dst_ip": "185.220.101.34",
        }
    )
    assert event.entities is not None
    assert event.entities.host_id == "ws-17"
    assert event.entities.src_address == "10.10.1.41"
    assert event.entities.dst_address == "185.220.101.34"


def test_dns_query_becomes_domain_artifact() -> None:
    """Домен из потока — артефакт, по нему собирается инцидент."""
    event = _normalized(
        {
            "timestamp": "2026-08-17T06:03:00Z",
            "operation": "C2_SUSPECT",
            "dns_query": "cdn-metrics.example-analytics.com",
        }
    )
    assert [(a.type.value, a.value) for a in event.artifacts] == [
        ("domain", "cdn-metrics.example-analytics.com")
    ]


def test_siem_row_maps_user_and_indicator() -> None:
    event = _normalized(
        {
            "timestamp": "2026-08-17T06:13:00Z",
            "operation": "KERBEROS_TGS_RC4",
            "device_host": "dc-01",
            "subject_user": "smirnov",
            "src_ip": "10.10.1.10",
            "indicator": "MSSQLSvc/db01",
            "indicator_type": "spn",
        },
        source=EventSource.SIEM,
    )
    assert event.entities is not None
    assert (event.entities.host_id, event.entities.user_id) == ("dc-01", "smirnov")
    assert ("spn", "MSSQLSvc/db01") in [(a.type.value, a.value) for a in event.artifacts]


def test_edr_row_maps_process_lineage() -> None:
    event = _normalized(
        {
            "timestamp": "2026-08-17T06:00:00Z",
            "event_type": "PROCESS_START",
            "hostname": "ws-17",
            "username": "smirnov",
            "process_guid": "p-1000",
            "parent_process_guid": "p-0010",
            "sha256": "4f53c6c3",
            "image_path": "C:/Windows/System32/cmd.exe",
        },
        source=EventSource.EDR,
    )
    assert event.entities is not None
    assert (event.entities.process_id, event.entities.parent_process_id) == ("p-1000", "p-0010")
    types = [a.type.value for a in event.artifacts]
    assert "hash" in types and "file" in types


def test_row_without_entity_fields_stays_none() -> None:
    """Пустой набор сущностей не подменяется пустым объектом: отличие значимо для графа."""
    event = _normalized({"timestamp": "2026-08-17T06:00:00Z", "operation": "PING"})
    assert event.entities is None


def test_unknown_indicator_type_does_not_break_ingest() -> None:
    event = _normalized(
        {
            "timestamp": "2026-08-17T06:00:00Z",
            "operation": "ALERT",
            "indicator": "что-то",
            "indicator_type": "неизвестный-тип",
        }
    )
    assert event.artifacts == ()


def test_recent_window_from_sqlite_keeps_entities_and_artifacts(tmp_path: Path) -> None:
    """Окно контекста для предикатов не теряет сущности при sqlite-хранилище."""
    store = SqliteRecentEventStore(tmp_path / "events.db")
    try:
        event = raw_row_to_normalized(
            {
                "timestamp": "2026-08-17T06:01:04Z",
                "operation": "C2_SUSPECT",
                "asset_id": "ws-17",
                "flow_src_ip": "10.10.1.41",
                "flow_dst_ip": "185.220.101.34",
                "dns_query": "cdn-metrics.example-analytics.com",
            },
            source=EventSource.NETWORK,
            event_id="nf-1",
        )
        store.add_recent_event(event, max_events=64)

        window = store.list_recent_events(limit=64)
        assert len(window) == 1
        restored = window[0]
        assert restored.entities is not None, "окно контекста вернуло событие без сущностей"
        assert restored.entities.host_id == "ws-17"
        assert restored.entities.dst_address == "185.220.101.34"
        assert [(a.type.value, a.value) for a in restored.artifacts] == [
            ("domain", "cdn-metrics.example-analytics.com")
        ]
    finally:
        store.close()


def test_recent_window_preserves_order(tmp_path: Path) -> None:
    """Порядок окна — по времени приёма, от старых к новым."""
    store = SqliteRecentEventStore(tmp_path / "events.db")
    try:
        for index in range(5):
            event = raw_row_to_normalized(
                {
                    "timestamp": datetime(2026, 8, 17, 6, index, tzinfo=UTC).isoformat(),
                    "operation": "ALLOWED",
                    "asset_id": f"host-{index}",
                },
                source=EventSource.NETWORK,
                event_id=f"e-{index}",
            )
            store.add_recent_event(event, max_events=64)
        window = store.list_recent_events(limit=64)
        assert [e.event_id for e in window] == [f"e-{i}" for i in range(5)]
    finally:
        store.close()


@pytest.mark.parametrize("limit", [0, -1])
def test_recent_window_rejects_empty_limit(tmp_path: Path, limit: int) -> None:
    store = SqliteRecentEventStore(tmp_path / "events.db")
    try:
        assert store.list_recent_events(limit=limit) == []
    finally:
        store.close()
