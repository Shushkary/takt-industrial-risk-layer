"""Тесты коннектора PT NAD — сетевого сенсора единого хранилища.

Проверяют маппинг документов, потоковое чтение NDJSON, редактирование секретов.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takt.domain.entities.event import ArtifactType, EventSource
from takt.infrastructure.importers.nad_events import (
    NadEventSourceReader,
    map_nad,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pt_techlab"


def test_nad_fixture_yields_five_events_with_ndr_source() -> None:
    """Чтение фикстуры даёт ровно 5 событий, у всех source == EventSource.NDR."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson")
    events = list(reader)
    assert len(events) == 5
    for event in events:
        assert event.source is EventSource.NDR


def test_nad_first_document_nad_0001_fields() -> None:
    """Первый документ (nad-0001): проверка основных полей и артефактов."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson")
    events = list(reader)
    event = events[0]

    assert event.event_id == "nad-0001"
    assert event.protocol == "dns"
    assert event.operation == "DNS QUERY TO SUSPICIOUS DYNAMIC DOMAIN"  # в верхнем регистре
    assert event.entities.host_id == "ws-buh-14"
    assert event.entities.src_address == "10.10.1.17"
    assert event.entities.dst_address == "10.10.0.2"

    # Проверка артефакта DOMAIN
    domain_artifacts = [a for a in event.artifacts if a.type is ArtifactType.DOMAIN]
    assert any(a.value == "updates.cdn-delivery.top" for a in domain_artifacts)


def test_nad_security_password_not_in_payload_but_login_preserved() -> None:
    """Документ nad-0004: пароль НЕ в payload, login сохранён и попадает в entities."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson", ingest_trust=1.0)
    events = list(reader)
    event = events[3]  # nad-0004 — четвёртый документ (индекс 3)

    # Пароль не должен встречаться нигде в serialized payload
    payload_str = json.dumps(event.payload, ensure_ascii=False, default=str)
    assert "P@ssw0rd-not-for-storage" not in payload_str

    # Пароль должен быть заменён на маркер
    assert event.payload["credentials"]["password"] == "[redacted]"

    # Login должен быть сохранён
    assert event.payload["credentials"]["login"] == "svc_admin"
    assert event.entities.user_id == "svc_admin"

    # Login должен попасть в артефакты как ACCOUNT
    account_artifacts = [a for a in event.artifacts if a.type is ArtifactType.ACCOUNT]
    assert any(a.value == "svc_admin" for a in account_artifacts)


def test_nad_hashes_lowercased() -> None:
    """Хеши приводятся к нижнему регистру (nad-0003: SHA256 в верхнем, должна быть нижняя)."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson")
    events = list(reader)
    event = events[2]  # nad-0003 — третий документ (индекс 2)

    hash_artifacts = [a for a in event.artifacts if a.type is ArtifactType.HASH]
    assert len(hash_artifacts) > 0

    # Все хеши должны быть в нижнем регистре
    for artifact in hash_artifacts:
        assert artifact.value == artifact.value.lower()

    # Самый длинный хеш (SHA256-подобный) должен соответствовать исходному в нижнем регистре
    longest_hash = max(hash_artifacts, key=lambda a: len(a.value))
    assert longest_hash.value == "9f3ab4c1d2e5a6b78c90d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293ae77d"


def test_nad_payload_size_sum_of_bytes_sent_recv() -> None:
    """payload_size для nad-0002 равен сумме bytes.sent (18422) + bytes.recv (240311)."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson")
    events = list(reader)
    event = events[1]  # nad-0002 — второй документ (индекс 1)

    expected_size = 18422 + 240311
    assert event.payload_size == expected_size


def test_nad_mitre_technique_in_payload() -> None:
    """MITRE техника из att_ck попадает в payload['mitre_technique'] (nad-0002: T1573.002)."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson")
    events = list(reader)
    event = events[1]  # nad-0002 — второй документ (индекс 1)

    assert "mitre_technique" in event.payload
    assert event.payload["mitre_technique"] == "T1573.002"


def test_nad_malformed_json_does_not_stop_loading(tmp_path: pytest.TempPathFactory) -> None:
    """Битая JSON строка не роняет загрузку: валидный документ, {невалид}, валидный → 2 события."""
    test_file = tmp_path / "broken.ndjson"
    test_file.write_text(
        '{"_ndx": "valid-1", "ts": "2026-06-01T09:00:10Z", "app_proto": "dns"}\n'
        '{невалидный json\n'
        '{"_ndx": "valid-2", "ts": "2026-06-01T09:01:10Z", "app_proto": "http"}\n',
        encoding="utf-8"
    )

    reader = NadEventSourceReader(test_file)
    events = list(reader)
    assert len(events) == 2
    assert events[0].event_id == "valid-1"
    assert events[1].event_id == "valid-2"


def test_nad_document_without_timestamp_raises_valueerror() -> None:
    """Документ без единого поля времени (ts/ts_start/_ltime/tx_time) вызывает ValueError."""
    doc_no_timestamp = {
        "_ndx": "bad-doc",
        "app_proto": "tcp",
        "src": {"ip": "10.0.0.1"},
        "dst": {"ip": "10.0.0.2"},
    }
    with pytest.raises(ValueError, match="document has no timestamp field"):
        map_nad(doc_no_timestamp)


def test_nad_ingest_trust_propagated() -> None:
    """ingest_trust пробрасывается в события (передай 0.8 и проверь)."""
    reader = NadEventSourceReader(FIXTURES / "nad_sample.ndjson", ingest_trust=0.8)
    events = list(reader)

    for event in events:
        assert event.ingest_trust == 0.8
