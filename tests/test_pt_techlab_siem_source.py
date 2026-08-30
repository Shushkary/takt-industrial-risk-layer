"""Тесты коннектора PT SIEM — событий, нормализованных по таксономии стенда.

Маппинг построен по фактической таксономии заказчика (`taxonomy.json`, сборка 27.0.859,
331 поле), а не по предполагаемым именам колонок. Проверяются решения, которые нельзя
восстановить из кода без основания: идентичность события, состав операции, цепочка процессов
(признак ТЗ §4.2, которого в PT NAD нет), перевод типа индикатора и обе формы записи полей —
плоские ключи с точкой и вложенные объекты.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takt.domain.entities.event import ArtifactType, EventSource, NormalizedEvent
from takt.domain.entities.kill_chain import PHASE_FIELD, PHASE_ORIGIN_FIELD, KillChainPhase
from takt.infrastructure.importers.siem_events import (
    PtSiemEventSourceReader,
    map_pt_siem,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pt_techlab"
SAMPLE = FIXTURES / "pt_siem_sample.ndjson"


def _events() -> list[NormalizedEvent]:
    return list(PtSiemEventSourceReader(SAMPLE))


def test_fixture_yields_five_events_with_siem_source() -> None:
    """Чтение выгрузки даёт пять событий, все — класса `siem`."""
    events = _events()
    assert len(events) == 5
    for event in events:
        assert event.source is EventSource.SIEM


def test_event_id_is_uuid_and_never_source_msgid() -> None:
    """Идентификатор события — `uuid`, а не `id`/`msgid`.

    В таксономии `id` и `msgid` называют **тип** события в источнике (`4625` — неудачный
    вход), а не отдельное событие: сотни попыток подбора пароля получили бы один
    идентификатор и склеились бы в одно событие. Уникален только `uuid`.
    """
    event = _events()[0]
    assert event.event_id == "b2f0c1d4-0a11-4c2e-9f01-000000000001"
    assert event.payload["msgid"] == "4625"


def test_event_without_uuid_gets_composite_key() -> None:
    """Документ без `uuid` получает составной ключ, а не отбрасывается."""
    event = _events()[4]
    assert event.event_id.startswith("siem:")
    assert "2026-06-01T09:14:55Z" in event.event_id
    assert "10.10.1.17" in event.event_id


def test_operation_is_action_over_object() -> None:
    """Операция — действие над объектом: пара `action` + `object` из таксономии.

    Одно `action` слишком грубо (`ACCESS` одинаков для файла и учётной записи), а имя
    правила источника — это название срабатывания, а не то, что произошло.
    """
    events = _events()
    assert events[0].operation == "LOGIN_ACCOUNT"
    assert events[2].operation == "START_PROCESS"
    assert events[3].operation == "DETECT_ALERT"


def test_operation_falls_back_to_correlation_rule_when_no_action() -> None:
    """Без `action` операция берётся из имени корреляционного правила, затем из `msgid`."""
    document = {"time": "2026-06-01T09:00:00Z", "correlation_name": "Suspicious_Chain"}
    assert map_pt_siem(document).operation == "SUSPICIOUS_CHAIN"

    without_rule = {"time": "2026-06-01T09:00:00Z", "msgid": "4625"}
    assert map_pt_siem(without_rule).operation == "4625"

    bare = {"time": "2026-06-01T09:00:00Z"}
    assert map_pt_siem(bare).operation == "SIEM_EVENT"


def test_process_chain_fills_entities() -> None:
    """Цепочка процессов закрывает признак «процесс» ТЗ §4.2, которого в PT NAD нет.

    Идентификатор берётся из `guid`: он глобально уникален, тогда как числовой `id`
    переиспользуется операционной системой после завершения процесса.
    """
    event = _events()[2]
    assert event.entities.process_id == "{9f1c7a02-0001-0000-0000-000000000001}"
    assert event.entities.parent_process_id == "{9f1c7a02-0001-0000-0000-000000000000}"

    process_artifacts = {a.value for a in event.artifacts if a.type is ArtifactType.PROCESS}
    assert "powershell.exe" in process_artifacts
    assert "rundll32.exe" in process_artifacts


def test_entities_host_user_and_addresses() -> None:
    """Узел, учётная запись и адреса — ключи склейки событий."""
    event = _events()[0]
    assert event.entities.host_id == "ws-buh-14"
    assert event.entities.user_id == "svc_admin"
    assert event.operator_id == "svc_admin"
    assert event.entities.src_address == "10.10.1.17"
    assert event.entities.dst_address == "10.10.0.5"


def test_protocol_prefers_layer7_over_transport() -> None:
    """Протокол события — прикладной (`protocol.layer7`), транспортный — запасной."""
    events = _events()
    assert events[0].protocol == "smb"
    assert events[4].protocol == "tcp"
    assert map_pt_siem({"time": "2026-06-01T09:00:00Z"}).protocol == "siem"


def test_nested_and_flat_field_forms_give_the_same_event() -> None:
    """Выгрузка встречается в двух формах записи, и обе читаются одинаково.

    API стенда отдаёт плоские ключи с точкой (`"src.ip"`), экспорт в JSON — вложенные
    объекты (`{"src": {"ip": ...}}`). Разбор только одной формы молча терял бы адреса.
    """
    flat = {"time": "2026-06-01T09:00:00Z", "action": "login", "object": "account",
            "event_src.host": "ws-1", "src.ip": "10.0.0.1", "dst.ip": "10.0.0.2",
            "subject.account.name": "ivanov"}
    nested = {"time": "2026-06-01T09:00:00Z", "action": "login", "object": "account",
              "event_src": {"host": "ws-1"}, "src": {"ip": "10.0.0.1"},
              "dst": {"ip": "10.0.0.2"}, "subject": {"account": {"name": "ivanov"}}}

    first, second = map_pt_siem(flat), map_pt_siem(nested)
    assert first.entities == second.entities
    assert first.operation == second.operation == "LOGIN_ACCOUNT"


def test_ioc_type_becomes_typed_artifact() -> None:
    """Тип индикатора из таксономии переводится в тип артефакта TAKT."""
    event = _events()[3]
    addresses = {a.value for a in event.artifacts if a.type is ArtifactType.ADDRESS}
    assert "185.23.44.9" in addresses
    domains = {a.value for a in event.artifacts if a.type is ArtifactType.DOMAIN}
    assert "updates.cdn-delivery.top" in domains


@pytest.mark.parametrize(
    ("ioc_type", "artifact_type"),
    [
        ("domain", ArtifactType.DOMAIN),
        ("hash", ArtifactType.HASH),
        ("host", ArtifactType.HOST),
        ("ip_address", ArtifactType.ADDRESS),
        ("path", ArtifactType.FILE),
        ("url", ArtifactType.URL),
        ("username", ArtifactType.ACCOUNT),
    ],
)
def test_each_translatable_ioc_type(ioc_type: str, artifact_type: ArtifactType) -> None:
    """Каждый переводимый тип индикатора даёт артефакт своего типа."""
    document = {"time": "2026-06-01T09:00:00Z",
                "alert.ioc_type": ioc_type, "alert.ioc_value": "indicator-value"}
    event = map_pt_siem(document)
    assert any(
        artifact.type is artifact_type and artifact.value == "indicator-value"
        for artifact in event.artifacts
    )


@pytest.mark.parametrize("ioc_type", ["meta", "other", "registry", "cmdline", "binary", "email"])
def test_untranslatable_ioc_type_does_not_invent_an_artifact(ioc_type: str) -> None:
    """Типу индикатора без соответствия в модели TAKT артефакт не приписывается.

    Значение остаётся в `payload` и видно аналитику; подставить ему ближайший тип значит
    соврать о природе индикатора — реестровый ключ не файл и не домен.
    """
    document = {"time": "2026-06-01T09:00:00Z",
                "alert.ioc_type": ioc_type, "alert.ioc_value": "indicator-value"}
    event = map_pt_siem(document)
    assert all(a.value != "indicator-value" for a in event.artifacts)
    assert event.payload["alert.ioc_value"] == "indicator-value"


def test_hashes_are_lowercased() -> None:
    """Хеши приводятся к нижнему регистру: иначе одно и то же тело не склеится."""
    event = _events()[2]
    hashes = {a.value for a in event.artifacts if a.type is ArtifactType.HASH}
    assert "9f3ab4c1d2e5a6b78c90d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293ae77d" in hashes
    assert "5d41402abc4b2a76b9719d911017c592" in hashes


def test_payload_size_from_byte_counters() -> None:
    """Объём: `count.bytes`, а при разбивке по направлениям — сумма входа и выхода."""
    events = _events()
    assert events[0].payload_size == 512
    assert events[3].payload_size == 2048 + 17400
    assert map_pt_siem({"time": "2026-06-01T09:00:00Z"}).payload_size == 0


def test_incident_category_becomes_kill_chain_phase() -> None:
    """Категория инцидента переводится в фазу цепочки — с сохранением происхождения.

    Фазу продукт не вычисляет: она выводится из объявленной классификации источника, и
    основание перевода остаётся в событии.
    """
    events = _events()
    assert events[0].payload[PHASE_FIELD] == KillChainPhase.INITIAL_ACCESS.value
    assert events[0].payload[PHASE_ORIGIN_FIELD] == "incident.category=BruteForce"
    assert events[3].payload[PHASE_FIELD] == KillChainPhase.C2.value
    assert events[4].payload[PHASE_FIELD] == KillChainPhase.RECON.value
    # Событие без объявленной категории фазы не получает.
    assert PHASE_FIELD not in events[1].payload


def test_secrets_are_redacted_even_outside_the_taxonomy() -> None:
    """Секрет в поле вне таксономии всё равно не доходит до `payload`.

    В таксономии PT SIEM полей-паролей не объявлено, но выгрузка несёт свободные поля
    нормализатора. Общее маскирование по имени поля работает и здесь — как страховка.
    """
    document = {
        "time": "2026-06-01T09:00:00Z",
        "action": "login",
        "subject.account.name": "svc_admin",
        "datafield1": {"password": "P@ssw0rd-not-for-storage"},
        "cookie": "SESS=deadbeef",
    }
    event = map_pt_siem(document)

    serialized = json.dumps(event.payload, ensure_ascii=False, default=str)
    assert "P@ssw0rd-not-for-storage" not in serialized
    assert event.payload["datafield1"]["password"] == "[redacted]"
    assert event.payload["cookie"] == "[redacted]"
    # Учётная запись — не секрет: без неё не собрать корреляцию по пользователю.
    assert event.payload["subject.account.name"] == "svc_admin"


def test_document_without_time_is_rejected() -> None:
    """Событие без времени не принимается: хронология инцидента на нём не строится."""
    with pytest.raises(ValueError):
        map_pt_siem({"action": "login", "event_src.host": "ws-1"})


def test_time_cascade_falls_back_to_original_time() -> None:
    """Без `time` берётся исходное время источника, и только потом — время приёма."""
    document = {"original_time": "2026-06-01T09:00:14Z", "recv_time": "2026-06-01T09:00:17Z"}
    event = map_pt_siem(document)
    assert event.observed_at.isoformat().startswith("2026-06-01T09:00:14")


def test_malformed_line_does_not_stop_loading(tmp_path: Path) -> None:
    """Битая строка журналируется без содержимого и пропускается: загрузка идёт дальше."""
    broken = tmp_path / "broken.ndjson"
    broken.write_text(
        '{"uuid": "ok-1", "time": "2026-06-01T09:00:10Z", "action": "login"}\n'
        "{невалидный json\n"
        '{"uuid": "ok-2", "time": "2026-06-01T09:01:10Z", "action": "logout"}\n',
        encoding="utf-8",
    )
    events = list(PtSiemEventSourceReader(broken))
    assert [event.event_id for event in events] == ["ok-1", "ok-2"]


def test_dataset_loader_knows_the_pt_siem_source() -> None:
    """Выгрузку стенда есть чем принять: источник объявлен в загрузчике датасета."""
    from takt.tools.load_dataset import NDJSON_READERS, SOURCE_CLASS

    assert NDJSON_READERS["pt_siem"] is PtSiemEventSourceReader
    assert SOURCE_CLASS["pt_siem"] == EventSource.SIEM.value
