"""Протокол, операция и учётная запись событий PT NAD по фактическим схемам таблиц.

Выгрузка стенда — 38 таблиц `nad_traffic_<протокол>` (`nad_table_schemas.json`). Протокол в
документе не записан: его несёт **имя таблицы**, а поля запроса и ответа у каждой таблицы
свои. Без разбора того и другого 32 таблицы из 38 давали безликое событие `NETWORK_FLOW`
неизвестного протокола: по нему нельзя ни отличить подбор пароля от запроса DNS, ни собрать
цепочку.

Здесь закреплено то, что нельзя восстановить из кода без схемы стенда: какое поле каждой
таблицы означает операцию, какое — учётную запись, и почему колонка `protocol` таблицы RDP
протоколом события не является.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takt.domain.entities.event import ArtifactType, NormalizedEvent
from takt.infrastructure.importers.nad_events import (
    TABLE_PROTOCOL,
    NadEventSourceReader,
    map_nad,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pt_techlab"
SAMPLE = FIXTURES / "nad_protocols.ndjson"


def _by_table() -> dict[str, NormalizedEvent]:
    """События фикстуры по имени таблицы: в фикстуре по одному документу на таблицу."""
    events = list(NadEventSourceReader(SAMPLE))
    return {event.payload["table_name"]: event for event in events}


def test_every_stand_table_is_declared() -> None:
    """Таблица перевода покрывает все 38 таблиц стенда — без умолчаний по остатку.

    Таблица, которой в перечне нет, означает не «протокол неизвестен», а незамеченную
    таблицу: её события молча стали бы безликим сетевым потоком.
    """
    assert len(TABLE_PROTOCOL) == 38
    assert TABLE_PROTOCOL["nad_traffic_dns"] == "dns"
    # Таблицы, которые протокол не называют: поток несёт `app_proto`, срабатывание сигнатуры
    # и восстановленные файлы протоколом не являются.
    for table in ("nad_traffic_flow", "nad_traffic_alert", "nad_traffic_files"):
        assert TABLE_PROTOCOL[table] is None


@pytest.mark.parametrize(
    ("table", "protocol"),
    [
        ("nad_traffic_ftp", "ftp"),
        ("nad_traffic_http", "http"),
        ("nad_traffic_smb", "smb"),
        ("nad_traffic_kerberos", "kerberos"),
        ("nad_traffic_ldap", "ldap"),
        ("nad_traffic_dns", "dns"),
        ("nad_traffic_ntlm", "ntlm"),
        ("nad_traffic_socks5", "socks5"),
        ("nad_traffic_snmp", "snmp"),
        ("nad_traffic_nfs", "nfs"),
        ("nad_traffic_dcerpc", "dcerpc"),
        ("nad_traffic_dcerpc_br", "dcerpc"),
    ],
)
def test_protocol_comes_from_table_name(table: str, protocol: str) -> None:
    """Протокол события берётся из имени таблицы: в документе его нет."""
    assert _by_table()[table].protocol == protocol


def test_flow_table_keeps_its_own_app_proto() -> None:
    """У таблицы потоков протокол объявлен полем `app_proto` — оно и выигрывает."""
    assert _by_table()["nad_traffic_flow"].protocol == "ftp"


def test_rdp_protocol_column_is_not_the_event_protocol() -> None:
    """Колонка `protocol` таблицы RDP — уровень безопасности сеанса, а не протокол.

    Значение `HYBRID` (то есть CredSSP) описывает способ защиты соединения. Приняв его за
    протокол события, продукт показал бы аналитику несуществующий протокол «hybrid»
    вместо `rdp`.
    """
    event = _by_table()["nad_traffic_rdp"]
    assert event.protocol == "rdp"
    assert event.payload["protocol"] == "HYBRID"


@pytest.mark.parametrize(
    ("table", "operation"),
    [
        ("nad_traffic_ftp", "USER"),
        ("nad_traffic_http", "POST"),
        ("nad_traffic_smb", "SMB2_CREATE"),
        ("nad_traffic_kerberos", "AS-REQ"),
        ("nad_traffic_ldap", "BIND"),
        ("nad_traffic_dcerpc", "CREATESERVICEW"),
        ("nad_traffic_dcerpc_br", "STARTSERVICEW"),
        ("nad_traffic_dns", "QUERY"),
        ("nad_traffic_ntlm", "NTLMSSP_AUTH"),
        ("nad_traffic_socks5", "CONNECT"),
        ("nad_traffic_snmp", "GET-NEXT"),
        ("nad_traffic_nfs", "OPEN"),
        ("nad_traffic_pop3", "USER"),
    ],
)
def test_operation_comes_from_protocol_fields(table: str, operation: str) -> None:
    """Операция события — команда протокола из полей запроса своей таблицы."""
    assert _by_table()[table].operation == operation


def test_flow_record_stays_a_network_flow() -> None:
    """Запись потока команды не несёт и остаётся сетевым потоком — это не пробел."""
    assert _by_table()["nad_traffic_flow"].operation == "NETWORK_FLOW"


@pytest.mark.parametrize(
    ("table", "login"),
    [
        ("nad_traffic_ftp", "svc_backup"),
        ("nad_traffic_pop3", "ivanov"),
        ("nad_traffic_kerberos", "svc_admin"),
        ("nad_traffic_ldap", "CN=svc_admin,OU=Service,DC=corp,DC=local"),
        ("nad_traffic_ntlm", "svc_admin"),
        ("nad_traffic_socks5", "proxyuser"),
        ("nad_traffic_snmp", "monitor"),
        ("nad_traffic_flow", "svc_backup"),
    ],
)
def test_login_comes_from_protocol_fields(table: str, login: str) -> None:
    """Учётная запись берётся из поля аутентификации своего протокола."""
    event = _by_table()[table]
    assert event.entities.user_id == login
    assert event.operator_id == login
    assert any(
        artifact.type is ArtifactType.ACCOUNT and artifact.value == login
        for artifact in event.artifacts
    )


def test_login_from_cleartext_command_only_for_authentication_commands() -> None:
    """Аргумент команды становится логином только у команд аутентификации.

    В FTP и POP3 логин передаётся аргументом команды `USER`. У остальных команд тот же
    аргумент — имя файла или адрес получателя, и принимать его за учётную запись значит
    засорять корреляцию по пользователю ложными связями.
    """
    login_document = {"table_name": "nad_traffic_ftp", "tx_time": "2026-06-01T09:00:00Z",
                      "rqs": {"cmd": {"name": "USER", "args": ["svc_backup"]}}}
    assert map_nad(login_document).entities.user_id == "svc_backup"

    file_document = {"table_name": "nad_traffic_ftp", "tx_time": "2026-06-01T09:00:00Z",
                     "rqs": {"cmd": {"name": "RETR", "args": ["/backup/payroll.zip"]}}}
    assert map_nad(file_document).entities.user_id is None


def test_credentials_array_login_is_read() -> None:
    """`credentials` в схеме стенда — массив, и логин из него читается.

    Разбор только формы «объект» терял логин на данных стенда целиком: поле объявлено как
    `array(row("login", "valid", "password"))`.
    """
    event = _by_table()["nad_traffic_flow"]
    assert event.entities.user_id == "svc_backup"
    assert event.payload["credentials"][0]["password"] == "[redacted]"


def test_dns_query_array_gives_domain_artifact() -> None:
    """Домен запроса DNS объявлен массивом записей — артефакт берётся из первой."""
    event = _by_table()["nad_traffic_dns"]
    domains = {a.value for a in event.artifacts if a.type is ArtifactType.DOMAIN}
    assert "updates.cdn-delivery.top" in domains


def test_http_url_and_host_become_artifacts() -> None:
    """URL и узел запроса HTTP — самостоятельные индикаторы."""
    event = _by_table()["nad_traffic_http"]
    assert any(a.type is ArtifactType.URL and a.value == "/api/v1/upload" for a in event.artifacts)
    domains = {a.value for a in event.artifacts if a.type is ArtifactType.DOMAIN}
    assert "updates.cdn-delivery.top" in domains


def test_smb_and_nfs_filenames_become_artifacts() -> None:
    """Имя файла из запроса протокола — артефакт FILE, а не строка в глубине payload."""
    files = {a.value for a in _by_table()["nad_traffic_smb"].artifacts if a.type is ArtifactType.FILE}
    assert "IPC$\\svcctl" in files
    files = {a.value for a in _by_table()["nad_traffic_nfs"].artifacts if a.type is ArtifactType.FILE}
    assert "payroll.xlsx" in files


def test_dcerpc_target_account_is_an_artifact_not_the_actor() -> None:
    """Учётная запись в параметрах DCERPC — объект операции, а не тот, кто действует.

    `CreateServiceW` с `username` заводит службу от имени этой записи. Поставить её в
    `user_id` значило бы объявить её инициатором события; связь по учётной записи при этом
    нужна, поэтому она остаётся артефактом.
    """
    event = _by_table()["nad_traffic_dcerpc"]
    assert event.entities.user_id is None
    accounts = {a.value for a in event.artifacts if a.type is ArtifactType.ACCOUNT}
    assert "CORP\\svc_admin" in accounts


def test_dcerpc_broadcast_has_no_node_or_addresses() -> None:
    """У `nad_traffic_dcerpc_br` в схеме нет ни узла, ни адресов — событие всё равно принято.

    Это единственная из 38 таблиц без колонок `src` и `dst`: связать её событие с остальными
    можно только по `flow_id`. Подставлять узел неоткуда, и выдумывать его нельзя — событие
    принимается с пустыми сущностями, а `flow_id` остаётся в payload как единственная связь.
    """
    event = _by_table()["nad_traffic_dcerpc_br"]
    assert event.entities.host_id is None
    assert event.entities.src_address is None
    assert event.entities.dst_address is None
    assert event.payload["flow_id"] == "f-90210"
    assert event.operation == "STARTSERVICEW"


def test_ldap_simple_bind_password_is_redacted() -> None:
    """Пароль простой привязки LDAP передаётся открытым текстом и маскируется."""
    event = _by_table()["nad_traffic_ldap"]
    serialized = json.dumps(event.payload, ensure_ascii=False, default=str)
    assert "P@ssw0rd-not-for-storage" not in serialized


def test_socks5_and_dcerpc_passwords_are_redacted() -> None:
    """Пароли SOCKS5 и параметров DCERPC до payload не доходят."""
    for table in ("nad_traffic_socks5", "nad_traffic_dcerpc"):
        serialized = json.dumps(_by_table()[table].payload, ensure_ascii=False, default=str)
        assert "P@ssw0rd-not-for-storage" not in serialized, table


def test_table_name_is_taken_from_the_file_when_the_document_is_silent(tmp_path: Path) -> None:
    """Выгрузка из Trino имени таблицы в документе не несёт — оно берётся из имени файла.

    Экспорт делается по одной таблице (`SELECT * FROM nad_traffic_dns`), поэтому имя файла —
    штатный и единственный источник протокола для такой выгрузки.
    """
    export = tmp_path / "nad_traffic_dns.ndjson"
    export.write_text(
        '{"tx_id": 1, "tx_time": "2026-06-01T09:00:00Z", "opcode": "QUERY",'
        ' "query": [{"rrname": "evil.example", "rrtype": "A"}]}\n',
        encoding="utf-8",
    )
    event = next(iter(NadEventSourceReader(export)))
    assert event.protocol == "dns"
    assert event.operation == "QUERY"


def test_reader_table_name_overrides_the_file_name(tmp_path: Path) -> None:
    """Имя таблицы можно задать явно: имя файла выгрузки заказчик выбирает произвольно."""
    export = tmp_path / "export-2026-06-01.ndjson"
    export.write_text(
        '{"tx_id": 1, "tx_time": "2026-06-01T09:00:00Z", "rqs": {"method": "GET"}}\n',
        encoding="utf-8",
    )
    event = next(iter(NadEventSourceReader(export, table_name="nad_traffic_http")))
    assert event.protocol == "http"
    assert event.operation == "GET"


def test_unknown_table_name_does_not_invent_a_protocol(tmp_path: Path) -> None:
    """Незнакомое имя таблицы протоколом не становится: событие идёт как сетевое."""
    export = tmp_path / "some_other_table.ndjson"
    export.write_text('{"tx_id": 1, "tx_time": "2026-06-01T09:00:00Z"}\n', encoding="utf-8")
    event = next(iter(NadEventSourceReader(export)))
    assert event.protocol == "network"
    assert event.operation == "NETWORK_FLOW"


def test_password_in_command_arguments_is_redacted() -> None:
    """Аргумент команды `PASS` — это пароль открытым текстом, и в payload он не идёт.

    Разбор команд протокола вскрыл то, чего маскирование по имени поля не видело: у FTP,
    POP3 и IMAP пароль лежит не в поле `password`, а в аргументе команды.
    """
    document = {"table_name": "nad_traffic_ftp", "tx_time": "2026-06-01T09:00:00Z",
                "rqs": {"cmd": {"name": "PASS", "args": ["P@ssw0rd-not-for-storage"]}}}
    event = map_nad(document)

    serialized = json.dumps(event.payload, ensure_ascii=False, default=str)
    assert "P@ssw0rd-not-for-storage" not in serialized
    assert event.payload["rqs"]["cmd"]["args"] == "[redacted]"


def test_imap_login_keeps_the_account_and_drops_the_password() -> None:
    """Команда `LOGIN` несёт и учётную запись, и пароль одной строкой.

    Учётная запись нужна для корреляции и остаётся в сущностях события, а сам аргумент
    целиком маскируется: разделить его на логин и пароль надёжно нельзя — пароль может
    содержать пробел.
    """
    document = {"table_name": "nad_traffic_imap", "tx_time": "2026-06-01T09:00:00Z",
                "rqs": {"cmd": {"name": "LOGIN", "args": "ivanov P@ssw0rd-not-for-storage"}}}
    event = map_nad(document)

    assert event.entities.user_id == "ivanov"
    assert event.payload["rqs"]["cmd"]["args"] == "[redacted]"
    assert "P@ssw0rd-not-for-storage" not in json.dumps(event.payload, ensure_ascii=False)


def test_snmp_community_and_http_authorization_are_redacted() -> None:
    """Строка сообщества SNMP и заголовок `Authorization` — предъявители доступа.

    Разбор таблиц вскрыл ещё три носителя секрета помимо полей с именем `password`:
    `community` в SNMP v1/v2c — это и есть пароль доступа к устройству, `auth_params` и
    `privacy_params` в SNMPv3 — материал аутентификации и шифрования, а `authorization` в
    HTTP несёт пару «логин:пароль» в кодировке base64.
    """
    snmp = {"table_name": "nad_traffic_snmp", "tx_time": "2026-06-01T09:00:00Z",
            "rqs": {"msg_type": "GET", "community": "s3cret-community",
                    "usm_sec_params": {"user_name": "monitor", "auth_params": "a1b2c3",
                                       "privacy_params": "d4e5f6"}}}
    payload = map_nad(snmp).payload
    assert payload["rqs"]["community"] == "[redacted]"
    assert payload["rqs"]["usm_sec_params"]["auth_params"] == "[redacted]"
    assert payload["rqs"]["usm_sec_params"]["privacy_params"] == "[redacted]"
    # Имя пользователя SNMPv3 — не секрет: по нему идёт корреляция.
    assert payload["rqs"]["usm_sec_params"]["user_name"] == "monitor"

    http = {"table_name": "nad_traffic_http", "tx_time": "2026-06-01T09:00:00Z",
            "rqs": {"method": "GET", "url": "/admin",
                    "authorization": "Basic c3ZjX2FkbWluOlBAc3N3MHJk",
                    "proxy_authorization": "Basic c3ZjX2FkbWluOlBAc3N3MHJk"}}
    payload = map_nad(http).payload
    assert payload["rqs"]["authorization"] == "[redacted]"
    assert payload["rqs"]["proxy_authorization"] == "[redacted]"


def test_dcerpc_auth_block_is_not_a_secret() -> None:
    """Блок `auth` в DCERPC — тип и уровень аутентификации, а не её материал.

    По схеме это `row("type", "level")`: маскировать его значит потерять признак того,
    была ли аутентификация подписана, ничего при этом не защитив.
    """
    payload = _by_table()["nad_traffic_dcerpc"].payload
    assert payload["rqs"]["auth"] == {"type": "NTLMSSP", "level": "PKT_PRIVACY"}


def test_smtp_auth_mechanism_is_not_an_account() -> None:
    """У команды `AUTH` первое слово аргумента — механизм, а не учётная запись.

    SMTP передаёт `AUTH LOGIN` или `AUTH PLAIN <base64>`: приняв первое слово за логин,
    продукт завёл бы в корреляции несуществующую учётную запись `LOGIN`. Сам аргумент при
    этом маскируется — в `PLAIN` он несёт логин и пароль в кодировке base64.
    """
    document = {"table_name": "nad_traffic_smtp", "tx_time": "2026-06-01T09:00:00Z",
                "rqs": {"cmd": {"name": "AUTH", "args": "PLAIN AHN2Y19hZG1pbgBQQHNzdzByZA=="}}}
    event = map_nad(document)

    assert event.entities.user_id is None
    assert event.payload["rqs"]["cmd"]["args"] == "[redacted]"
    assert event.operation == "AUTH"
