"""Коннектор к сетевому сенсору PT NAD (единое хранилище заказчика).

Маппинг построен по схеме индекса, предоставленной заказчиком
(Elasticsearch mapping, 1786 полей). Документы читаются построчно в формате
NDJSON — по одному JSON-объекту на строку, как в выгрузке `_search`/`scroll`,
поэтому объём файла не влияет на потребление памяти.

Безопасность: трафик несёт пароли и ключи сессий — в `credentials`, а также в запросах
SMB и DCERPC. Эти значения **не** попадают ни в `payload`, ни в логи: они заменяются на
маркер общим для всех коннекторов маскированием
(`takt.infrastructure.importers.redaction`); список полей и основание — `REDACTED_FIELD_NAMES`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.importers.csv_events import _parse_ts
from takt.infrastructure.importers.redaction import (
    REDACTED_FIELD_NAMES,
    REDACTED_MARKER,
    redact,
)
from takt.infrastructure.importers.source_phase import annotate_phase

logger = logging.getLogger(__name__)


# Приоритет полей: первое непустое значение выигрывает. Каскад покрывает две
# формы записи: полную схему индекса заказчика (`src.host_id`, `s_msg`,
# `query.rrname`) и упрощённую выгрузку потоков (`src.host`, `verdict`,
# `dns.query`), которая встречается в демонстрационных наборах.
TIME_FIELDS = ("ts", "ts_start", "_ltime", "tx_time")
# Протокол. `app_proto` объявлен только у таблицы потоков и называет прикладной протокол
# точнее всего. Имя таблицы идёт раньше колонки `protocol`, потому что у таблицы RDP эта
# колонка означает уровень защиты сеанса (`HYBRID`, то есть CredSSP), а не протокол события.
PROTOCOL_FIELDS = ("app_proto", "proto")
PROTOCOL_FALLBACK_FIELDS = ("protocol",)
# Операция. Первые три пути — сигнатурные таблицы и упрощённые выгрузки, дальше идут поля
# команды каждого протокола: у 32 таблиц из 38 иначе получалось безликое `NETWORK_FLOW`.
OPERATION_FIELDS = (
    "s_msg", "alert.description", "verdict",
    "rqs.cmd.name",          # FTP, POP3, IMAP, SMTP, NFS (в NFS команды объявлены массивом)
    "rqs.method",            # HTTP, SIP
    "rqs.command",           # SMB, SOCKS5
    "rqs.operation.name",    # DCERPC и его широковещательная таблица
    "rqs.msg_type",          # NTLM, SNMP
    "rqs.type",              # Kerberos, LDAP, ICMP
    "rqs.options.type",      # DHCP: тип сообщения точнее, чем `op`
    "rqs.op",                # DHCP
    "rqs.mode",              # NTP
    "opcode",                # DNS
    "type",                  # SSH, TLS
    "app_name",
)
HOST_FIELDS = (
    "src.host_id", "host.host_id", "attacker.host_id",
    "src.host", "host.host", "src.name", "host.name",
)
# Учётная запись. `credentials` в схеме стенда — массив, поэтому путь разрешается и через
# элементы массива; остальные пути — поля аутентификации конкретных протоколов.
USER_FIELDS = (
    "user",                          # MySQL, PostgreSQL, Oracle TNS
    "credentials.login",             # запись потока
    "rqs.user_name",                 # NTLM, SOCKS5
    "rqs.cname.principal",           # Kerberos
    "rqs.bind.name",                 # LDAP: различающееся имя привязки
    "rqs.usm_sec_params.user_name",  # SNMPv3
    "subject",
)
SRC_FIELDS = ("src.ip", "attacker.ip")
DST_FIELDS = ("dst.ip", "victim.ip")
DOMAIN_FIELDS = (
    "query.rrname", "dns.query", "server_name", "dst.dns",
    "rqs.host",          # HTTP: узел запроса
    "rqs.domain_name",   # SOCKS5: узел, к которому просят соединение
)
URL_FIELDS = ("rqs.url", "rqs.uri")  # HTTP, SIP
# Имя файла в запросе протокола. Полный путь и имя извлечённого файла (`filepath`,
# `filename`) разбираются отдельной парой: у них приоритет «путь, иначе имя».
FILE_FIELDS = (
    "rqs.create.filename",     # SMB
    "rqs.read.filename", "rqs.write.filename",  # TFTP
    "rqs.cmd.open.filename",   # NFS
    "path",                    # именованный канал
)
# Учётные записи из параметров вызова DCERPC. Это объект операции (например, запись, от имени
# которой заводится служба), а не тот, кто действует, поэтому они становятся артефактом и не
# попадают в `user_id`: иначе продукт объявил бы их инициатором события.
TARGET_ACCOUNT_FIELDS = (
    "rqs.operation.params.user", "rqs.operation.params.username",
    "rsp.operation.username", "rsp.operation.account_name",
)

# Команды, аргумент которых начинается с учётной записи (FTP/POP3 `USER`, IMAP `LOGIN`).
# `AUTH` сюда не входит: у SMTP первое слово его аргумента — механизм (`PLAIN`, `LOGIN`),
# и учётной записи в нём нет вовсе.
LOGIN_COMMANDS: frozenset[str] = frozenset({"USER", "LOGIN"})
# Команды, аргумент которых содержит пароль открытым текстом. `USER` сюда не входит: его
# аргумент — только логин, и он нужен для корреляции.
SECRET_ARGUMENT_COMMANDS: frozenset[str] = frozenset({"PASS", "LOGIN", "AUTH", "AUTHENTICATE"})

# Протокол по имени таблицы стенда. Перечислены **все** 38 таблиц
# (`nad_table_schemas.json`): таблица, которой в перечне нет, означает не «протокол
# неизвестен», а незамеченную таблицу — её события молча стали бы сетевым потоком.
# `None` — таблица протокол не называет: запись потока несёт `app_proto`, срабатывание
# сигнатуры, восстановленное письмо и извлечённый файл протоколом не являются.
TABLE_PROTOCOL: dict[str, str | None] = {
    "nad_traffic_alert": None,
    "nad_traffic_s_alert": None,
    "nad_traffic_flow": None,
    "nad_traffic_files": None,
    "nad_traffic_files_old": None,
    "nad_traffic_mail": None,
    "nad_traffic_dcerpc": "dcerpc",
    # Широковещательная таблица DCERPC: те же вызовы, но без сторон соединения.
    "nad_traffic_dcerpc_br": "dcerpc",
    "nad_traffic_dhcp": "dhcp",
    "nad_traffic_dns": "dns",
    "nad_traffic_ftp": "ftp",
    "nad_traffic_http": "http",
    "nad_traffic_icmp": "icmp",
    "nad_traffic_imap": "imap",
    "nad_traffic_kerberos": "kerberos",
    "nad_traffic_ldap": "ldap",
    # MS-NMF — обрамление сообщений .NET поверх TCP.
    "nad_traffic_mc_nmf": "nmf",
    "nad_traffic_mysql": "mysql",
    "nad_traffic_nfs": "nfs",
    "nad_traffic_ntlm": "ntlm",
    "nad_traffic_ntp": "ntp",
    "nad_traffic_oracle_tns": "tns",
    # Именованные каналы передаются поверх SMB — это его сеанс, а не отдельный протокол.
    "nad_traffic_pipes": "smb",
    "nad_traffic_pop3": "pop3",
    "nad_traffic_postgresql": "postgresql",
    "nad_traffic_quic": "quic",
    "nad_traffic_rdp": "rdp",
    "nad_traffic_rfb": "rfb",
    "nad_traffic_sip": "sip",
    "nad_traffic_smb": "smb",
    "nad_traffic_smtp": "smtp",
    "nad_traffic_snmp": "snmp",
    "nad_traffic_socks5": "socks5",
    "nad_traffic_ssh": "ssh",
    "nad_traffic_tds": "tds",
    "nad_traffic_telnet": "telnet",
    "nad_traffic_tftp": "tftp",
    "nad_traffic_tls": "tls",
}
# Поля, в которых имя таблицы может прийти вместе с документом. Штатный источник — сама
# выгрузка (файл или явное имя при чтении): экспорт делается по одной таблице.
TABLE_NAME_FIELDS = ("table_name", "_table", "__table")


def _get(doc: dict[str, Any], path: str) -> Any:
    """Значение по точечному пути (`src.host_id`); None, если ветки нет.

    Путь проходит и через массивы: в схемах стенда записями-массивами объявлены
    `credentials`, `query`, команды NFS. Берётся первый элемент, в котором остаток пути
    разрешается, — разбор только формы «объект» терял логин и домен запроса целиком.
    """
    return _resolve(doc, tuple(path.split(".")))


def _resolve(node: Any, parts: tuple[str, ...]) -> Any:
    if isinstance(node, list):
        for item in node:
            found = _resolve(item, parts)
            if found is not None:
                return found
        return None
    if not parts:
        return node
    if not isinstance(node, dict):
        return None
    value = node.get(parts[0])
    if value is None:
        return None
    return _resolve(value, parts[1:])


def _text(doc: dict[str, Any], path: str) -> str | None:
    """Строковое значение по пути: списки сводятся к первому элементу."""
    value = _get(doc, path)
    if isinstance(value, list):
        value = next((item for item in value if item not in (None, "")), None)
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _first(doc: dict[str, Any], paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value = _text(doc, path)
        if value is not None:
            return value
    return None


def _event_id(doc: dict[str, Any]) -> str:
    """Идентификатор события: явный id хранилища, иначе составной ключ потока."""
    for path in ("_id", "_ndx", "_prn.id", "flow_id", "tx_id", "file_id"):
        value = _text(doc, path)
        if value is not None:
            return value
    parts = [
        _first(doc, TIME_FIELDS) or "",
        _first(doc, SRC_FIELDS) or "",
        _text(doc, "src.port") or "",
        _first(doc, DST_FIELDS) or "",
        _text(doc, "dst.port") or "",
    ]
    key = "|".join(parts).strip("|")
    if not key:
        raise ValueError("document has neither identifier nor flow key")
    return f"nad:{key}"


def _payload_size(doc: dict[str, Any]) -> int:
    """Объём: сумма направлений потока, иначе размер файла/объекта."""
    total = 0
    seen = False
    for path in ("bytes.sent", "bytes.recv"):
        raw = _get(doc, path)
        if isinstance(raw, (int, float)):
            total += int(raw)
            seen = True
    if seen:
        return max(0, total)
    # Упрощённая выгрузка хранит объём одним числом в `bytes`, а не разбивкой
    # по направлениям; булево значение объёмом не считается.
    for path in ("bytes", "size"):
        raw = _get(doc, path)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return max(0, int(raw))
    return 0


def _table_name(doc: dict[str, Any], table_name: str | None) -> str | None:
    """Имя таблицы стенда: из документа, иначе объявленное при чтении выгрузки."""
    return _first(doc, TABLE_NAME_FIELDS) or table_name


def _login_from_command(doc: dict[str, Any]) -> str | None:
    """Учётная запись из аргумента команды аутентификации открытым текстом.

    В FTP и POP3 логин передаётся аргументом команды `USER`, в IMAP — первым словом
    аргумента `LOGIN`. У остальных команд тот же аргумент означает имя файла или адрес
    получателя, поэтому логином считается только аргумент команд из `LOGIN_COMMANDS`.
    """
    name = _text(doc, "rqs.cmd.name")
    if name is None or name.upper() not in LOGIN_COMMANDS:
        return None
    argument = _text(doc, "rqs.cmd.args")
    if argument is None:
        return None
    # У `LOGIN` за логином в том же аргументе идёт пароль — берётся первое слово.
    return argument.split()[0]


def _redact_command_arguments(payload: dict[str, Any]) -> dict[str, Any]:
    """Замаскировать аргументы команд, несущих пароль открытым текстом.

    Маскирования по имени поля здесь недостаточно: у FTP, POP3 и IMAP пароль лежит не в
    поле `password`, а в аргументе команды (`PASS`, `LOGIN`). Аргумент маскируется целиком —
    отделить в нём пароль от логина надёжно нельзя, пароль может содержать пробел. Сама
    учётная запись при этом не теряется: она уже разобрана в сущности события.
    """
    request = payload.get("rqs")
    if not isinstance(request, dict):
        return payload
    command = request.get("cmd")
    entries = command if isinstance(command, list) else [command]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip().upper()
        if name in SECRET_ARGUMENT_COMMANDS and entry.get("args") not in (None, "", []):
            entry["args"] = REDACTED_MARKER
    return payload


def _artifacts(doc: dict[str, Any], user: str | None) -> tuple[EventArtifact, ...]:
    """Индикаторы: хеши, отпечатки TLS, файлы, URL, домены, адрес назначения, учётки."""
    candidates: list[tuple[ArtifactType, str | None]] = [
        (ArtifactType.HASH, _text(doc, "sha256")),
        (ArtifactType.HASH, _text(doc, "md5")),
        (ArtifactType.HASH, _text(doc, "ja3_md5")),
        (ArtifactType.HASH, _text(doc, "ja4")),
        (ArtifactType.FILE, _text(doc, "filepath") or _text(doc, "filename")),
        *((ArtifactType.FILE, _text(doc, path)) for path in FILE_FIELDS),
        *((ArtifactType.URL, _text(doc, path)) for path in URL_FIELDS),
        *((ArtifactType.DOMAIN, _text(doc, path)) for path in DOMAIN_FIELDS),
        (ArtifactType.ADDRESS, _first(doc, DST_FIELDS)),
        (ArtifactType.ACCOUNT, user),
        *((ArtifactType.ACCOUNT, _text(doc, path)) for path in TARGET_ACCOUNT_FIELDS),
    ]
    seen: set[tuple[str, str]] = set()
    artifacts: list[EventArtifact] = []
    for kind, value in candidates:
        if not value:
            continue
        normalized = value.lower() if kind is ArtifactType.HASH else value
        marker = (str(kind), normalized)
        if marker in seen:
            continue
        seen.add(marker)
        artifacts.append(EventArtifact(kind, normalized))
    return tuple(artifacts)


def map_nad(
    doc: dict[str, Any], trust: float = 1.0, table_name: str | None = None
) -> NormalizedEvent:
    """Документ PT NAD → нормализованное событие TAKT.

    `table_name` — имя таблицы стенда, из которой сделана выгрузка. Протокол в документе не
    записан, и без имени таблицы событие остаётся сетевым потоком неизвестного протокола.
    """
    observed_raw = _first(doc, TIME_FIELDS)
    if observed_raw is None:
        raise ValueError("document has no timestamp field")

    operation = _first(doc, OPERATION_FIELDS) or "NETWORK_FLOW"
    user = _first(doc, USER_FIELDS) or _login_from_command(doc)
    table = _table_name(doc, table_name)
    protocol = (
        _first(doc, PROTOCOL_FIELDS)
        or (TABLE_PROTOCOL.get(table.lower()) if table else None)
        or _first(doc, PROTOCOL_FALLBACK_FIELDS)
        or "network"
    )
    # Фаза цепочки: у выгрузки стенда её нет, и без перевода классификации источника событие
    # не попадёт в хронологию инцидента.
    payload = annotate_phase(_redact_command_arguments(redact(doc)))
    # Техника MITRE ATT&CK выносится в payload плоским полем: по ней
    # корреляция и UI строят связи, не разбирая исходный документ.
    technique = _text(doc, "att_ck")
    if technique:
        payload["mitre_technique"] = technique

    return NormalizedEvent(
        event_id=_event_id(doc),
        observed_at=_parse_ts(observed_raw),
        source=EventSource.NDR,
        protocol=protocol,
        operation=operation.upper(),
        payload_size=_payload_size(doc),
        payload=payload,
        operator_id=user or "",
        entities=EventEntities(
            host_id=_first(doc, HOST_FIELDS),
            user_id=user,
            src_address=_first(doc, SRC_FIELDS),
            dst_address=_first(doc, DST_FIELDS),
        ),
        artifacts=_artifacts(doc, user),
        ingest_trust=trust,
    )


@dataclass(frozen=True, slots=True)
class NadEventSourceReader:
    """Потоковое чтение выгрузки PT NAD в формате NDJSON.

    Битая строка не останавливает загрузку: она журналируется без содержимого
    документа (в нём возможны секреты) и пропускается.
    """

    path: Path
    ingest_trust: float = 1.0
    table_name: str | None = None

    def _table(self) -> str | None:
        """Имя таблицы стенда: объявленное при чтении, иначе имя файла выгрузки.

        Экспорт из хранилища делается по одной таблице (`SELECT * FROM nad_traffic_dns`),
        поэтому имя файла — штатный источник протокола. Незнакомое имя протоколом не
        становится: событие идёт как сетевое, а не с выдуманным протоколом.
        """
        if self.table_name is not None:
            return self.table_name
        stem = self.path.stem.lower()
        return stem if stem in TABLE_PROTOCOL else None

    def __iter__(self) -> Iterator[NormalizedEvent]:
        table = self._table()
        with self.path.open(encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    doc = json.loads(text)
                    # Выгрузки _search кладут документ в поле _source.
                    if isinstance(doc, dict) and isinstance(doc.get("_source"), dict):
                        source_doc = dict(doc["_source"])
                        if "_id" in doc:
                            source_doc.setdefault("_id", doc["_id"])
                        doc = source_doc
                    if not isinstance(doc, dict):
                        raise ValueError("document is not an object")
                    yield map_nad(doc, self.ingest_trust, table)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "nad document skipped path=%s line=%d reason=%s",
                        self.path,
                        line_number,
                        exc,
                    )


__all__ = [
    "REDACTED_FIELD_NAMES",
    "TABLE_PROTOCOL",
    "NadEventSourceReader",
    "map_nad",
    "redact",
]
