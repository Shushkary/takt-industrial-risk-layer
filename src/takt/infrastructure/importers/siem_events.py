"""Коннектор к системе сбора событий PT SIEM (таксономия стенда).

Маппинг построен по фактической таксономии заказчика (`taxonomy.json`, сборка 27.0.859,
331 поле), а не по предполагаемым именам колонок. Таксономия — это уже нормализованная модель
события: `action` называет действие, `object` — объект действия, `subject.*` — того, кто
действует, `event_src.*` — узел и правило источника. Поэтому коннектор не разбирает исходный
текст события, а переносит объявленные поля в каноническое событие TAKT.

Главное, что даёт этот класс источника и чего нет в PT NAD, — **цепочка процессов**
(`subject.process.guid` и `subject.process.parent.guid`): признак «процесс» из ТЗ §4.2 сетевой
сенсор не видит принципиально.

Выгрузка читается построчным NDJSON. Поля встречаются в двух формах записи: плоские ключи с
точкой (`"src.ip"`, так отдаёт API стенда) и вложенные объекты (`{"src": {"ip": ...}}`);
читаются обе — разбор только одной молча терял бы адреса и учётные записи.

CSV-маппер `map_siem` для обезличенного датасета остаётся здесь же: он читает другой формат
(колонки `record_id`, `device_host`, `rule_name`) и к таксономии стенда отношения не имеет.
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
from takt.infrastructure.importers.redaction import redact
from takt.infrastructure.importers.soc_csv import CsvEventSourceReader, map_siem
from takt.infrastructure.importers.source_phase import annotate_phase

logger = logging.getLogger(__name__)

# Приоритет полей: первое непустое значение выигрывает.
#
# Время. `time` — время события в нормализованной записи; `original_time` — время, как его
# указал источник до нормализации; `recv_time` — время приёма в SIEM, а не наступления
# события, поэтому оно последнее: по нему хронология инцидента поедет на задержку доставки.
TIME_FIELDS = ("time", "original_time", "start_time", "recv_time")
# Протокол: прикладной точнее транспортного, `siem` — для событий узла, где протокола нет.
PROTOCOL_FIELDS = ("protocol.layer7", "protocol")
# Узел: `event_src.*` называет источник записи — для событий конечной точки это и есть узел.
HOST_FIELDS = (
    "event_src.host", "event_src.hostname", "event_src.fqdn", "event_src.asset",
    "src.host", "src.hostname",
)
# Учётная запись: имя, а не полная запись `домен\\имя`, — иначе не склеится с логином из
# сетевого сенсора, где домена нет.
USER_FIELDS = ("subject.account.name", "subject.name", "subject.account.id")
PROCESS_FIELDS = ("subject.process.guid", "subject.process.id")
PARENT_PROCESS_FIELDS = ("subject.process.parent.guid", "subject.process.parent.id")
SRC_FIELDS = ("src.ip", "external_src.ip", "assigned_src_ip")
DST_FIELDS = ("dst.ip", "external_dst.ip", "assigned_dst_ip")
# Операция, если действие не объявлено: имя корреляционного правила, затем правила источника,
# затем идентификатор типа события.
OPERATION_FALLBACK_FIELDS = ("correlation_name", "event_src.rule", "msgid", "event_type")

# Перевод типа индикатора (`alert.ioc_type`, перечисление таксономии) в тип артефакта TAKT.
# Переводится только то, для чего в модели есть точный тип. Остальные значения перечисления
# (`binary`, `cmdline`, `email`, `mac_address`, `meta`, `other`, `registry`) артефакта не
# получают: реестровый ключ — не файл и не домен, и приписать ему ближайший тип значит соврать
# о природе индикатора. Значение остаётся в `payload` и видно аналитику.
IOC_ARTIFACT_TYPES: dict[str, ArtifactType] = {
    "domain": ArtifactType.DOMAIN,
    "hash": ArtifactType.HASH,
    "host": ArtifactType.HOST,
    "ip_address": ArtifactType.ADDRESS,
    "path": ArtifactType.FILE,
    "url": ArtifactType.URL,
    "username": ArtifactType.ACCOUNT,
}

HASH_FIELDS = (
    "object.hash.sha256", "object.hash.md5", "object.hash.sha1",
    "subject.process.hash.sha256", "subject.process.hash.md5",
    "object.process.hash.sha256", "subject.process.parent.hash.sha256",
)
FILE_FIELDS = (
    "object.fullpath", "object.path",
    "subject.process.fullpath", "subject.process.path",
    "object.process.fullpath", "subject.process.parent.fullpath",
)
PROCESS_NAME_FIELDS = (
    "subject.process.name", "object.process.name", "subject.process.parent.name",
)
ACCOUNT_FIELDS = ("subject.account.name", "object.account.name")
# Доменные имена: только сетевые. `object.domain` и `subject.account.domain` — домен
# каталога (`CORP`), а не DNS-имя, и артефактом типа `domain` не становятся.
DOMAIN_FIELDS = ("dst.fqdn", "external_dst.fqdn", "event_src.fqdn")


def _field(doc: dict[str, Any], path: str) -> Any:
    """Значение поля таксономии в любой из двух форм записи.

    Сначала пробуется плоский ключ с точкой (`"src.ip"`) — так поля называет API стенда,
    затем спуск по вложенным объектам (`{"src": {"ip": ...}}`) — так выглядит экспорт в JSON.
    """
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _text(doc: dict[str, Any], path: str) -> str | None:
    """Строковое значение по пути: списки сводятся к первому непустому элементу."""
    value = _field(doc, path)
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


def _number(doc: dict[str, Any], path: str) -> int | None:
    value = _field(doc, path)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _event_id(doc: dict[str, Any]) -> str:
    """Идентификатор события: `uuid`, иначе составной ключ.

    `id` и `msgid` в идентификацию намеренно не входят: в таксономии они называют **тип**
    события в источнике (`4625` — неудачный вход), а не отдельное событие. Сотни попыток
    подбора пароля получили бы один идентификатор и склеились бы в одно событие.
    """
    value = _text(doc, "uuid")
    if value is not None:
        return value
    parts = [
        _first(doc, TIME_FIELDS) or "",
        _first(doc, HOST_FIELDS) or "",
        _text(doc, "msgid") or "",
        _first(doc, SRC_FIELDS) or "",
        _first(doc, DST_FIELDS) or "",
        _first(doc, USER_FIELDS) or "",
    ]
    key = "|".join(parts).strip("|")
    if not key:
        raise ValueError("document has neither uuid nor identifying fields")
    return f"siem:{key}"


def _operation(doc: dict[str, Any]) -> str:
    """Операция события: действие над объектом — пара `action` + `object` таксономии.

    Одно `action` слишком грубо: `ACCESS` одинаков для файла и для учётной записи. Имя
    правила источника операцией не является — это название срабатывания, а не то, что
    произошло, поэтому оно идёт запасным вариантом.
    """
    action = _text(doc, "action")
    target = _text(doc, "object")
    if action and target:
        return f"{action}_{target}".upper()
    if action:
        return action.upper()
    fallback = _first(doc, OPERATION_FALLBACK_FIELDS)
    return fallback.upper() if fallback else "SIEM_EVENT"


def _payload_size(doc: dict[str, Any]) -> int:
    """Объём: общий счётчик байт, иначе сумма направлений потока."""
    total = _number(doc, "count.bytes")
    if total is not None:
        return max(0, total)
    directions = [_number(doc, "count.bytes_in"), _number(doc, "count.bytes_out")]
    if any(value is not None for value in directions):
        return max(0, sum(value for value in directions if value is not None))
    return 0


def _artifacts(doc: dict[str, Any]) -> tuple[EventArtifact, ...]:
    """Индикаторы события: хеши, файлы, процессы, учётные записи, адреса, домены."""
    candidates: list[tuple[ArtifactType, str | None]] = [
        *((ArtifactType.HASH, _text(doc, path)) for path in HASH_FIELDS),
        *((ArtifactType.FILE, _text(doc, path)) for path in FILE_FIELDS),
        *((ArtifactType.PROCESS, _text(doc, path)) for path in PROCESS_NAME_FIELDS),
        *((ArtifactType.ACCOUNT, _text(doc, path)) for path in ACCOUNT_FIELDS),
        *((ArtifactType.DOMAIN, _text(doc, path)) for path in DOMAIN_FIELDS),
        (ArtifactType.ADDRESS, _first(doc, DST_FIELDS)),
    ]
    ioc_type = (_text(doc, "alert.ioc_type") or "").lower()
    ioc_value = _text(doc, "alert.ioc_value")
    if ioc_value and ioc_type in IOC_ARTIFACT_TYPES:
        candidates.append((IOC_ARTIFACT_TYPES[ioc_type], ioc_value))

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


def map_pt_siem(doc: dict[str, Any], trust: float = 1.0) -> NormalizedEvent:
    """Событие PT SIEM по таксономии стенда → нормализованное событие TAKT."""
    observed_raw = _first(doc, TIME_FIELDS)
    if observed_raw is None:
        raise ValueError("document has no timestamp field")

    user = _first(doc, USER_FIELDS)
    # Фаза цепочки: событие стенда приходит без неё, и без перевода объявленной категории
    # инцидента оно не станет шагом хронологии. Продукт фазу не вычисляет — происхождение
    # перевода сохраняется рядом с ней.
    payload = annotate_phase(redact(doc))

    return NormalizedEvent(
        event_id=_event_id(doc),
        observed_at=_parse_ts(observed_raw),
        source=EventSource.SIEM,
        protocol=_first(doc, PROTOCOL_FIELDS) or "siem",
        operation=_operation(doc),
        payload_size=_payload_size(doc),
        payload=payload,
        operator_id=user or "",
        entities=EventEntities(
            host_id=_first(doc, HOST_FIELDS),
            user_id=user,
            process_id=_first(doc, PROCESS_FIELDS),
            parent_process_id=_first(doc, PARENT_PROCESS_FIELDS),
            src_address=_first(doc, SRC_FIELDS),
            dst_address=_first(doc, DST_FIELDS),
        ),
        artifacts=_artifacts(doc),
        ingest_trust=trust,
    )


@dataclass(frozen=True, slots=True)
class PtSiemEventSourceReader:
    """Потоковое чтение выгрузки PT SIEM в формате NDJSON.

    Битая строка не останавливает загрузку: она журналируется без содержимого документа
    (в выгрузке возможны секреты вне таксономии) и пропускается.
    """

    path: Path
    ingest_trust: float = 1.0

    def __iter__(self) -> Iterator[NormalizedEvent]:
        with self.path.open(encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    doc = json.loads(text)
                    if not isinstance(doc, dict):
                        raise ValueError("document is not an object")
                    yield map_pt_siem(doc, self.ingest_trust)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "pt siem document skipped path=%s line=%d reason=%s",
                        self.path,
                        line_number,
                        exc,
                    )


__all__ = [
    "IOC_ARTIFACT_TYPES",
    "CsvEventSourceReader",
    "PtSiemEventSourceReader",
    "map_pt_siem",
    "map_siem",
]
