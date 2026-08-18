"""Коннектор к сетевому сенсору PT NAD (единое хранилище заказчика).

Маппинг построен по схеме индекса, предоставленной заказчиком
(Elasticsearch mapping, 1786 полей). Документы читаются построчно в формате
NDJSON — по одному JSON-объекту на строку, как в выгрузке `_search`/`scroll`,
поэтому объём файла не влияет на потребление памяти.

Безопасность: поле `credentials.password` содержит пароли, восстановленные из
трафика. Оно **не** попадает ни в `payload`, ни в логи — значение заменяется
на маркер. См. `REDACTED_FIELDS`.
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

logger = logging.getLogger(__name__)

# Поля, значения которых нельзя сохранять и журналировать.
REDACTED_FIELDS: tuple[tuple[str, ...], ...] = (("credentials", "password"),)
REDACTED_MARKER = "[redacted]"

# Приоритет полей: первое непустое значение выигрывает. Каскад покрывает две
# формы записи: полную схему индекса заказчика (`src.host_id`, `s_msg`,
# `query.rrname`) и упрощённую выгрузку потоков (`src.host`, `verdict`,
# `dns.query`), которая встречается в демонстрационных наборах.
TIME_FIELDS = ("ts", "ts_start", "_ltime", "tx_time")
PROTOCOL_FIELDS = ("app_proto", "proto", "protocol")
OPERATION_FIELDS = ("s_msg", "alert.description", "verdict", "type", "app_name")
HOST_FIELDS = (
    "src.host_id", "host.host_id", "attacker.host_id",
    "src.host", "host.host", "src.name", "host.name",
)
USER_FIELDS = ("user", "credentials.login", "subject")
SRC_FIELDS = ("src.ip", "attacker.ip")
DST_FIELDS = ("dst.ip", "victim.ip")
DOMAIN_FIELDS = ("query.rrname", "dns.query", "server_name", "dst.dns")


def _get(doc: dict[str, Any], path: str) -> Any:
    """Значение по точечному пути (`src.host_id`); None, если ветки нет."""
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


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


def redact(doc: dict[str, Any]) -> dict[str, Any]:
    """Копия документа без секретов (пароли из трафика)."""
    safe = json.loads(json.dumps(doc, ensure_ascii=False, default=str))
    for path in REDACTED_FIELDS:
        node = safe
        for part in path[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
            if not isinstance(node, dict):
                break
        if isinstance(node, dict) and path[-1] in node:
            node[path[-1]] = REDACTED_MARKER
    return safe


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


def _artifacts(doc: dict[str, Any]) -> tuple[EventArtifact, ...]:
    """Индикаторы: хеши, отпечатки TLS, файлы, домены, адрес назначения, учётка."""
    candidates: list[tuple[ArtifactType, str | None]] = [
        (ArtifactType.HASH, _text(doc, "sha256")),
        (ArtifactType.HASH, _text(doc, "md5")),
        (ArtifactType.HASH, _text(doc, "ja3_md5")),
        (ArtifactType.HASH, _text(doc, "ja4")),
        (ArtifactType.FILE, _text(doc, "filepath") or _text(doc, "filename")),
        *((ArtifactType.DOMAIN, _text(doc, path)) for path in DOMAIN_FIELDS),
        (ArtifactType.ADDRESS, _first(doc, DST_FIELDS)),
        (ArtifactType.ACCOUNT, _text(doc, "credentials.login")),
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


def map_nad(doc: dict[str, Any], trust: float = 1.0) -> NormalizedEvent:
    """Документ PT NAD → нормализованное событие TAKT."""
    observed_raw = _first(doc, TIME_FIELDS)
    if observed_raw is None:
        raise ValueError("document has no timestamp field")

    operation = _first(doc, OPERATION_FIELDS) or "NETWORK_FLOW"
    payload = redact(doc)
    # Техника MITRE ATT&CK выносится в payload плоским полем: по ней
    # корреляция и UI строят связи, не разбирая исходный документ.
    technique = _text(doc, "att_ck")
    if technique:
        payload["mitre_technique"] = technique

    return NormalizedEvent(
        event_id=_event_id(doc),
        observed_at=_parse_ts(observed_raw),
        source=EventSource.NDR,
        protocol=_first(doc, PROTOCOL_FIELDS) or "network",
        operation=operation.upper(),
        payload_size=_payload_size(doc),
        payload=payload,
        operator_id=_first(doc, USER_FIELDS) or "",
        entities=EventEntities(
            host_id=_first(doc, HOST_FIELDS),
            user_id=_first(doc, USER_FIELDS),
            src_address=_first(doc, SRC_FIELDS),
            dst_address=_first(doc, DST_FIELDS),
        ),
        artifacts=_artifacts(doc),
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

    def __iter__(self) -> Iterator[NormalizedEvent]:
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
                    yield map_nad(doc, self.ingest_trust)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "nad document skipped path=%s line=%d reason=%s",
                        self.path,
                        line_number,
                        exc,
                    )


__all__ = ["NadEventSourceReader", "map_nad", "redact", "REDACTED_FIELDS"]
