from __future__ import annotations

import contextlib
import csv
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
    RawEvent,
)

# Синонимы полей, встречающиеся у разных источников: CSV-выгрузки, тела интеграций
# (netflow, ipfix, syslog, snmp) и ручной приём через `/events`. Порядок значим —
# берётся первое непустое.
_ENTITY_ALIASES: dict[str, tuple[str, ...]] = {
    "host_id": ("host_id", "hostname", "asset_id", "device_host", "src_host", "plc_id", "node"),
    "user_id": ("user_id", "username", "user", "subject_user", "account", "operator_id"),
    "process_id": ("process_guid", "process_id", "process"),
    "parent_process_id": ("parent_process_guid", "parent_process_id", "parent_process"),
    # `flow_*` — поля потоков netflow/ipfix: интеграция кладёт адреса именно под ними.
    "src_address": ("src_address", "src_ip", "flow_src_ip", "source_ip", "client_ip"),
    "dst_address": ("dst_address", "dst_ip", "flow_dst_ip", "remote_ip", "destination_ip", "server_ip"),
}

# Артефакты, распознаваемые по имени поля. Значение артефакта — то же, что в payload.
_ARTIFACT_ALIASES: tuple[tuple[ArtifactType, tuple[str, ...]], ...] = (
    (ArtifactType.HASH, ("sha256", "hash", "file_hash")),
    (ArtifactType.FILE, ("image_path", "file_path", "file")),
    (ArtifactType.DOMAIN, ("dns_query", "domain", "fqdn")),
)


def _first_value(row: dict[str, str], names: tuple[str, ...]) -> str:
    for name in names:
        value = str(row.get(name) or "").strip()
        if value:
            return value
    return ""


def _entities_from_row(row: dict[str, str]) -> EventEntities | None:
    """Сущности события из полей строки.

    Без этого события интеграций (netflow, ipfix, syslog, snmp) приходили с
    `entities = None`: они не попадали ни в корреляцию по сущностям, ни в граф кейса,
    ни в поиск по узлу — то есть источник формально принимался, но в расследовании
    не участвовал.
    """
    values = {field: _first_value(row, names) for field, names in _ENTITY_ALIASES.items()}
    if not any(values.values()):
        return None
    return EventEntities(**{field: value or None for field, value in values.items()})


def _artifacts_from_row(row: dict[str, str]) -> tuple[EventArtifact, ...]:
    found: list[EventArtifact] = []
    for artifact_type, names in _ARTIFACT_ALIASES:
        value = _first_value(row, names)
        if value:
            found.append(EventArtifact(type=artifact_type, value=value))
    # Индикатор SIEM несёт собственный тип в соседнем поле.
    indicator = _first_value(row, ("indicator",))
    if indicator:
        raw_type = _first_value(row, ("indicator_type",)) or "address"
        # Неизвестный тип индикатора не повод терять событие: он остаётся в payload.
        with contextlib.suppress(ValueError):
            found.append(EventArtifact(type=ArtifactType(raw_type.lower()), value=indicator))
    return tuple(found)


def _parse_ts(value: str) -> datetime:
    val = value.strip()
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    dt = datetime.fromisoformat(val)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def raw_row_to_normalized(
    row: dict[str, str],
    *,
    source: EventSource,
    event_id: str | None = None,
) -> NormalizedEvent:
    """Универсальный маппинг полей demo CSV (auth / plc)."""
    ts_raw = row.get("timestamp") or row.get("ts") or row.get("time")
    if not ts_raw:
        raise ValueError("row missing timestamp")
    observed = _parse_ts(ts_raw)
    protocol = row.get("protocol") or row.get("proto") or "unknown"
    operation = (
        row.get("operation")
        or row.get("event_type")
        or row.get("action")
        or row.get("op")
        or "UNKNOWN"
    )
    payload = dict(row)
    operator_id = (
        row.get("operator_id")
        or row.get("operator")
        or row.get("actor")
        or row.get("username")
        or row.get("user")
        or ""
    )
    ps = row.get("payload_size") or row.get("length") or "0"
    try:
        payload_size = int(ps)
    except ValueError:
        payload_size = len(str(row))
    return NormalizedEvent(
        event_id=event_id or str(uuid4()),
        observed_at=observed,
        source=source,
        protocol=str(protocol),
        operation=str(operation).upper(),
        payload_size=payload_size,
        payload=payload,
        operator_id=str(operator_id).strip(),
        entities=_entities_from_row(row),
        artifacts=_artifacts_from_row(row),
    )


def load_normalized_from_csv(
    path: str | Path, *, source: EventSource
) -> list[NormalizedEvent]:
    p = Path(path)
    out: list[NormalizedEvent] = []
    with p.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out.append(raw_row_to_normalized(row, source=source))
    return out


def iter_raw_events(path: str | Path, *, source: EventSource):
    p = Path(path)
    with p.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_raw = row.get("timestamp") or row.get("ts") or row.get("time")
            if not ts_raw:
                continue
            yield RawEvent(
                source=source,
                received_at=_parse_ts(ts_raw),
                payload=dict(row),
            )


def iter_normalized_from_csv(path: str | Path, *, source: EventSource):
    """Потоковый вариант `load_normalized_from_csv`: одна строка CSV в памяти за раз.

    Для больших файлов (100k+ строк) позволяет прогонять бэктест без
    материализации всего набора событий в список.
    """
    p = Path(path)
    with p.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield raw_row_to_normalized(row, source=source)
