from __future__ import annotations

import csv
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.importers.csv_events import _parse_ts, raw_row_to_normalized
from takt.infrastructure.importers.source_phase import annotate_phase

logger = logging.getLogger(__name__)


def _value(row: dict[str, str], key: str) -> str | None:
    value = (row.get(key) or "").strip()
    return value or None


def _size(row: dict[str, str], key: str = "payload_size") -> int:
    raw = _value(row, key)
    if raw is None:
        return len(str(row))
    value = int(raw)
    if value < 0:
        raise ValueError(f"{key} must not be negative")
    return value


def _artifacts(*items: tuple[ArtifactType, str | None]) -> tuple[EventArtifact, ...]:
    return tuple(EventArtifact(kind, value) for kind, value in items if value)


RowMapper = Callable[[dict[str, str], float], NormalizedEvent]


@dataclass(frozen=True, slots=True)
class CsvEventSourceReader:
    path: Path
    mapper: RowMapper
    ingest_trust: float = 1.0

    def __iter__(self) -> Iterator[NormalizedEvent]:
        with self.path.open(encoding="utf-8-sig", newline="") as stream:
            for line_number, row in enumerate(csv.DictReader(stream), start=2):
                try:
                    yield self.mapper(dict(row), self.ingest_trust)
                except (KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "source row skipped path=%s line=%d reason=%s",
                        self.path,
                        line_number,
                        exc,
                    )


def _payload(row: dict[str, str]) -> dict[str, str]:
    """Полезная нагрузка события: строка источника плюс фаза, если её удалось перевести.

    Выгрузка AIT-ADS несёт фазу колонкой `attack_phase` — она остаётся как есть. Выгрузка
    стенда PT фазы не несёт, и перевод объявленной категории — единственный способ построить
    по ней цепочку.
    """
    return annotate_phase(dict(row))


def map_edr(row: dict[str, str], trust: float) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row["event_id"], observed_at=_parse_ts(row["timestamp"]), source=EventSource.EDR,
        protocol="endpoint", operation=row["event_type"].upper(), payload_size=_size(row), payload=_payload(row),
        operator_id=_value(row, "username") or "",
        entities=EventEntities(host_id=_value(row, "hostname"), user_id=_value(row, "username"),
                               process_id=_value(row, "process_guid"), parent_process_id=_value(row, "parent_process_guid"),
                               dst_address=_value(row, "remote_ip")),
        artifacts=_artifacts((ArtifactType.HASH, _value(row, "sha256")),
                             (ArtifactType.FILE, _value(row, "image_path"))), ingest_trust=trust,
    )


def map_siem(row: dict[str, str], trust: float) -> NormalizedEvent:
    kind_raw = (_value(row, "indicator_type") or "address").lower()
    kind = ArtifactType(kind_raw)
    return NormalizedEvent(
        event_id=row["record_id"], observed_at=_parse_ts(row["event_time"]), source=EventSource.SIEM,
        protocol="siem", operation=row["rule_name"].upper(), payload_size=_size(row), payload=_payload(row),
        operator_id=_value(row, "subject_user") or "",
        entities=EventEntities(host_id=_value(row, "device_host"), user_id=_value(row, "subject_user"),
                               src_address=_value(row, "src_ip"), dst_address=_value(row, "dst_ip")),
        artifacts=_artifacts((kind, _value(row, "indicator"))), ingest_trust=trust,
    )


def map_ndr(row: dict[str, str], trust: float) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row["flow_id"], observed_at=_parse_ts(row["start_time"]), source=EventSource.NDR,
        protocol=row["app_protocol"], operation=row["verdict"].upper(), payload_size=_size(row, "bytes"), payload=_payload(row),
        entities=EventEntities(host_id=_value(row, "src_host"), src_address=_value(row, "src_ip"),
                               dst_address=_value(row, "dst_ip")),
        artifacts=_artifacts((ArtifactType.DOMAIN, _value(row, "dns_query"))), ingest_trust=trust,
    )


def map_netflow(row: dict[str, str], trust: float) -> NormalizedEvent:
    """Сетевой поток как класс источника Netflow.

    Отличается от `map_ndr` не данными, а трактовкой: NDR отдаёт вердикт средства
    обнаружения, Netflow — сам поток без вердикта. Строка приводится к именам полей
    интеграции (`flow_src_ip`, `flow_dst_ip`, `flow_bytes`) и проходит тот же
    нормализатор, что и приём через `POST /integrations/ingest/netflow`, — иначе
    загрузка датасета и боевой приём разошлись бы в разборе полей.
    """
    flow_row = {
        "timestamp": row.get("start_time", ""),
        "protocol": row.get("app_protocol", "") or "NETFLOW",
        "operation": (row.get("verdict") or "NETFLOW_FLOW").upper(),
        "asset_id": row.get("src_host", ""),
        "flow_src_ip": row.get("src_ip", ""),
        "flow_dst_ip": row.get("dst_ip", ""),
        "flow_bytes": row.get("bytes", ""),
        "payload_size": row.get("bytes", "0"),
        "dns_query": row.get("dns_query", ""),
        "collector": "netflow-collector",
        # Разметка фазы цепочки приходит из датасета и должна дожить до окна симуляции:
        # без переноса поток Netflow терял фазу, и цепочка в интерфейсе была неполной.
        "attack_phase": row.get("attack_phase", ""),
        "mitre_technique": row.get("mitre_technique", ""),
        "incident_id": row.get("incident_id", ""),
    }
    event = raw_row_to_normalized(
        flow_row,
        source=EventSource.NETWORK,
        event_id=row.get("flow_id") or None,
    )
    return replace(event, ingest_trust=trust)


def map_ot(row: dict[str, str], trust: float) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row["event_id"], observed_at=_parse_ts(row["timestamp"]), source=EventSource.OT,
        protocol=row["protocol"], operation=row["operation"].upper(), payload_size=_size(row), payload=_payload(row),
        entities=EventEntities(host_id=_value(row, "asset_id"), src_address=_value(row, "src_address"),
                               dst_address=_value(row, "dst_address")),
        artifacts=_artifacts((ArtifactType.PROCESS, _value(row, "tag"))), ingest_trust=trust,
    )
