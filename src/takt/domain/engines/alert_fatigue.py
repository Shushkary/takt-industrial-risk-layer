from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from takt.domain.entities.event import ArtifactType, EventSource, NormalizedEvent
from takt.domain.ports.hasher import HasherPort

_ENTITY_FIELDS = frozenset(
    {"host_id", "user_id", "process_id", "parent_process_id", "src_address", "dst_address"}
)


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    fields: tuple[str, ...]
    bucket_sec: int | None = None
    priority: int = 100
    name: str = ""
    # Окно правила: **sliding** — событие даёт ключи текущего и предыдущего окна, цепочка
    # продолжается, пока активность не прервалась дольше длины окна; **calendar** — только
    # текущее окно, граница жёсткая. Скользящее окно уместно для отличительного ключа и
    # опасно для ключа, который событие делит с фоном: обход по такому ключу вырождается
    # и стягивает весь поток в одно дело (то же наблюдение — в `incident_pivot`).
    window: str = "calendar"
    # Классы источников, к которым правило применяется. Пустой кортеж — ко всем.
    #
    # Область применения задаётся явно, а не выводится: правило `host_id в окне` осмысленно
    # для потока SOC и меняет разбор промышленного контура, где ключ слияния — актив плюс
    # операция. Новый класс источника попадает под корреляцию только решением в конфигурации.
    sources: tuple[str, ...] = ()


def correlation_rules_from_config(raw: object) -> tuple[CorrelationRule, ...]:
    """Parse and validate correlation rules, ordered by priority then declaration."""
    if not isinstance(raw, Mapping):
        return ()
    rows = raw.get("keys")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return ()
    parsed: list[tuple[int, CorrelationRule]] = []
    for index, item in enumerate(rows):
        if not isinstance(item, Mapping):
            continue
        fields_raw = item.get("fields")
        if not isinstance(fields_raw, Sequence) or isinstance(fields_raw, (str, bytes)):
            continue
        fields = tuple(str(field).strip() for field in fields_raw if str(field).strip())
        if not fields or any(not _valid_correlation_field(field) for field in fields):
            continue
        bucket_raw = item.get("bucket_sec")
        try:
            bucket = int(bucket_raw) if bucket_raw is not None else None
            priority = int(item.get("priority", 100))
        except (TypeError, ValueError):
            continue
        if bucket is not None and bucket < 1:
            continue
        sources = _correlation_sources(item.get("sources"))
        if sources is None:
            continue
        window = str(item.get("window") or "calendar").strip().lower()
        if window not in {"calendar", "sliding"}:
            continue
        parsed.append(
            (
                index,
                CorrelationRule(
                    fields=fields,
                    bucket_sec=bucket,
                    priority=priority,
                    name=str(item.get("name") or f"rule_{index + 1}"),
                    window=window,
                    sources=sources,
                ),
            )
        )
    return tuple(rule for _, rule in sorted(parsed, key=lambda pair: (pair[1].priority, pair[0])))


def correlation_fingerprints(
    event: NormalizedEvent,
    rules: Sequence[CorrelationRule],
    hasher: HasherPort,
) -> list[str]:
    """Кандидатные ключи события по правилам, все поля которых у него заполнены.

    Правило со скользящим окном (`window: sliding`) даёт **два** ключа: текущее окно и
    предыдущее. Без перекрытия граница окна календарная, и два события одного узла в двух
    минутах друг от друга попадали в разные дела только потому, что одно легло после ровной
    отметки времени. С перекрытием цепочка продолжается, пока активность не прерывается
    дольше, чем на длину окна.

    Порядок ключей детерминирован: сначала текущее окно, затем предыдущее.
    """
    fingerprints: list[str] = []
    for rule in rules:
        if rule.sources and event.source.value not in rule.sources:
            continue
        values = [_correlation_value(event, field) for field in rule.fields]
        if any(value is None for value in values):
            continue
        material: dict[str, Any] = {field: value for field, value in zip(rule.fields, values, strict=True)}
        if rule.bucket_sec is None:
            fingerprints.append(_correlation_key(rule, material, hasher))
            continue
        bucket = int(event.observed_at.timestamp() // rule.bucket_sec)
        buckets = (bucket, bucket - 1) if rule.window == "sliding" else (bucket,)
        for index in buckets:
            fingerprints.append(_correlation_key(rule, {**material, "bucket": index}, hasher))
    return fingerprints


def _correlation_key(rule: CorrelationRule, material: dict[str, Any], hasher: HasherPort) -> str:
    digest = hasher.hash_bytes(
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(", ", ": ")).encode("utf-8")
    )[:24]
    return f"corr:{rule.name}:{digest}"


def _correlation_sources(raw: object) -> tuple[str, ...] | None:
    """Разбирает область применения правила. `None` — правило непригодно и отбрасывается.

    Неизвестное имя класса источника — это опечатка в конфигурации, а не пустая область:
    применить такое правило ко всем источникам значило бы молча расширить корреляцию на
    промышленный контур.
    """
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return None
    known = {source.value for source in EventSource}
    values = tuple(str(item).strip().lower() for item in raw if str(item).strip())
    if not values or any(value not in known for value in values):
        return None
    return tuple(dict.fromkeys(values))


def _valid_correlation_field(field: str) -> bool:
    # Допустимые типы артефактов берутся из каталога ArtifactType, а не из
    # копии списка: иначе новый тип (напр. `spn`, `repo`) молча оказался бы
    # недоступен для правил корреляции.
    return field in _ENTITY_FIELDS or (
        field.startswith("artifact:")
        and field.split(":", 1)[1] in {kind.value for kind in ArtifactType}
    )


def _correlation_value(event: NormalizedEvent, field: str) -> str | tuple[str, ...] | None:
    if field.startswith("artifact:"):
        kind = field.split(":", 1)[1]
        values = tuple(sorted({item.value.strip().lower() for item in event.artifacts if item.type.value == kind and item.value.strip()}))
        return values or None
    if event.entities is None:
        return None
    raw = getattr(event.entities, field, None)
    value = str(raw or "").strip().lower()
    return value or None


def _asset_key(ev: NormalizedEvent) -> str:
    return str(ev.payload.get("asset_id") or ev.payload.get("plc_id") or "_")


def burst_fingerprint_legacy(ev: NormalizedEvent) -> str:
    """Ключ слияния до v0.7: source|asset|operation (для обратной совместимости backtest)."""
    aid = _asset_key(ev)
    return f"{ev.source.value}|{aid}|{ev.operation}"


def burst_fingerprint_bucketed(ev: NormalizedEvent, bucket_sec: int) -> str:
    """
    Ключ слияния без расщепления по source: asset|operation|time_bucket.
    Одинаковый актив и операция в одном календарном бакете (UTC) попадают в один открытый кейс.
    """
    aid = _asset_key(ev)
    ts = ev.observed_at.timestamp()
    bucket = int(ts // bucket_sec)
    return f"{aid}|{ev.operation}|{bucket}"


def burst_fingerprint(ev: NormalizedEvent) -> str:
    """Обратная совместимость (тесты, legacy): `source|asset|operation`."""
    return burst_fingerprint_legacy(ev)


def case_bucket_burst_fingerprint(
    *,
    primary_asset_id: str,
    trigger_operation: str,
    created_at: datetime,
    bucket_sec: int,
) -> str:
    """Ключ **bucketed** по полям уже сохранённого кейса (миграция / нормализация БД)."""
    aid = str(primary_asset_id or "_").strip() or "_"
    op = str(trigger_operation or "_").strip() or "_"
    bs = bucket_sec if bucket_sec >= 1 else 300
    dt = created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)
    ts = dt.astimezone(UTC).timestamp()
    bucket = int(ts // bs)
    return f"{aid}|{op}|{bucket}"


def compute_burst_fingerprint(
    ev: NormalizedEvent,
    *,
    mode: str,
    bucket_sec: int,
) -> str:
    """
    **mode**: **legacy** — старый fingerprint; иначе **bucketed** (по умолчанию).
    **bucket_sec**: размер окна в секундах (дефолт из YAML, обычно 300).
    """
    m = (mode or "bucketed").strip().lower()
    if m == "legacy":
        return burst_fingerprint_legacy(ev)
    if bucket_sec < 1:
        bucket_sec = 300
    return burst_fingerprint_bucketed(ev, bucket_sec)
