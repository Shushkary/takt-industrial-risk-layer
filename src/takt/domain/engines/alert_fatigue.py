from __future__ import annotations

from datetime import datetime, timezone

from takt.domain.entities.event import NormalizedEvent


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
    dt = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
    ts = dt.astimezone(timezone.utc).timestamp()
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
