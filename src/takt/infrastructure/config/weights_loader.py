from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _AlertFatigueCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = "bucketed"
    bucket_sec: int = Field(default=300, ge=1, le=86_400)


class _IngestTrustCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    by_source: dict[str, float] = Field(default_factory=dict)


class _StorageCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backend: str = "memory"
    sqlite_path: str = "data/takt_cases.db"


class _SiemWebhookCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_url_prefixes: list[str] = Field(default_factory=list)
    retries: int = Field(default=3, ge=1, le=10)
    backoff_sec: float = Field(default=0.35, ge=0.0, le=60.0)


class _ExportCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pdf_unicode_font: str = ""


class _RiskWeightsSchema(BaseModel):
    model_config = ConfigDict(extra="allow")
    version: str = ""
    """Метка версии конфигурации. Попадает в отчёт разметки (`docs/customer_value_map.md`, G-2):
    предложение изменить правило осмысленно только вместе с версией, против которой оно
    посчитано. На расчёт риска не влияет."""
    rhythm: float = Field(default=0.0, ge=0.0, le=1.0)
    graph: float = Field(default=0.0, ge=0.0, le=1.0)
    context: float = Field(default=0.0, ge=0.0, le=1.0)
    user: float = Field(default=0.0, ge=0.0, le=1.0)
    data_quality: float = Field(default=0.0, ge=0.0, le=1.0)
    mandelbrot_entropy_cap: float = 2.5
    dq_degraded_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    feigenbaum_target: float = 4.669201609
    eps_soft_cap: float = Field(default=100_000.0, gt=0.0)
    alert_fatigue: _AlertFatigueCfg = Field(default_factory=_AlertFatigueCfg)
    ingest_trust: _IngestTrustCfg = Field(default_factory=_IngestTrustCfg)
    storage: _StorageCfg = Field(default_factory=_StorageCfg)
    siem_webhook: _SiemWebhookCfg = Field(default_factory=_SiemWebhookCfg)
    export: _ExportCfg = Field(default_factory=_ExportCfg)


def load_risk_weights(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        msg = f"risk weights config not found: {p.resolve()}"
        raise FileNotFoundError(msg)
    with p.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("risk config must be a mapping")
    try:
        _RiskWeightsSchema.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"risk config validation error: {e.errors()}") from e
    return data
