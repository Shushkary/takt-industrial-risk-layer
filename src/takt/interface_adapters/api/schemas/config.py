"""Схемы маршрутов конфигурации: веса оценки риска и пороги классов."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RiskWeightsSet(BaseModel):
    """Веса факторов Risk = F(R, G, C, U, DQ). Сумма проверяется при записи, а не здесь."""

    model_config = ConfigDict(extra="forbid")

    rhythm: float = Field(ge=0.0, le=1.0)
    graph: float = Field(ge=0.0, le=1.0)
    context: float = Field(ge=0.0, le=1.0)
    user: float = Field(ge=0.0, le=1.0)
    data_quality: float = Field(ge=0.0, le=1.0)


class RiskThresholdSet(BaseModel):
    """Пороги классов риска — доли шкалы 0..1. Порядок проверяется при записи."""

    model_config = ConfigDict(extra="forbid")

    critical: float = Field(ge=0.0, le=1.0)
    high: float = Field(ge=0.0, le=1.0)
    medium: float = Field(ge=0.0, le=1.0)


class RiskWeightsResponse(BaseModel):
    version: str
    weights: RiskWeightsSet
    thresholds: RiskThresholdSet
    config_path: str
    """Путь к файлу конфигурации относительно корня проекта: правка из окна и правка на
    сервере идут в один и тот же файл, и окно обязано называть, в какой именно."""
    editable: bool
    """Доступен ли файл на запись. Роль проверяется отдельно, до обработчика."""


class RiskWeightsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    weights: RiskWeightsSet
    thresholds: RiskThresholdSet
    reason: str = Field(min_length=1, max_length=2000)
    """Причина обязательна: веса меняют оценку всех последующих дел, и по журналу должно быть
    видно, кто и зачем их менял."""
