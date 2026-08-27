"""Перевод классификаций средств обнаружения в фазы цепочки атаки.

Фазу ТАКТ не вычисляет: она приходит от разметки датасета или от вышестоящего средства
обнаружения (см. `takt.domain.entities.kill_chain`). Датасет AIT-ADS отдаёт фазу колонкой,
а стенд PT — нет: в схемах PT NAD такой колонки не существует, а таксономия PT SIEM даёт
категорию инцидента (`incident.category`, 34 значения). Категория — это объявленная
классификация вышестоящего средства, поэтому её перевод в фазу допустим и не является
догадкой продукта.

Таблица перевода лежит в конфигурации (`config/kill_chain/source_phases.yaml`), а не в коде:
её показывают интегратору при сертификации, и меняется она без правки логики. Каждая строка
таблицы несёт основание, а неоднозначные категории перечислены отдельно — с причиной, по
которой фаза для них не назначается.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from takt.domain.entities.kill_chain import KillChainPhase

# Поля события, в которых ищется категория. Порядок — от точного к общему: `incident.category`
# заполняется при заведении инцидента, `category.high` и `category.generic` приходят с самим
# событием и грубее по смыслу.
CATEGORY_FIELDS: tuple[str, ...] = ("incident.category", "category.high", "category.generic")


class _Mapping(BaseModel):
    phase: str
    reason: str
    pt_siem_categories: list[str] = Field(default_factory=list)

    @field_validator("phase")
    @classmethod
    def _known_phase(cls, value: str) -> str:
        if value not in {phase.value for phase in KillChainPhase}:
            raise ValueError(f"unknown kill chain phase: {value}")
        return value

    @field_validator("reason")
    @classmethod
    def _reason_is_stated(cls, value: str) -> str:
        # Основание обязательно: перевод чужой классификации показывают при сертификации, и
        # строка без причины не отличима от догадки.
        if len(value.strip()) < 20:
            raise ValueError("mapping needs a stated reason")
        return value


class _NotMapped(BaseModel):
    category: str
    reason: str


class _Document(BaseModel):
    version: int
    mappings: list[_Mapping]
    not_mapped: list[_NotMapped] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SourcePhaseMap:
    """Таблица перевода: категория источника → фаза цепочки и основание перевода."""

    by_category: dict[str, tuple[KillChainPhase, str]]
    refused: dict[str, str]

    def phase_for_category(self, category: str) -> tuple[KillChainPhase, str] | None:
        """Фаза по категории. Неизвестная и намеренно не переведённая дают None."""
        return self.by_category.get(category.strip())

    def phase_for_payload(self, payload: dict) -> tuple[KillChainPhase, str, str] | None:
        """Фаза по событию: фаза, категория, из которой она выведена, и основание.

        Поиск идёт по каскаду полей категории, в том числе по вложенной записи
        (`{"incident": {"category": ...}}`) и по плоскому ключу с точкой — выгрузки стенда
        встречаются в обеих формах.
        """
        for field in CATEGORY_FIELDS:
            value = _lookup(payload, field)
            if not value:
                continue
            found = self.phase_for_category(value)
            if found is not None:
                phase, reason = found
                return phase, f"{field}={value}", reason
        return None


def _lookup(payload: dict, path: str) -> str | None:
    if path in payload:
        raw = payload[path]
    else:
        node: object = payload
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
            if node is None:
                return None
        raw = node
    if isinstance(raw, (dict, list)) or raw is None:
        return None
    text = str(raw).strip()
    return text or None


def load_source_phase_map(path: str | Path) -> SourcePhaseMap:
    """Прочитать таблицу перевода из YAML."""
    document = _Document.model_validate(
        yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    )
    by_category: dict[str, tuple[KillChainPhase, str]] = {}
    for item in document.mappings:
        phase = KillChainPhase(item.phase)
        for category in item.pt_siem_categories:
            if category in by_category:
                raise ValueError(f"category mapped twice: {category}")
            by_category[category] = (phase, item.reason)
    refused = {item.category: item.reason for item in document.not_mapped}
    overlap = sorted(set(by_category) & set(refused))
    if overlap:
        # Категория не может одновременно переводиться и быть объявленной непереводимой:
        # такая таблица читается двумя способами, и при сертификации это вопрос без ответа.
        raise ValueError(f"category both mapped and refused: {overlap}")
    return SourcePhaseMap(by_category=by_category, refused=refused)


def default_source_phase_map_path() -> Path:
    """Путь к таблице в репозитории: `config/kill_chain/source_phases.yaml`."""
    return Path(__file__).resolve().parents[4] / "config" / "kill_chain" / "source_phases.yaml"


@lru_cache(maxsize=4)
def load_source_phase_map_cached(path: str) -> SourcePhaseMap:
    """Таблица читается один раз на путь: приём событий идёт потоком."""
    return load_source_phase_map(path)


__all__ = [
    "CATEGORY_FIELDS",
    "SourcePhaseMap",
    "default_source_phase_map_path",
    "load_source_phase_map",
    "load_source_phase_map_cached",
]
