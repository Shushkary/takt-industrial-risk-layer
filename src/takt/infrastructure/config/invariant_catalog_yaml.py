from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from takt.domain.invariants.catalog import INVARIANT_RECORDS, InvariantId
from takt.domain.invariants.evaluator import InvariantRuleOverrides
from takt.domain.invariants.rule_predicates import VALID_BUILTIN_PREDICATE_KEYS
from takt.domain.invariants.rule_spec import InvariantRuleSpec, default_predicate_builtin_ref

_DEFAULT_CONTEXT_EVENTS = 5
"""Если в YAML не указано — берётся это значение (нижняя граница для окон серий)."""

_RHYTHM_SERIES_CONTEXT = 24
"""Достаточная глубина для джиттера / опроса / дрейфа в одном буфере оценки."""

_VERDICT_MAPPED_IDS: frozenset[str] = frozenset(
    {
        InvariantId.C2_EXTERNAL_DNS.value,
        InvariantId.LATERAL_MOVEMENT.value,
        InvariantId.RECONNAISSANCE.value,
        InvariantId.OUT_OF_SHIFT_ACCESS.value,
    }
)
"""Инварианты, для которых допустимо сопоставление вердиктов вышестоящей автоматики.

ТАКТ разбирает инцидент после средств обнаружения: `verdict` от NDR и `rule_name` от SIEM
попадают в `operation` нормализованного события. Список `source_operations` объявляет,
какие вердикты означают этот инвариант у конкретного заказчика. Ограничение перечнем — чтобы
сопоставление не расползлось на промышленные правила, где операция значит другое.
"""

_ALLOWED_PARAM_KEYS: frozenset[str] = frozenset({"auth_fail_threshold", "source_operations"})

_PER_RULE_CONTEXT_CAP: dict[str, int] = {
    InvariantId.POLLING_JITTER.value: _RHYTHM_SERIES_CONTEXT,
    InvariantId.PAYLOAD_LENGTH_DRIFT.value: _RHYTHM_SERIES_CONTEXT,
    InvariantId.REQUEST_REPLY_DISSONANCE.value: _RHYTHM_SERIES_CONTEXT,
    InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value: _RHYTHM_SERIES_CONTEXT,
    InvariantId.BRUTE_FORCE.value: 20,
    InvariantId.BLIND_COMMAND.value: 3,
}


class InvariantYamlRecord(BaseModel):
    """Одна запись каталога инвариантов (файл `config/invariants/<id>.yaml`)."""

    id: str
    block_key: str
    block_label_ru: str
    title_ru: str
    context_window_events: int = Field(default=_DEFAULT_CONTEXT_EVENTS, ge=1, le=10_000)
    params: dict[str, Any] = Field(default_factory=dict)
    experimental: bool = False
    predicate_ref: str
    inputs: list[str] = Field(default_factory=list)
    severity_curve: dict[str, Any] | None = None

    @field_validator("id")
    @classmethod
    def _known_id(cls, v: str) -> str:
        try:
            InvariantId(v)
        except ValueError as e:
            msg = f"unknown invariant id in yaml: {v!r}"
            raise ValueError(msg) from e
        return v

    @model_validator(mode="after")
    def _params_schema(self) -> InvariantYamlRecord:
        if not self.params:
            return self
        extra = set(self.params) - _ALLOWED_PARAM_KEYS
        if extra:
            msg = f"unknown params for {self.id}: {sorted(extra)}"
            raise ValueError(msg)
        if "auth_fail_threshold" in self.params:
            if self.id != InvariantId.BRUTE_FORCE.value:
                msg = f"auth_fail_threshold is only supported for brute_force (got {self.id})"
                raise ValueError(msg)
            t = self.params.get("auth_fail_threshold")
            if t is not None and (not isinstance(t, int) or int(t) < 1):
                msg = "auth_fail_threshold must be int >= 1"
                raise ValueError(msg)
        if "source_operations" in self.params:
            if self.id not in _VERDICT_MAPPED_IDS:
                msg = (
                    "source_operations are only supported for "
                    f"{sorted(_VERDICT_MAPPED_IDS)} (got {self.id})"
                )
                raise ValueError(msg)
            self._validate_source_operations()
        return self

    def _validate_source_operations(self) -> None:
        raw = self.params.get("source_operations")
        if not isinstance(raw, list) or not raw:
            msg = "source_operations must be a non-empty list of operation names"
            raise ValueError(msg)
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                msg = f"source_operations must contain non-empty strings, got {item!r}"
                raise ValueError(msg)
            normalized = item.strip().upper()
            if normalized in seen:
                msg = f"duplicate source operation {normalized!r} in {self.id}"
                raise ValueError(msg)
            seen.add(normalized)

    @model_validator(mode="after")
    def _predicate_ref_schema(self) -> InvariantYamlRecord:
        pref = self.predicate_ref.strip()
        if not pref.startswith("builtin:"):
            msg = "predicate_ref must start with 'builtin:'"
            raise ValueError(msg)
        name = pref[8:].strip()
        if name not in VALID_BUILTIN_PREDICATE_KEYS:
            msg = f"unknown builtin predicate {name!r}"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class InvariantCatalogFromYaml:
    """Загруженный набор записей; `max_context_window_events` расширяет буфер контекста оценки."""

    records: tuple[InvariantYamlRecord, ...]

    def max_context_window_events(self) -> int:
        return max(r.context_window_events for r in self.records)


def _merge_record_defaults(data: dict[str, Any], dom_id: str) -> dict[str, Any]:
    merged = dict(data)
    cap = _PER_RULE_CONTEXT_CAP.get(dom_id)
    if cap is not None and "context_window_events" not in merged:
        merged["context_window_events"] = cap
    if not str(merged.get("predicate_ref", "")).strip():
        merged["predicate_ref"] = default_predicate_builtin_ref(dom_id)
    merged.setdefault("inputs", [])
    merged.setdefault("severity_curve", None)
    return merged


def load_invariant_catalog_from_dir(path: str | Path) -> InvariantCatalogFromYaml:
    """Читает все `*.yaml` в каталоге; набор `id` должен в точности совпадать с `InvariantId`."""
    root = Path(path)
    if not root.is_dir():
        msg = f"invariant catalog directory not found: {root.resolve()}"
        raise FileNotFoundError(msg)
    files = sorted(root.glob("*.yaml"))
    if not files:
        msg = f"no *.yaml invariant specs under {root.resolve()}"
        raise FileNotFoundError(msg)

    dom_ids = {m.value for m in InvariantId}
    seen: set[str] = set()
    records: list[InvariantYamlRecord] = []

    for fp in files:
        with fp.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            msg = f"invariant yaml must be a mapping: {fp}"
            raise ValueError(msg)
        dom_id = str(raw.get("id", "")).strip()
        merged = _merge_record_defaults(raw, dom_id)
        rec = InvariantYamlRecord.model_validate(merged)
        if rec.id in seen:
            msg = f"duplicate invariant id {rec.id!r} ({fp})"
            raise ValueError(msg)
        seen.add(rec.id)
        records.append(rec)

    missing = dom_ids - seen
    extra = seen - dom_ids
    if missing or extra:
        msg = f"invariant yaml set must match InvariantId exactly; missing={sorted(missing)!r} extra={sorted(extra)!r}"
        raise ValueError(msg)

    records.sort(key=lambda r: r.id)
    return InvariantCatalogFromYaml(records=tuple(records))


def catalog_rule_overrides(cat: InvariantCatalogFromYaml) -> InvariantRuleOverrides:
    """Снимок доменных переопределений из загруженного YAML-каталога."""
    for r in cat.records:
        if r.id != InvariantId.BRUTE_FORCE.value:
            continue
        raw = r.params.get("auth_fail_threshold")
        if isinstance(raw, int):
            return InvariantRuleOverrides(brute_force_auth_fail_threshold=raw)
    return InvariantRuleOverrides()


def catalog_experimental_invariant_ids(cat: InvariantCatalogFromYaml) -> frozenset[str]:
    """Идентификаторы правил, помеченных `experimental: true` (по умолчанию не влияют на risk_score)."""
    return frozenset(r.id for r in cat.records if r.experimental)


def catalog_rule_specs(cat: InvariantCatalogFromYaml) -> tuple[InvariantRuleSpec, ...]:
    """Доменные спецификации для исполнения в `evaluate_declared_rules`."""
    return tuple(
        InvariantRuleSpec(
            id=r.id,
            block_key=r.block_key,
            context_window_events=int(r.context_window_events),
            experimental=bool(r.experimental),
            params=dict(r.params),
            predicate_ref=str(r.predicate_ref).strip(),
            inputs=tuple(r.inputs),
            severity_curve=dict(r.severity_curve) if r.severity_curve else None,
        )
        for r in sorted(cat.records, key=lambda x: x.id)
    )


def expected_yaml_blobs_from_domain_catalog() -> dict[str, str]:
    """Содержимое файлов по умолчанию (синхронно с `INVARIANT_RECORDS`). Для генерации и тестов."""
    out: dict[str, str] = {}
    for r in INVARIANT_RECORDS:
        cap = _PER_RULE_CONTEXT_CAP.get(r.id, _DEFAULT_CONTEXT_EVENTS)
        bl = json.dumps(r.block_label_ru, ensure_ascii=False)
        tt = json.dumps(r.title_ru, ensure_ascii=False)
        pr = default_predicate_builtin_ref(r.id)
        body = (
            f"id: {r.id}\n"
            f"block_key: {r.block_key}\n"
            f"block_label_ru: {bl}\n"
            f"title_ru: {tt}\n"
            f"context_window_events: {cap}\n"
            f"predicate_ref: {pr}\n"
            f"inputs: []\n"
            f"severity_curve: null\n"
        )
        out[f"{r.id}.yaml"] = body
    return out
