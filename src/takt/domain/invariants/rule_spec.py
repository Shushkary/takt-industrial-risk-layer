from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from takt.domain.invariants.catalog import INVARIANT_RECORDS, InvariantId

_DEFAULT_CONTEXT = 5
_RHYTHM = 24


@dataclass(frozen=True, slots=True)
class InvariantRuleSpec:
    """Декларативное правило из каталога (данные + ссылка на встроенный предикат)."""

    id: str
    block_key: str
    context_window_events: int
    experimental: bool
    params: Mapping[str, Any]
    predicate_ref: str
    inputs: tuple[str, ...]
    severity_curve: Mapping[str, Any] | None

    def predicate_name(self) -> str:
        raw = self.predicate_ref.strip()
        if raw.startswith("builtin:"):
            return raw[len("builtin:") :].strip()
        return raw


_IDS_NOOP: frozenset[str] = frozenset()

_PER_CONTEXT: dict[str, int] = {
    InvariantId.POLLING_JITTER.value: _RHYTHM,
    InvariantId.PAYLOAD_LENGTH_DRIFT.value: _RHYTHM,
    InvariantId.REQUEST_REPLY_DISSONANCE.value: _RHYTHM,
    InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value: _RHYTHM,
    InvariantId.BRUTE_FORCE.value: 20,
    InvariantId.BLIND_COMMAND.value: 3,
}


def _default_predicate_id(inv_id: str) -> str:
    if inv_id in _IDS_NOOP:
        return "noop"
    return inv_id


def default_predicate_builtin_ref(inv_id: str) -> str:
    return f"builtin:{_default_predicate_id(inv_id)}"


def default_extended_rule_specs() -> tuple[InvariantRuleSpec, ...]:
    """Каталог по умолчанию (не из YAML), совместимый с прежней монолитной логикой."""
    rows = []
    for rec in INVARIANT_RECORDS:
        iid = rec.id
        pred = _default_predicate_id(iid)
        ctx_n = _PER_CONTEXT.get(iid, _DEFAULT_CONTEXT)
        rows.append(
            InvariantRuleSpec(
                id=iid,
                block_key=rec.block_key,
                context_window_events=ctx_n,
                experimental=False,
                params={},
                predicate_ref=f"builtin:{pred}",
                inputs=(),
                severity_curve=None,
            )
        )
    return tuple(sorted(rows, key=lambda r: r.id))


def max_rule_context_window(specs: tuple[InvariantRuleSpec, ...]) -> int:
    if not specs:
        return _DEFAULT_CONTEXT
    return max(s.context_window_events for s in specs)
