from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from takt.domain.entities.event import NormalizedEvent


def _truthy(val: Any) -> bool:
    if val is True or val == 1:
        return True
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "y")
    return False


def apply_enrichment_rules(ev: NormalizedEvent, rules: Mapping[str, Any] | None) -> NormalizedEvent:
    """Выставляет семантические флаги в payload до оценки инвариантов (доменный чистый шаг)."""
    if not rules or not rules.get("enabled", True):
        return ev
    pl = dict(ev.payload)
    air = rules.get("air_gap_segments")
    if isinstance(air, list) and air:
        seg_allowed = {str(x).lower() for x in air}
        seg = str(pl.get("segment", "")).lower()
        if seg in seg_allowed and _truthy(pl.get("is_new_peer")):
            pl["new_node_airgap"] = True
    return replace(ev, payload=pl)
