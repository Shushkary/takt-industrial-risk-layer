from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from takt.domain.entities.event import NormalizedEvent


def _first_int(*candidates: Any) -> int | None:
    for c in candidates:
        if c is None:
            continue
        try:
            return int(str(c).strip())
        except (TypeError, ValueError):
            continue
    return None


def apply_telemetry_hints(
    ev: NormalizedEvent,
    *,
    enrichment_rules: Mapping[str, Any] | None = None,
) -> NormalizedEvent:
    """
    Нормализует подсказки телеметрии (IEC-60870-5-104) в canonical поле payload iec104_type_id.
    Список имён колонок задаётся в enrichment.iec104_type_aliases (конфиг).
    """
    pl = dict(ev.payload)
    if pl.get("iec104_type_id") is not None:
        try:
            pl["iec104_type_id"] = int(pl["iec104_type_id"])
            return replace(ev, payload=pl)
        except (TypeError, ValueError):
            pl.pop("iec104_type_id", None)

    aliases: list[str] = []
    if enrichment_rules and isinstance(enrichment_rules.get("iec104_type_aliases"), list):
        aliases = [str(x) for x in enrichment_rules["iec104_type_aliases"]]
    if not aliases:
        aliases = ["asdu_type", "asdu_type_id", "type_id", "iec_asdu_type"]

    raw_vals = [pl.get(k) for k in aliases if k in pl]
    tid = _first_int(*raw_vals)

    if tid is not None:
        pl["iec104_type_id"] = tid
        return replace(ev, payload=pl)
    return ev
