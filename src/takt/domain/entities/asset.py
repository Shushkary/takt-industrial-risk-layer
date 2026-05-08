from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Asset:
    """Объект КИИ / узел топологии."""

    asset_id: str
    segment: str
    is_air_gapped: bool
    metadata: dict[str, str]
