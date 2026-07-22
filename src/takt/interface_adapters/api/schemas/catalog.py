from __future__ import annotations

from pydantic import BaseModel


class DemoGraphEdgeOut(BaseModel):
    src: str
    dst: str
    kind: str


class DemoTopologyResponse(BaseModel):
    jump_host: str
    plc_hosts: list[str]
    edges: list[DemoGraphEdgeOut]
    has_jump_bypass_pattern: bool


class InvariantCatalogItem(BaseModel):
    id: str
    block_key: str
    block_label_ru: str
    title_ru: str
    experimental: bool = False


class EventSourceCatalogItem(BaseModel):
    id: str
    source_class: str
    display_name: str
    event_count: int = 0
    ingest_trust: float | None = None
