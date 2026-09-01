from __future__ import annotations

from fastapi import HTTPException, Query

from takt.domain.engines.causal_mesh import detect_jump_server_bypass
from takt.domain.entities.event import EventSource
from takt.domain.vocabulary import EVENT_SOURCE_RU, vocabulary
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.catalog import (
    DemoGraphEdgeOut,
    DemoTopologyResponse,
    EventSourceCatalogItem,
    InvariantCatalogItem,
)


def register_catalog_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/invariants", response_model=list[InvariantCatalogItem], tags=["Catalog"])
    def invariants_catalog(block_key: str | None = Query(default=None, description="Фильтр: rhythm, topology, …")):
        rows = tuple(ctx.invariant_catalog.records)
        if block_key is not None and block_key.strip() != "":
            bk = block_key.strip().lower()
            known = frozenset(r.block_key for r in rows)
            if bk not in known:
                raise HTTPException(
                    status_code=400,
                    detail=f"unknown block_key; use one of: {', '.join(sorted(known))}",
                )
            rows = tuple(r for r in rows if r.block_key == bk)
        return [
            InvariantCatalogItem(
                id=r.id,
                block_key=r.block_key,
                block_label_ru=r.block_label_ru,
                title_ru=r.title_ru,
                experimental=r.experimental,
            )
            for r in rows
        ]

    @app.get("/catalog/event-sources", response_model=list[EventSourceCatalogItem], tags=["Catalog"])
    def event_sources_catalog():
        tbs = ctx.trust_by_source
        store = getattr(app.state, "recent_event_store", None)
        counts = store.event_counts_by_source() if store is not None else {}
        return [
            EventSourceCatalogItem(
                id=s.value,
                source_class=s.value,
                # Названия берутся из общего словаря, а не из локальной таблицы: иначе каталог
                # и карточка дела называли бы один и тот же источник по-разному.
                display_name=EVENT_SOURCE_RU.get(s.value, s.value),
                event_count=counts.get(s.value, 0),
                ingest_trust=(float(tbs[s.value]) if s.value in tbs else None),
            )
            for s in EventSource
        ]

    @app.get("/catalog/vocabulary", tags=["Catalog"])
    def vocabulary_catalog():
        """Русские названия обозначений продукта для интерфейсов.

        Один источник правды ([`vocabulary.py`](../../domain/vocabulary.py)): свой словарь в
        АРМ разошёлся бы с продуктом при первом же добавлении статуса или источника.
        Значения из данных источника — операция, протокол, идентификаторы — сюда не входят
        и не переводятся.
        """
        return vocabulary()

    @app.get("/topology/demo-graph", response_model=DemoTopologyResponse, tags=["Catalog"])
    def demo_topology():
        bypass = detect_jump_server_bypass(list(ctx.demo_edges), ctx.jump_host, ctx.plc_hosts)
        return DemoTopologyResponse(
            jump_host=ctx.jump_host,
            plc_hosts=sorted(ctx.plc_hosts),
            edges=[DemoGraphEdgeOut(src=e.src, dst=e.dst, kind=e.kind) for e in ctx.demo_edges],
            has_jump_bypass_pattern=bypass,
        )
