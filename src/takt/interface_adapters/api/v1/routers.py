"""Роутеры surface ``/api/v1`` (собираются в примонтированный sub-app).

Эндпоинты демонстрируют чистую архитектуру итерации 1:
    * идемпотентный ingest с изоляцией невалидных записей в dead-letter;
    * SSE-поток изменений статуса кейсов;
    * курсорную пагинацию поиска событий;
    * RBAC на каждом write-маршруте;
    * ошибки в формате RFC 9457 (обработчики sub-app).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from takt.domain.soc.invariants import check_all_invariants
from takt.domain.soc.normalized_event import NormalizedEvent
from takt.interface_adapters.api.v1.context import SocApiContext
from takt.interface_adapters.api.v1.cursor import (
    bound_limit,
    decode_cursor,
    encode_cursor,
)
from takt.interface_adapters.api.v1.problem import ProblemException
from takt.interface_adapters.api.v1.rbac import Role, require_role
from takt.interface_adapters.api.v1.schemas import (
    DeadLetterOut,
    DecisionIn,
    EventIn,
    HintOut,
    ProcessEventOut,
    SearchOut,
)

_ANY_ROLE = require_role(Role.ANALYST_L1, Role.ANALYST_L2, Role.MANAGER, Role.ADMIN)
_WRITE_L1 = require_role(Role.ANALYST_L1)
_ADMIN = require_role(Role.ADMIN)


def build_router(ctx: SocApiContext) -> APIRouter:
    router = APIRouter()

    @router.post("/events", response_model=ProcessEventOut, dependencies=[Depends(_WRITE_L1)])
    def ingest_event(body: EventIn) -> ProcessEventOut:
        raw_json = body.model_dump_json()
        # Построение доменной сущности может упасть на инвариантах конструктора.
        try:
            event = NormalizedEvent(
                source_class=body.source_class,
                host_id=body.host_id,
                user_id=body.user_id,
                process=body.process,
                address=body.address,
                artifact=body.artifact,
                ts=body.ts,
                raw_ref=body.raw_ref,
                hasher=ctx.hasher,
            )
        except ValueError as exc:
            ctx.dead_letters.record(
                raw_data=raw_json,
                error_type="ConstructionError",
                error_detail=str(exc),
                ts=ctx.clock.now(),
            )
            raise ProblemException(
                status=422, title="Unprocessable Entity", detail=str(exc), type_suffix="invariant-violation"
            ) from exc

        # Дополнительная проверка 7 инвариантов (в т.ч. зависящих от Clock).
        violations = check_all_invariants(event, ctx.invariants)
        if violations:
            detail = "; ".join(f"{v.code}: {v.reason}" for v in violations)
            ctx.dead_letters.record(
                raw_data=raw_json,
                error_type="InvariantViolation",
                error_detail=detail,
                ts=ctx.clock.now(),
            )
            raise ProblemException(
                status=422, title="Unprocessable Entity", detail=detail, type_suffix="invariant-violation"
            )

        result = ctx.process_event.execute(event)
        # Обновление read-моделей и публикация SSE-события только для новых кейсов.
        if result.created:
            _project_new_case(ctx, event, result.case_id)
            _publish_case_event(ctx, case_id=result.case_id, status="new", ts=body.ts.isoformat())
        return ProcessEventOut(
            case_id=result.case_id, created=result.created, content_hash=result.content_hash
        )

    @router.get("/events/search", response_model=SearchOut, dependencies=[Depends(_ANY_ROLE)])
    def search_events(
        q: str | None = Query(default=None),
        cursor: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> SearchOut:
        try:
            after_seq = decode_cursor(cursor)
        except ValueError as exc:
            raise ProblemException(status=400, title="Bad Request", detail=str(exc)) from exc
        page = ctx.search_events.execute(query=q, after_seq=after_seq, limit=bound_limit(limit))
        next_cursor = encode_cursor(page.next_cursor) if page.next_cursor is not None else None
        return SearchOut(items=page.items, next_cursor=next_cursor, total_count=page.total_count)

    @router.get("/cases/{case_id}/card", dependencies=[Depends(_ANY_ROLE)])
    def case_card(case_id: str) -> dict[str, Any]:
        card = ctx.get_case_card.execute(case_id)
        if card is None:
            raise ProblemException(status=404, title="Not Found", detail=f"кейс {case_id} не найден")
        return card

    @router.get("/cases/{case_id}/attack-chain", dependencies=[Depends(_ANY_ROLE)])
    def attack_chain(case_id: str) -> dict[str, Any]:
        return {"case_id": case_id, "chain": ctx.get_attack_chain.execute(case_id)}

    @router.get("/cases/{case_id}/hints", response_model=list[HintOut], dependencies=[Depends(_ANY_ROLE)])
    def case_hints(case_id: str) -> list[HintOut]:
        card = ctx.get_case_card.execute(case_id)
        if card is None:
            raise ProblemException(status=404, title="Not Found", detail=f"кейс {case_id} не найден")
        from takt.application.soc.playbook_engine import CaseState

        state = CaseState(
            severity=str(card.get("severity", "")),
            status=str(card.get("status", "")),
            invariant_hits=tuple(card.get("invariant_hits", ())),
            source_classes=tuple(card.get("source_classes", ())),
            degraded_sources=bool(card.get("degraded_sources", False)),
        )
        return [HintOut(rule_id=h.rule_id, recommendation=h.recommendation, priority=h.priority) for h in ctx.playbooks.get_hints(state)]

    @router.post("/cases/{case_id}/decision", dependencies=[Depends(_WRITE_L1)])
    def case_decision(case_id: str, body: DecisionIn, request: Request) -> dict[str, Any]:
        actor = getattr(request.state, "takt_actor_id", "") or request.headers.get("X-Role", "unknown")
        entry = ctx.record_decision.execute(
            case_id=case_id, decision=body.decision, actor=actor, note=body.note
        )
        card = ctx.get_case_card.execute(case_id)
        if card is not None:
            card["status"] = "decided"
            ctx.case_projection.upsert_case_card(card)
        _publish_case_event(ctx, case_id=case_id, status="decided", ts=entry.ts, severity=str((card or {}).get("severity", "")))
        return {"case_id": case_id, "seq": entry.seq, "entry_hash": entry.entry_hash}

    @router.get(
        "/admin/dead-letters", response_model=list[DeadLetterOut], dependencies=[Depends(_ADMIN)]
    )
    def list_dead_letters(limit: int = Query(default=100, ge=1, le=1000)) -> list[DeadLetterOut]:
        return [
            DeadLetterOut(
                id=d.id, raw_data=d.raw_data, error_type=d.error_type, error_detail=d.error_detail, ts=d.ts
            )
            for d in ctx.dead_letters.list(limit=limit)
        ]

    @router.get("/stream/cases", dependencies=[Depends(_ANY_ROLE)])
    async def stream_cases(
        replay: int = Query(default=0, ge=0, le=256),
        close_after: int | None = Query(default=None, ge=1),
    ) -> StreamingResponse:
        return StreamingResponse(
            _sse_case_stream(ctx, replay=replay, close_after=close_after),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return router


def _project_new_case(ctx: SocApiContext, event: NormalizedEvent, case_id: str) -> None:
    ctx.case_projection.upsert_case_card(
        {
            "case_id": case_id,
            "severity": "medium",
            "status": "new",
            "source_classes": [event.source_class],
            "invariant_hits": [],
            "degraded_sources": False,
            "host_id": event.host_id,
        }
    )
    ctx.search_projection.index_event(
        {
            "content_hash": event.content_hash,
            "case_id": case_id,
            "source_class": event.source_class,
            "host_id": event.host_id,
            "user_id": event.user_id,
            "address": event.address,
            "ts": event.ts.isoformat(),
        }
    )


def _publish_case_event(
    ctx: SocApiContext, *, case_id: str, status: str, ts: str, severity: str = "medium"
) -> None:
    ctx.broadcaster.publish(
        {"case_id": case_id, "severity": severity, "status": status, "ts": ts}
    )


async def _sse_case_stream(ctx: SocApiContext, *, replay: int, close_after: int | None):
    sent = 0
    for event in ctx.broadcaster.recent(replay):
        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        sent += 1
        if close_after is not None and sent >= close_after:
            return
    queue = ctx.broadcaster.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
            except TimeoutError:
                # Периодический heartbeat-комментарий, чтобы соединение не отпало.
                yield ": keep-alive\n\n"
                continue
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            sent += 1
            if close_after is not None and sent >= close_after:
                return
    finally:
        ctx.broadcaster.unsubscribe(queue)
