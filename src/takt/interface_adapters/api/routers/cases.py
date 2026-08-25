from __future__ import annotations

import hashlib
import hmac
import os
from datetime import UTC, datetime

from fastapi import HTTPException, Query, Request, Response
from pydantic import ValidationError

from takt.application.use_cases.cases_query_service import CasesListQuery
from takt.interface_adapters.api.dependencies import ApiContext, require
from takt.interface_adapters.api.schemas.cases import (
    CaseDetail,
    CasesFullExportResponse,
    CasesImportBody,
    CasesImportResponse,
    CasesStatsResponse,
    CaseSummary,
    DecisionBriefDetail,
)


def register_case_routes(ctx: ApiContext) -> None:
    app = ctx.app
    # Схемы берутся импортом, а не из контекста: это те же самые классы (app.py импортирует
    # их оттуда же и просто передаёт дальше), но через переменную их нельзя использовать
    # как тип — `response_model=list[CaseSummary]` тогда не проверяется.
    query_service = require(ctx.cases_query_service, "cases_query_service")
    case_to_detail = require(ctx.case_to_detail, "case_to_detail")
    decision_brief_to_detail = require(ctx.decision_brief_to_detail, "decision_brief_to_detail")
    domain_case_from_detail = require(ctx.domain_case_from_detail, "domain_case_from_detail")
    offset_limit_link_header = require(ctx.offset_limit_link_header, "offset_limit_link_header")

    @app.get(
        "/cases",
        response_model=list[CaseSummary],
        tags=["Cases"],
        responses={
            200: {
                "description": "Список кейсов (после фильтров и сортировки, срез по offset/limit)",
                "headers": {
                    "X-Total-Count": {
                        "description": "Число записей после всех фильтров и сортировки, до применения offset/limit",
                        "schema": {"type": "string", "example": "42"},
                    },
                    "Link": {
                        "description": (
                            "Пагинация (RFC 8288): при переданном query-параметре `limit` — "
                            "`rel=\"next\"` и/или `rel=\"prev\"` с теми же фильтрами, что в запросе"
                        ),
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    )
    def list_cases(
        request: Request,
        response: Response,
        status: str | None = Query(default=None, description="NEW, TRIAGE, …"),
        risk_class: str | None = Query(default=None, description="LOW, MEDIUM, HIGH, CRITICAL"),
        risk_classes: str | None = Query(
            default=None,
            description="Несколько классов через запятую, напр. HIGH,CRITICAL (пересекается с фильтром risk_class)",
        ),
        created_after: datetime | None = Query(default=None, description="ISO-8601: created_at >= момента (без часового пояса — UTC)"),
        created_before: datetime | None = Query(default=None, description="ISO-8601: created_at <= момента (без часового пояса — UTC)"),
        min_risk_score: float | None = Query(default=None, ge=0.0, le=1.0),
        max_risk_score: float | None = Query(default=None, ge=0.0, le=1.0, description="Кейсы с risk_score <= порога"),
        min_dq_score: float | None = Query(default=None, ge=0.0, le=1.0, description="Кейсы с dq_score >= порога"),
        max_dq_score: float | None = Query(default=None, ge=0.0, le=1.0, description="Кейсы с dq_score <= порога"),
        dq_partial: bool | None = Query(default=None, description="true — только partial_observability; false — только полная наблюдаемость"),
        has_invariant: str | None = Query(default=None, description="Подстрока id инварианта"),
        has_dq_reason: str | None = Query(default=None, description="Подстрока причины DQ (напр. source_reputation_drift, stale_data)"),
        primary_asset_id: str | None = Query(default=None, description="Точное совпадение primary_asset_id (без учёта регистра)"),
        fingerprint: str | None = Query(default=None, description="Точное совпадение burst_fingerprint"),
        fingerprint_prefix: str | None = Query(default=None, description="Префикс burst_fingerprint (без учёта регистра)"),
        title_contains: str | None = Query(default=None, description="Подстрока в title кейса (без учёта регистра)"),
        case_id_prefix: str | None = Query(default=None, description="Префикс case_id (без учёта регистра)"),
        trigger_operation_contains: str | None = Query(default=None, description="Подстрока в trigger_operation последнего события (без учёта регистра)"),
        min_invariant_hits: int | None = Query(default=None, ge=0, le=10_000, description="Минимум записей в invariant_hits"),
        max_invariant_hits: int | None = Query(default=None, ge=0, le=10_000, description="Максимум записей в invariant_hits"),
        xai_contains: str | None = Query(default=None, description="Подстрока в xai_summary (без учёта регистра)"),
        min_event_count: int | None = Query(default=None, ge=1, le=100_000, description="Минимум нормализованных событий в кейсе (после merge — union event_ids)"),
        max_event_count: int | None = Query(default=None, ge=0, le=100_000, description="Максимум нормализованных событий в кейсе"),
        audit_contains: str | None = Query(default=None, description="Подстрока в любой строке audit_log (без учёта регистра)"),
        event_source: str | None = Query(default=None, description="Точное совпадение last_event_source (EventSource последнего события в потоке)"),
        sort: str = Query(
            default="risk_score_desc",
            description="risk_score|created_at|dq_score|invariant_hits|event_count|title|case_id|primary_asset_id — _desc или _asc",
        ),
        limit: int | None = Query(default=None, ge=1, le=1000, description="Ограничить число записей"),
        offset: int = Query(default=0, ge=0, description="Смещение после сортировки"),
    ):
        try:
            result = query_service.list_cases(
                CasesListQuery(
                    status=status,
                    risk_class=risk_class,
                    risk_classes=risk_classes,
                    created_after=created_after,
                    created_before=created_before,
                    min_risk_score=min_risk_score,
                    max_risk_score=max_risk_score,
                    min_dq_score=min_dq_score,
                    max_dq_score=max_dq_score,
                    dq_partial=dq_partial,
                    has_invariant=has_invariant,
                    has_dq_reason=has_dq_reason,
                    primary_asset_id=primary_asset_id,
                    fingerprint=fingerprint,
                    fingerprint_prefix=fingerprint_prefix,
                    title_contains=title_contains,
                    case_id_prefix=case_id_prefix,
                    trigger_operation_contains=trigger_operation_contains,
                    min_invariant_hits=min_invariant_hits,
                    max_invariant_hits=max_invariant_hits,
                    xai_contains=xai_contains,
                    min_event_count=min_event_count,
                    max_event_count=max_event_count,
                    audit_contains=audit_contains,
                    event_source=event_source,
                    sort=sort,
                    offset=offset,
                    limit=limit,
                )
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        response.headers["X-Total-Count"] = str(result.total_before_slice)
        link = offset_limit_link_header(request, offset=offset, limit=limit, total_before_slice=result.total_before_slice)
        if link:
            response.headers["Link"] = link
        return [
            CaseSummary(
                case_id=c.case_id,
                status=c.status.value,
                title=c.title,
                risk_class=c.risk_class,
                risk_score=c.risk_score,
                fingerprint=c.burst_fingerprint,
                primary_asset_id=c.primary_asset_id,
                trigger_operation=c.trigger_operation,
                operator_id=c.operator_id,
                last_event_source=c.last_event_source,
                invariant_hits_count=len(c.invariant_hits),
                event_count=len(c.normalized_event_ids),
                created_at=c.created_at.astimezone(UTC).isoformat(timespec="seconds"),
                dq_score=c.dq_score,
                dq_partial=c.dq_partial,
            )
            for c in result.items
        ]

    @app.get("/cases/stats", response_model=CasesStatsResponse, tags=["Cases"])
    def cases_stats():
        stats = query_service.stats()
        return CasesStatsResponse(
            total=stats.total,
            open=stats.open,
            by_status=stats.by_status,
            by_risk_class=stats.by_risk_class,
            avg_risk_score=stats.avg_risk_score,
            avg_dq_score=stats.avg_dq_score,
            dq_partial_count=stats.dq_partial_count,
            normalized_events_total=stats.normalized_events_total,
            distinct_invariant_hits=stats.distinct_invariant_hits,
            invariant_hits_occurrences_total=stats.invariant_hits_occurrences_total,
            by_last_event_source=stats.by_last_event_source,
        )

    @app.get(
        "/cases/export/full.json",
        response_model=CasesFullExportResponse,
        tags=["Export"],
        responses={
            200: {
                "description": "Пакет карточек (срез по offset/limit после сортировки)",
                "headers": {
                    "X-Total-Count": {
                        "description": "Число кейсов в репозитории, подпадающих под выгрузку (до среза по offset/limit; совпадает с total_in_repo в теле)",
                        "schema": {"type": "string", "example": "42"},
                    },
                    "Link": {
                        "description": (
                            "Пагинация (RFC 8288): при переданном query-параметре `limit` — "
                            "`rel=\"next\"` и/или `rel=\"prev\"` с тем же путём и параметрами выгрузки"
                        ),
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    )
    def export_all_cases_full_json(
        request: Request,
        response: Response,
        offset: int = Query(default=0, ge=0, description="Смещение в отсортированном списке (created_at desc)"),
        limit: int | None = Query(default=None, ge=1, le=10_000, description="Макс. число кейсов в ответе (по умолчанию — все от offset; не больше 10000)"),
    ):
        result = query_service.full_export(offset=offset, limit=limit)
        total = result.total
        response.headers["X-Total-Count"] = str(total)
        exp_link = offset_limit_link_header(request, offset=offset, limit=limit, total_before_slice=total)
        if exp_link:
            response.headers["Link"] = exp_link
        return CasesFullExportResponse(
            exported_at=result.exported_at,
            count=len(result.items),
            total_in_repo=total,
            offset=result.offset,
            limit=result.limit,
            cases=[case_to_detail(c) for c in result.items],
        )

    @app.post("/cases/import/full.json", response_model=CasesImportResponse, tags=["Export"])
    async def import_cases_full_json(request: Request):
        raw = await request.body()
        try:
            body = CasesImportBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        import_secret = os.environ.get("TAKT_IMPORT_HMAC_SECRET", "").strip()
        if import_secret:
            got = request.headers.get("X-TAKT-Import-Signature", "").strip()
            if got.startswith("sha256="):
                got = got.split("=", 1)[1].strip()
            expected = hmac.new(import_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
            if not got or not hmac.compare_digest(got, expected):
                raise HTTPException(status_code=401, detail="invalid import signature")
        parsed = []
        for d in body.cases:
            try:
                parsed.append(domain_case_from_detail(d))
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e

        result = query_service.import_cases(parsed, mode=body.mode)
        return CasesImportResponse(imported=result.imported, skipped=result.skipped, mode=result.mode)

    @app.get("/cases/{case_id}", response_model=CaseDetail, tags=["Cases"])
    def get_case(case_id: str):
        c = query_service.get_case_or_none(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case_to_detail(c)

    @app.get("/cases/{case_id}/decision-brief", response_model=DecisionBriefDetail, tags=["Cases"])
    def get_case_decision_brief(case_id: str):
        """Сводка для лица, принимающего решение: без разбора карточки аналитика."""
        c = query_service.get_case_or_none(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return decision_brief_to_detail(c)
