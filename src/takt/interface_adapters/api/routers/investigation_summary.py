"""Итоговое описание расследования: шаблон, редакции, утверждение.

Порядок регистрации важен так же, как у `/cases/groups`: пути объявляются раньше
`/cases/{case_id}`, иначе сегмент попадёт в путь как идентификатор дела.

Права: писать редакцию может тот же, кто пишет находки (первая линия и выше) — это рабочая
запись аналитика. Утверждать редакцию, которая уходит в доказательный пакет, может вторая
линия: то же правило, по которому решение по делу принимает вторая линия, а не первая.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from takt.application.use_cases.investigation_summary import build_summary_template
from takt.application.use_cases.response_package import build_response_package
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext, require
from takt.interface_adapters.api.schemas.investigation_summary import (
    SummaryApproveBody,
    SummarySaveBody,
)


def _summary_dict(item) -> dict:
    return {
        "version": item.version,
        "sections": dict(item.sections),
        "confidence": item.confidence,
        "author": item.author,
        "created_at": item.created_at.isoformat(),
        "checksum": item.checksum,
        "approved": bool(item.approved),
        "approved_by": item.approved_by,
        "approved_at": item.approved_at.isoformat() if item.approved_at else "",
    }


def register_investigation_summary_routes(ctx: ApiContext) -> None:
    app = ctx.app
    use_case = require(ctx.investigation_summary_uc, "investigation_summary_uc")

    def case_or_404(case_id: str):
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id}")
        return case

    def _events(case) -> list:
        store = getattr(app.state, "recent_event_store", None)
        return store.events_by_ids(case.normalized_event_ids) if store is not None else []

    @app.get("/cases/{case_id}/summary", tags=["Cases"])
    def read_summary(case_id: str):
        """Редакции описания и заготовка для следующей.

        Заготовка отдаётся всегда: она собрана из уже посчитанного продуктом и нужна и при
        первом заполнении, и при правке — чтобы идентификаторы не переносились руками.
        """
        case = case_or_404(case_id)
        events = _events(case)
        package = build_response_package(case, events)
        template = build_summary_template(
            case, events, response_actions=[f"{item.action}: {item.value}" for item in package.candidates
                                            if item.selected_by_default]
        )
        current = use_case.current(case_id)
        return {
            "case_id": case_id,
            "sections": [
                {"key": section.key, "title": section.title, "prompt": section.prompt}
                for section in template.sections
            ],
            "template": {
                "draft": template.draft,
                "confidence": template.confidence,
                "facts": template.facts,
            },
            "current": _summary_dict(current) if current is not None else None,
            "versions": [_summary_dict(item) for item in case.investigation_summaries],
        }

    @app.post("/cases/{case_id}/summary", tags=["Cases"])
    def save_summary(case_id: str, body: SummarySaveBody, request: Request):
        case_or_404(case_id)
        try:
            record = use_case.save(
                case_id, dict(body.sections), confidence=body.confidence,
                actor=security_actor_from_request(request), clock=ctx.clock.now_utc(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _summary_dict(record)

    @app.post("/cases/{case_id}/summary/approve", tags=["Cases"])
    def approve_summary(case_id: str, body: SummaryApproveBody, request: Request):
        """Утверждение редакции: именно она уходит в доказательный пакет."""
        case_or_404(case_id)
        try:
            record = use_case.approve(
                case_id, body.version,
                actor=security_actor_from_request(request), clock=ctx.clock.now_utc(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _summary_dict(record)
