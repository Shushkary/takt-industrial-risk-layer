from __future__ import annotations

from fastapi import HTTPException, Request

from takt.application.use_cases.manual_correlation import ManualCorrelationCommand
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.correlation import (
    CorrelationAttachBody,
    CorrelationMergeBody,
    CorrelationReasonBody,
    CorrelationSplitBody,
)


def register_correlation_routes(ctx: ApiContext) -> None:
    app = ctx.app
    use_case = ctx.manual_correlation_uc
    if use_case is None:
        raise RuntimeError("manual correlation use case is required")

    def command(request: Request, case_id: str, reason: str, **kwargs) -> ManualCorrelationCommand:
        return ManualCorrelationCommand(
            case_id=case_id, reason=reason, actor=security_actor_from_request(request),
            request_id=str(getattr(request.state, "request_id", "")), **kwargs,
        )

    def invoke(action, cmd: ManualCorrelationCommand):
        try:
            case = action(cmd, clock=ctx.clock.now_utc())
        except ValueError as exc:
            detail = str(exc)
            raise HTTPException(status_code=404 if detail.startswith("unknown case") else 400, detail=detail) from exc
        return {
            "case_id": case.case_id, "status": case.status.value,
            "event_ids": list(case.normalized_event_ids), "risk_score": case.risk_score,
            "related_cases": list(case.related_cases),
        }

    @app.post("/cases/{case_id}/events/{event_id}/detach", tags=["Cases"])
    def detach_event(case_id: str, event_id: str, body: CorrelationReasonBody, request: Request):
        return invoke(use_case.detach, command(request, case_id, body.reason, event_id=event_id))

    @app.post("/cases/{case_id}/events/attach", tags=["Cases"])
    def attach_event(case_id: str, body: CorrelationAttachBody, request: Request):
        return invoke(use_case.attach, command(request, case_id, body.reason, event_id=body.event_id))

    @app.post("/cases/{case_id}/merge", tags=["Cases"])
    def merge_case(case_id: str, body: CorrelationMergeBody, request: Request):
        return invoke(use_case.merge, command(request, case_id, body.reason, source_case_id=body.source_case_id))

    @app.post("/cases/{case_id}/split", tags=["Cases"])
    def split_case(case_id: str, body: CorrelationSplitBody, request: Request):
        return invoke(use_case.split, command(request, case_id, body.reason, event_ids=tuple(body.event_ids)))
