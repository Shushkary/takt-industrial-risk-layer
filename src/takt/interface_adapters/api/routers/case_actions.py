from fastapi import HTTPException, Request

from takt.application.use_cases.case_actions_facade import OperatorActionCommand
from takt.application.use_cases.formal_verdict_confirmation import ConfirmFormalVerdictCommand
from takt.application.use_cases.manual_permit import AttachManualPermitCommand
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext


def register_case_action_routes(ctx: ApiContext) -> None:
    app = ctx.app
    if any(
        item is None
        for item in (
            ctx.case_actions_facade,
            ctx.manual_permit_body_model,
            ctx.operator_action_body_model,
            ctx.formal_verdict_confirmation_body_model,
            ctx.decision_body_model,
            ctx.case_decision_response_model,
            ctx.manual_permit_to_detail,
            ctx.formal_verdict_record_to_detail,
        )
    ):
        raise RuntimeError("case action dependencies are required")

    facade = ctx.case_actions_facade
    ManualPermitBody = ctx.manual_permit_body_model
    OperatorActionBody = ctx.operator_action_body_model
    FormalVerdictConfirmationBody = ctx.formal_verdict_confirmation_body_model
    DecisionBody = ctx.decision_body_model
    CaseDecisionResponse = ctx.case_decision_response_model

    @app.post("/cases/{case_id}/manual-permits", tags=["Cases"])
    def post_manual_permit(case_id: str, body: ManualPermitBody, request: Request):
        try:
            permit = facade.attach_manual_permit(
                AttachManualPermitCommand(
                    case_id=case_id,
                    work_order_number=body.work_order_number,
                    actor=security_actor_from_request(request),
                    asset_id=body.asset_id,
                    operation=body.operation,
                    action_class=body.action_class,
                    executor=body.executor,
                    approver=body.approver,
                    valid_from=body.valid_from,
                    valid_to=body.valid_to,
                    document_status=body.document_status,
                    restrictions=body.restrictions,
                    note=body.note,
                )
            )
        except ValueError as e:
            detail = str(e)
            code = 400 if "work_order_number" in detail else 404
            raise HTTPException(status_code=code, detail=detail) from e
        return {"permit": ctx.manual_permit_to_detail(permit).model_dump()}

    def _record_operator_action(case_id: str, action: str, body: OperatorActionBody, request: Request) -> dict[str, str]:
        try:
            return facade.record_operator_action(
                OperatorActionCommand(
                    case_id=case_id,
                    action=action,
                    actor=security_actor_from_request(request),
                    reason=body.reason,
                    note=body.note,
                )
            )
        except ValueError as e:
            code = 400 if str(e) == "reason is required" else 404
            raise HTTPException(status_code=code, detail=str(e)) from e

    @app.post("/cases/{case_id}/operator-actions/viewed", tags=["Cases"])
    def post_operator_viewed(case_id: str, body: OperatorActionBody, request: Request):
        return _record_operator_action(case_id, "viewed", body, request)

    @app.post("/cases/{case_id}/operator-actions/additional-review", tags=["Cases"])
    def post_operator_additional_review(case_id: str, body: OperatorActionBody, request: Request):
        return _record_operator_action(case_id, "additional_review", body, request)

    @app.post("/cases/{case_id}/formal-verdict/confirmation", tags=["Cases"])
    def post_formal_verdict_confirmation(case_id: str, body: FormalVerdictConfirmationBody, request: Request):
        try:
            record = facade.confirm_formal_verdict(
                ConfirmFormalVerdictCommand(
                    case_id=case_id,
                    actor=security_actor_from_request(request),
                    verdict=body.verdict,
                    confidence=body.confidence,
                    reason=body.reason,
                    note=body.note,
                )
            )
        except ValueError as e:
            detail = str(e)
            code = 400 if "unknown case" not in detail else 404
            raise HTTPException(status_code=code, detail=detail) from e
        return {"case_id": case_id, "record": ctx.formal_verdict_record_to_detail(record).model_dump()}

    @app.get("/cases/{case_id}/operator-actions/history", tags=["Cases"])
    def get_operator_action_history(case_id: str):
        try:
            return facade.operator_action_history(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/cases/{case_id}/formal-verdict/history", tags=["Cases"])
    def get_formal_verdict_history(case_id: str):
        try:
            entries = facade.formal_verdict_history(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return {
            "case_id": case_id,
            "entries": [
                ctx.formal_verdict_record_to_detail(entry).model_dump() if hasattr(entry, "ts") else entry
                for entry in entries
            ],
        }

    @app.post("/cases/{case_id}/decision", response_model=CaseDecisionResponse, tags=["Cases"])
    def post_decision(case_id: str, body: DecisionBody, request: Request):
        try:
            facade.submit_decision(
                case_id=case_id,
                status=body.status,
                actor=security_actor_from_request(request),
                reason=body.reason,
                request_id=str(getattr(request.state, "request_id", "")),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return CaseDecisionResponse(case_id=case_id, status=body.status.value)
