from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Query, Request, Response

from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.compliance import RemediationAttemptBody


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(__import__("os").environ.get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def register_compliance_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.compliance_facade
    if facade is None:
        raise RuntimeError("compliance facade is required")

    @app.get("/compliance/data-quality-report", tags=["Analytics"])
    def compliance_data_quality_report():
        return facade.data_quality_report()

    @app.get("/compliance/forensic-readiness", tags=["Analytics"])
    def compliance_forensic_readiness(only_not_ready: bool = False, missing_code: str = ""):
        try:
            return facade.forensic_readiness(only_not_ready=only_not_ready, missing_code=missing_code)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/compliance/remediation-kinds", tags=["Analytics"])
    def remediation_kinds_catalog():
        return facade.remediation_kinds_catalog()

    @app.get("/compliance/remediations", tags=["Analytics"])
    def compliance_remediations(
        case_id: str = "",
        kind: str = "",
        status: str = "",
        limit: int = Query(default=100, ge=1, le=500),
    ):
        try:
            return facade.remediations(case_id=case_id, kind=kind, status=status, limit=limit)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/compliance/mode", tags=["Analytics"])
    def compliance_mode_report():
        return facade.mode_report(compliance_enabled=_env_bool("TAKT_COMPLIANCE_MODE", default=False))

    @app.get("/cases/{case_id}/compliance/evidence-checklist", tags=["Analytics"])
    def case_evidence_checklist(case_id: str):
        try:
            return facade.evidence_checklist(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e

    @app.post("/cases/{case_id}/compliance/remediations", tags=["Analytics"])
    def post_remediation_attempt(case_id: str, body: RemediationAttemptBody, request: Request):
        try:
            return facade.record_remediation_attempt(
                case_id=case_id,
                kind=body.kind,
                status=body.status,
                action=body.action,
                result=body.result,
                note=body.note,
                actor=security_actor_from_request(request),
                request_id=str(getattr(request.state, "request_id", "")),
            )
        except ValueError as e:
            detail = str(e)
            code = 400 if "invalid remediation" in detail else 404
            raise HTTPException(status_code=code, detail=detail) from e

    @app.post("/cases/{case_id}/compliance/remediations/recheck-readiness", tags=["Analytics"])
    def post_remediation_readiness_recheck(case_id: str, body: dict[str, Any], request: Request):
        try:
            result = facade.recheck_readiness(
                case_id=case_id,
                attempt_id=str(body.get("attempt_id", "")).strip(),
                note=str(body.get("note", "")).strip(),
                actor=security_actor_from_request(request),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return {
            "case_id": result.case_id,
            "ready": result.ready,
            "missing_codes": result.missing_codes,
            "attempt": result.attempt,
        }

    @app.get("/cases/{case_id}/compliance/remediations/recheck-readiness/history", tags=["Analytics"])
    def get_remediation_readiness_recheck_history(
        request: Request,
        response: Response,
        case_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        attempt_id: str = "",
        ready: bool | None = None,
    ):
        try:
            result = facade.recheck_history(
                case_id=case_id,
                limit=limit,
                offset=offset,
                attempt_id=attempt_id,
                ready=ready,
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        response.headers["X-Total-Count"] = str(result.total_matched)
        if ctx.offset_limit_link_header is not None:
            link = ctx.offset_limit_link_header(
                request,
                offset=offset,
                limit=limit,
                total_before_slice=result.total_matched,
            )
            if link:
                response.headers["Link"] = link
        return {
            "case_id": result.case_id,
            "total_matched": result.total_matched,
            "entries": result.entries,
        }
