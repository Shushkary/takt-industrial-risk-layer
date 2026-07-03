from __future__ import annotations

from fastapi import HTTPException, Query, Request, Response

from takt.application.use_cases.forensic_export_facade import ForensicSupplementalFileError
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext


def register_forensic_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.forensic_export_facade
    if facade is None:
        raise RuntimeError("forensic export facade is required")

    @app.get(
        "/cases/{case_id}/forensic-bundle/manifest",
        tags=["Export"],
        responses={
            404: {"description": "Case not found"},
            503: {"description": "Forensic signing unavailable in strict mode"},
        },
    )
    def export_case_forensic_manifest(case_id: str, engagement_id: str = Query(default="")):
        try:
            return facade.manifest(case_id=case_id, engagement_id=engagement_id)
        except ForensicSupplementalFileError as e:
            status_code = 404 if e.code == "engagement_not_found" else 400
            raise HTTPException(status_code=status_code, detail=e.detail) from e
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=f"forensic_signing_unavailable: {e}") from e

    @app.get(
        "/cases/{case_id}/forensic-bundle.zip",
        tags=["Export"],
        responses={
            404: {"description": "Case not found"},
            503: {"description": "Forensic signing unavailable in strict mode"},
        },
    )
    def export_case_forensic_bundle(case_id: str, request: Request, engagement_id: str = Query(default="")):
        try:
            out = facade.archive(
                case_id=case_id,
                actor=security_actor_from_request(request),
                engagement_id=engagement_id,
            )
        except ForensicSupplementalFileError as e:
            status_code = 404 if e.code == "engagement_not_found" else 400
            raise HTTPException(status_code=status_code, detail=e.detail) from e
        except ValueError as e:
            raise HTTPException(status_code=404, detail="case not found") from e
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=f"forensic_signing_unavailable: {e}") from e
        return Response(content=out.content, media_type=out.media_type, headers=out.headers)

    @app.post("/forensic-bundle/verify", tags=["Export"])
    async def verify_forensic_bundle_endpoint(request: Request):
        try:
            return facade.verify_archive(await request.body())
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
