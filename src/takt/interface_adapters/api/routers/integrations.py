from __future__ import annotations

import httpx
from fastapi import HTTPException

from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.integrations import (
    SiemForwardAsyncResponse,
    SiemForwardBody,
    SiemForwardResponse,
)


def register_integration_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.export_facade
    if facade is None:
        raise RuntimeError("export facade is required for integration routes")

    @app.post("/integrations/siem/forward", response_model=SiemForwardResponse, tags=["Integrations"])
    def forward_to_siem(body: SiemForwardBody):
        try:
            code = facade.forward_siem_sync(
                case_id=body.case_id,
                target_url=body.target_url,
                allowed_prefixes=ctx.siem_webhook_prefixes,
                retries=int(getattr(app.state, "webhook_retries", 3)),
                backoff_sec=float(getattr(app.state, "webhook_backoff_sec", 0.35)),
            )
        except ValueError as e:
            status = 404 if str(e) == "case not found" else 400
            raise HTTPException(status_code=status, detail=str(e)) from e
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"webhook failed: {e!s}") from e
        return SiemForwardResponse(http_status=code)

    @app.post("/integrations/siem/forward/async", response_model=SiemForwardAsyncResponse, tags=["Integrations"])
    async def forward_to_siem_async(body: SiemForwardBody):
        try:
            code = await facade.forward_siem_async(
                case_id=body.case_id,
                target_url=body.target_url,
                allowed_prefixes=ctx.siem_webhook_prefixes,
                retries=int(getattr(app.state, "webhook_retries", 3)),
                backoff_sec=float(getattr(app.state, "webhook_backoff_sec", 0.35)),
            )
        except ValueError as e:
            status = 404 if str(e) == "case not found" else 400
            raise HTTPException(status_code=status, detail=str(e)) from e
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"webhook failed: {e!s}") from e
        return SiemForwardAsyncResponse(http_status=code, async_handled=True)
