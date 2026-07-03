from __future__ import annotations

from fastapi import HTTPException, Response

from takt.infrastructure.export.siem_webhook import SiemCaseExportPayload
from takt.interface_adapters.api.dependencies import ApiContext


def register_export_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.export_facade
    if facade is None:
        raise RuntimeError("export facade is required")

    @app.get("/cases/{case_id}/export.pdf", tags=["Export"])
    def export_case_pdf(case_id: str):
        try:
            out = facade.export_pdf(
                case_id=case_id,
                unicode_font_path=getattr(app.state, "pdf_unicode_font", None),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except RuntimeError as e:
            raise HTTPException(status_code=501, detail=str(e)) from e
        return Response(content=out.content, media_type=out.media_type, headers=out.headers)

    @app.get("/cases/{case_id}/export/siem.json", response_model=SiemCaseExportPayload, tags=["Export"])
    def export_case_siem_json(case_id: str):
        try:
            return facade.siem_payload(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/cases/{case_id}/export/gossopka.json", tags=["Export"])
    def export_case_gossopka_json(case_id: str):
        try:
            return facade.gossopka_card(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/cases/{case_id}/export/gossopka-transport.json", tags=["Export"])
    def export_case_gossopka_transport(case_id: str, exchange_mode: str = "pull_http_json"):
        try:
            return facade.gossopka_transport(case_id=case_id, exchange_mode=exchange_mode)
        except ValueError as e:
            code = 404 if str(e) == "case not found" else 500
            raise HTTPException(status_code=code, detail=str(e)) from e

    @app.get("/cases/{case_id}/export/gossopka-official.json", tags=["Export"])
    def export_case_gossopka_official_json(case_id: str):
        try:
            return facade.gossopka_official_card(case_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/cases/{case_id}/export/gossopka-official-transport.json", tags=["Export"])
    def export_case_gossopka_official_transport(case_id: str, exchange_mode: str = "pull_http_json"):
        try:
            return facade.gossopka_official_transport(case_id=case_id, exchange_mode=exchange_mode)
        except ValueError as e:
            code = 404 if str(e) == "case not found" else 500
            raise HTTPException(status_code=code, detail=str(e)) from e
