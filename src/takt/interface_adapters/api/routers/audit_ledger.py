from __future__ import annotations

from fastapi import HTTPException

from takt.interface_adapters.api.dependencies import ApiContext


def register_audit_ledger_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.audit_ledger_facade
    if facade is None:
        raise RuntimeError("audit ledger facade is required")

    @app.get("/cases/{case_id}/audit-ledger/verify", tags=["Analytics"])
    def verify_case_audit_ledger(case_id: str):
        try:
            return facade.verify_case_ledger(case_id)
        except NotImplementedError as e:
            raise HTTPException(status_code=501, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/audit-ledger/operations/verify", tags=["Analytics"])
    def verify_operation_audit_ledger(stream_key: str = ""):
        try:
            return facade.verify_operation_ledger(stream_key)
        except NotImplementedError as e:
            raise HTTPException(status_code=501, detail=str(e)) from e
