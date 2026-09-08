from __future__ import annotations

from fastapi import HTTPException

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.interface_adapters.api.dependencies import ApiContext


def register_attack_chain_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/cases/{case_id}/attack-chain", tags=["Cases"])
    def attack_chain(case_id: str):
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id}")
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            return {
                "case_id": case_id, "entry_point": "", "entry_point_status": "undetermined",
                "entry_point_reason": "", "steps": [],
                "last_observed": {"value": "", "observed_at": ""},
                "history": {"from": "", "to": "", "events": 0}, "artifacts": [],
            }
        result = reconstruct_attack_chain(store.events_by_ids(case.normalized_event_ids))
        return {"case_id": case_id, **result}
