from __future__ import annotations

from fastapi import HTTPException, Request

from takt.application.use_cases.case_findings import ArtifactInput
from takt.infrastructure.security.request_actor import security_actor_from_request
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.findings import ArtifactBody, FindingBody


def _artifact_dict(item) -> dict:
    return {
        "type": item.type, "value": item.value, "host_id": item.host_id,
        "verification_status": item.verification_status, "source": item.source,
        "added_by": item.added_by, "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _finding_dict(item) -> dict:
    return {
        "finding_id": item.finding_id, "text": item.text, "author": item.author,
        "created_at": item.created_at.isoformat(), "event_ids": list(item.event_ids),
        "artifacts": [_artifact_dict(artifact) for artifact in item.artifacts],
    }


def register_finding_routes(ctx: ApiContext) -> None:
    app = ctx.app
    use_case = ctx.case_findings_uc
    if use_case is None:
        raise RuntimeError("case findings use case is required")

    def case_or_404(case_id: str):
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id}")
        return case

    @app.post("/cases/{case_id}/findings", tags=["Cases"])
    def add_finding(case_id: str, body: FindingBody, request: Request):
        try:
            finding = use_case.add_finding(
                case_id, body.text, body.event_ids,
                [ArtifactInput(**item.model_dump()) for item in body.artifacts],
                actor=security_actor_from_request(request), clock=ctx.clock.now_utc(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=404 if str(exc).startswith("unknown case") else 400, detail=str(exc)) from exc
        return _finding_dict(finding)

    @app.get("/cases/{case_id}/findings", tags=["Cases"])
    def list_findings(case_id: str):
        return [_finding_dict(item) for item in case_or_404(case_id).findings]

    @app.post("/cases/{case_id}/artifacts", tags=["Cases"])
    def add_artifact(case_id: str, body: ArtifactBody, request: Request):
        try:
            item = use_case.add_artifact(
                case_id, ArtifactInput(**body.model_dump()),
                actor=security_actor_from_request(request), clock=ctx.clock.now_utc(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=404 if str(exc).startswith("unknown case") else 400, detail=str(exc)) from exc
        return _artifact_dict(item)

    @app.get("/cases/{case_id}/artifacts", tags=["Cases"])
    def list_artifacts(case_id: str):
        case = case_or_404(case_id)
        items = [_artifact_dict(item) for item in case.artifacts]
        store = getattr(app.state, "recent_event_store", None)
        if store is not None:
            for event in store.events_by_ids(case.normalized_event_ids):
                host_id = event.entities.host_id if event.entities else ""
                for artifact in event.artifacts:
                    items.append({
                        "type": artifact.type.value, "value": artifact.value, "host_id": host_id or "",
                        "verification_status": "unverified", "source": f"event:{event.event_id}",
                        "added_by": "system", "created_at": event.observed_at.isoformat(),
                    })
        unique = {(item["type"], item["value"], item["source"]): item for item in items}
        return list(unique.values())
