from __future__ import annotations

from fastapi import HTTPException
from pydantic import BaseModel, Field

from takt.application.use_cases.assemble_incident import (
    AssembleIncidentUseCase,
    IncidentSeed,
)
from takt.interface_adapters.api.dependencies import ApiContext


class AssembleIncidentRequest(BaseModel):
    """Сборка инцидента пивотом по отличительным сущностям."""

    case_id: str = Field(min_length=1, max_length=64)
    seeds: list[str] = Field(min_length=1, max_length=32)
    title: str = ""
    expand_hosts: list[str] = Field(default_factory=list, max_length=32)
    expand_padding_sec: int = Field(default=0, ge=0, le=86400)
    actor: str = ""


class AssembleIncidentResponse(BaseModel):
    case_id: str
    core_events: int
    expanded_events: int
    total_events: int
    source_case_ids: list[str]


def register_assemble_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.post("/cases/assemble/pivot", response_model=AssembleIncidentResponse, tags=["Cases"])
    def assemble_by_pivot_endpoint(request: AssembleIncidentRequest) -> AssembleIncidentResponse:
        """Собирает кейс из уже принятых событий. Группировка, не действие и не вердикт."""
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            raise HTTPException(
                status_code=409,
                detail="сборка инцидента требует постоянного хранилища событий (TAKT_STORAGE=sqlite)",
            )
        try:
            seeds = [IncidentSeed.parse(item) for item in request.seeds]
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        use_case = AssembleIncidentUseCase(
            events=store,
            repo=ctx.repo,
            weights=getattr(app.state, "risk_weights", {}),
        )
        try:
            assembled = use_case.execute(
                case_id=request.case_id,
                seeds=seeds,
                title=request.title,
                expand_hosts=tuple(request.expand_hosts),
                expand_padding_sec=request.expand_padding_sec,
                actor=request.actor,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return AssembleIncidentResponse(
            case_id=assembled.case.case_id,
            core_events=len(assembled.core_event_ids),
            expanded_events=len(assembled.expanded_event_ids),
            total_events=assembled.total_events,
            source_case_ids=list(assembled.source_case_ids),
        )
