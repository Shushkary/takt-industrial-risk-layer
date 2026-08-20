from __future__ import annotations

from fastapi import HTTPException, Query

from takt.application.use_cases.simulate_incident import SimulateIncidentUseCase
from takt.interface_adapters.api.dependencies import ApiContext


def register_simulation_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/cases/{case_id}/simulation", tags=["Cases"])
    def case_simulation(
        case_id: str,
        seconds_per_action: float | None = Query(
            default=None,
            ge=0.0,
            le=3600.0,
            description=(
                "Коэффициент модельной оценки времени, секунд на одно действие. Значения по"
                " умолчанию нет: в методике измерения он не задан и не измерялся. Без него"
                " отдаётся только число действий."
            ),
        ),
    ):
        """Хронология цепочки атаки с объяснением отбора и метриками трудоёмкости."""
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id}")
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            raise HTTPException(
                status_code=409,
                detail="симуляция требует постоянного хранилища событий (TAKT_STORAGE=sqlite)",
            )
        use_case = SimulateIncidentUseCase(events=store)
        return use_case.execute(case, seconds_per_action=seconds_per_action)
