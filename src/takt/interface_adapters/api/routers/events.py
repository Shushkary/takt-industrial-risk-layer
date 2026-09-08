from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException, Query, Response

from takt.application.use_cases.case_scenario import event_to_dict
from takt.domain.entities.event import NormalizedEvent
from takt.interface_adapters.api.dependencies import ApiContext


def _event_dict(event: NormalizedEvent) -> dict:
    """Тот же вид, что уходит в фикстуру сценария — одно представление на оба выхода."""
    return event_to_dict(event)


def register_event_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/events/search", tags=["Events"])
    def search_events(
        response: Response,
        source: str | None = None,
        observed_from: datetime | None = None,
        observed_to: datetime | None = None,
        host_id: str | None = None,
        user_id: str | None = None,
        process_id: str | None = None,
        address: str | None = None,
        artifact_type: str | None = None,
        artifact_value: str | None = None,
        text: str | None = None,
        exclude_case_id: str | None = Query(
            default=None,
            description=(
                "Исключить события этого дела из выдачи и из X-Total-Count. "
                "Нужен поиску кандидатов на присоединение: исключение после среза страницы "
                "теряет кандидатов за её пределами"
            ),
        ),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
    ):
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            response.headers["X-Total-Count"] = "0"
            return []
        # Состав дела спрашивается у продукта: перечислять полсотни идентификаторов в запросе
        # окну нечем, а исключение после выдачи теряет кандидатов за пределами страницы.
        # Неизвестное дело — отказ, а не молчаливый поиск без исключения: опечатка в
        # идентификаторе иначе вернула бы события самого дела как кандидатов.
        exclude_event_ids: list[str] = []
        if exclude_case_id:
            case = ctx.repo.get(exclude_case_id)
            if case is None:
                raise HTTPException(status_code=404, detail=f"unknown case: {exclude_case_id}")
            exclude_event_ids = list(case.normalized_event_ids)
        events, total = store.search_events(
            source=source, observed_from=observed_from, observed_to=observed_to,
            host_id=host_id, user_id=user_id, process_id=process_id, address=address,
            artifact_type=artifact_type, artifact_value=artifact_value, text=text,
            exclude_event_ids=exclude_event_ids,
            offset=offset, limit=limit,
        )
        response.headers["X-Total-Count"] = str(total)
        return [_event_dict(event) for event in events]
