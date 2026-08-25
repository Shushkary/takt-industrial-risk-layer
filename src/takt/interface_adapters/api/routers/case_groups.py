"""Сведённая очередь: `GET /cases/groups`.

Вынесено отдельным модулем не ради чистоты, а по границе, которую держит
`tests/test_backend_architecture_guard.py`: роутер длиннее 300 строк перестаёт читаться.

Порядок регистрации важен: `/cases/groups` обязан объявляться раньше `/cases/{case_id}`,
иначе `groups` попадёт в путь как идентификатор дела и вернёт 404.
"""

from __future__ import annotations

from fastapi import HTTPException, Query, Response

from takt.application.use_cases.cases_query_service import CasesListQuery
from takt.interface_adapters.api.dependencies import ApiContext, require
from takt.interface_adapters.api.schemas.cases import CaseGroupOut


def register_case_group_routes(ctx: ApiContext) -> None:
    app = ctx.app
    query_service = require(ctx.cases_query_service, "cases_query_service")

    @app.get(
        "/cases/groups",
        response_model=list[CaseGroupOut],
        tags=["Cases"],
        responses={
            200: {
                "description": "Однотипные дела, сведённые в строки очереди",
                "headers": {
                    "X-Total-Count": {
                        "description": "Число групп до среза по offset/limit",
                        "schema": {"type": "string", "example": "37"},
                    },
                    "X-Total-Cases": {
                        "description": "Число дел, попавших в группы (после фильтров)",
                        "schema": {"type": "string", "example": "284"},
                    },
                },
            }
        },
    )
    def list_case_groups(
        response: Response,
        status: str | None = Query(default=None, description="NEW, TRIAGE, …"),
        risk_classes: str | None = Query(default=None, description="Несколько классов через запятую"),
        primary_asset_id: str | None = Query(default=None, description="Точное совпадение primary_asset_id"),
        title_contains: str | None = Query(default=None, description="Подстрока в title кейса"),
        case_id_prefix: str | None = Query(default=None, description="Префикс case_id"),
        trigger_operation_contains: str | None = Query(default=None, description="Подстрока в trigger_operation"),
        group_by: str = Query(
            default="asset",
            description="asset — актив, операция и класс (какой узел шумит); operation — операция и класс (какое правило шумит)",
        ),
        limit: int | None = Query(default=None, ge=1, le=1000, description="Ограничить число групп"),
        offset: int = Query(default=0, ge=0, description="Смещение после сортировки"),
    ):
        """Очередь, сведённая по однотипности: актив, операция, класс риска.

        Фильтры совпадают с `GET /cases`, чтобы отбор и группировка не расходились.
        Группировка ничего не меняет в делах: каждое дело остаётся отдельным.
        """
        try:
            result = query_service.group_cases(
                CasesListQuery(
                    status=status,
                    risk_classes=risk_classes,
                    primary_asset_id=primary_asset_id,
                    title_contains=title_contains,
                    case_id_prefix=case_id_prefix,
                    trigger_operation_contains=trigger_operation_contains,
                    offset=offset,
                    limit=limit,
                ),
                group_by=group_by,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        response.headers["X-Total-Count"] = str(result.total_groups)
        response.headers["X-Total-Cases"] = str(result.total_cases)
        return [
            CaseGroupOut(
                key=group.key,
                primary_asset_id=group.primary_asset_id,
                assets=group.assets,
                trigger_operation=group.trigger_operation,
                risk_class=group.risk_class,
                cases=group.cases,
                events=group.events,
                max_risk_score=group.max_risk_score,
                top_case_id=group.top_case_id,
                first_created_at=group.first_created_at,
                last_created_at=group.last_created_at,
                by_status=group.by_status,
            )
            for group in result.items
        ]
