from __future__ import annotations

from fastapi import HTTPException, Response

from takt.application.use_cases.case_scenario import build_case_scenario
from takt.infrastructure.export.siem_webhook import SiemCaseExportPayload
from takt.interface_adapters.api.dependencies import ApiContext

# Сколько последних событий брать в предысторию сценария. Запас над окном оценки
# (`AssessRiskUseCase.recent_context_event_count`, минимум 5 и окна из каталога правил):
# фикстура пишется один раз, а окно может расшириться вместе с правилами.
_SCENARIO_CONTEXT_EVENTS = 200


def register_export_routes(ctx: ApiContext) -> None:
    app = ctx.app
    facade = ctx.export_facade
    if facade is None:
        raise RuntimeError("export facade is required")

    @app.get(
        "/cases/{case_id}/scenario.json",
        tags=["Export"],
        responses={
            404: {"description": "Case not found"},
            409: {"description": "Case is not a confirmed closed case and cannot become a reference scenario"},
            501: {"description": "Event store is not configured in this deployment"},
        },
    )
    def export_case_scenario(case_id: str):
        """Закрытое подтверждённое дело — в фикстуру регресса (`docs/customer_value_map.md`, G-6)."""
        case = ctx.repo.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        store = getattr(app.state, "recent_event_store", None)
        if store is None:
            raise HTTPException(status_code=501, detail="event store is not configured")
        try:
            return build_case_scenario(
                case,
                store.events_by_ids(case.normalized_event_ids),
                # Предыстория: то, что видел движок к моменту разбора. Без неё оконные
                # инварианты при прогоне не сработают, и регресс был бы ложно-зелёным.
                context_events=store.list_recent_events(limit=_SCENARIO_CONTEXT_EVENTS),
            )
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e

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

    @app.get("/cases/{case_id}/decision-brief.pdf", tags=["Export"])
    def export_decision_brief_pdf(case_id: str):
        """Сводка для ЛПР одним листом — производный документ, состояние дела не меняет."""
        try:
            out = facade.export_decision_brief_pdf(
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
