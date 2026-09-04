from __future__ import annotations

from fastapi import HTTPException

from takt.domain.entities.event import EventSource
from takt.domain.services.invariant_feedback import invariant_feedback
from takt.infrastructure.importers.csv_events import load_normalized_from_csv
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.analytics import BacktestFixtureResponse


def register_analytics_routes(ctx: ApiContext) -> None:
    app = ctx.app

    @app.get("/analytics/invariant-feedback", tags=["Analytics"])
    def invariant_feedback_report():
        """Разметка аналитика по инвариантам и предложения по правилам.

        Только чтение. Продукт ничего не применяет сам: автоматический пересчёт сделал бы
        вердикт невоспроизводимым (`docs/customer_value_map.md`, G-2).
        """
        return invariant_feedback(
            ctx.repo.list_all(),
            weights_version=ctx.risk_weights_version(),
        ).to_dict()

    @app.post("/backtest/fixture", response_model=BacktestFixtureResponse, tags=["Analytics"])
    def backtest_fixture():
        # Датасет лежит в `config/`, а не в `tests/`: каталог тестов исключён `.dockerignore`,
        # и эндпойнт, описанный в `docs/api_reference.md`, отвечал в образе 500 «fixture missing»
        # при любой конфигурации. `config/` копируется в образ — см. `Dockerfile`.
        fx = ctx.root / "config" / "demo" / "plc_polling_demo.csv"
        if not fx.is_file():
            raise HTTPException(status_code=500, detail="fixture missing")
        events = load_normalized_from_csv(fx, source=EventSource.PLC_POLLING)
        if ctx.backtest_uc is None:
            raise HTTPException(status_code=500, detail="backtest use case unavailable")
        report = ctx.backtest_uc.execute(
            events,
            graph_edges=list(ctx.demo_edges),
            polling_intervals_us=[1000.0, 1000.0, 4670.0, 21_800.0],
            trust_by_source=ctx.trust_by_source,
        )
        return BacktestFixtureResponse(
            events_processed=report.events_processed,
            cases_created=report.cases_created,
            merges=report.merges,
            risk_class_histogram=report.risk_class_histogram,
        )
