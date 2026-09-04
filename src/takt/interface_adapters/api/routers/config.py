"""Веса оценки риска: чтение и правка из окна аналитика.

Веса — конфигурация, а не состояние обучаемой модели: автоматического пересчёта по
накопленной истории в продукте нет намеренно (`docs/customer_value_map.md`, G-2). Правит их
человек, и до сих пор единственным способом была правка `config/risk_weights.yaml` на
сервере. Эти маршруты дают тот же механизм, а не другой: тот же файл, та же метка версии,
та же роль администратора.

Правка меняет оценку всех последующих дел, но не переписывает уже собранные: в отчёте
разметки стоит версия конфигурации, против которой он посчитан. Поэтому версия поднимается
при каждой записи, а причина правки обязательна и уходит в журнал безопасности.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from takt.infrastructure.config.weights_writer import (
    EDITABLE_THRESHOLDS,
    EDITABLE_WEIGHTS,
    WeightsRewriteError,
    next_version,
    read_source,
    rewrite_risk_weights,
    write_source,
)
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.config import (
    RiskThresholdSet,
    RiskWeightsBody,
    RiskWeightsResponse,
    RiskWeightsSet,
)


def register_config_routes(ctx: ApiContext) -> None:
    app = ctx.app

    def _thresholds() -> dict[str, Any]:
        raw = ctx.risk_weights.get("risk_class_thresholds")
        return raw if isinstance(raw, dict) else {}

    def _snapshot() -> RiskWeightsResponse:
        thresholds = _thresholds()
        path = ctx.risk_weights_path
        try:
            shown_path = path.relative_to(ctx.root).as_posix()
        except ValueError:
            shown_path = path.as_posix()
        return RiskWeightsResponse(
            version=ctx.risk_weights_version(),
            weights=RiskWeightsSet(**{name: float(ctx.risk_weights.get(name, 0.0)) for name in EDITABLE_WEIGHTS}),
            thresholds=RiskThresholdSet(**{name: float(thresholds.get(name, 0.0)) for name in EDITABLE_THRESHOLDS}),
            config_path=shown_path,
            editable=path.is_file(),
        )

    @app.get("/config/risk-weights", response_model=RiskWeightsResponse, tags=["Config"])
    def read_risk_weights() -> RiskWeightsResponse:
        """Действующие веса факторов риска, пороги классов и версия конфигурации."""
        return _snapshot()

    @app.put("/config/risk-weights", response_model=RiskWeightsResponse, tags=["Config"])
    def write_risk_weights(body: RiskWeightsBody, request: Request) -> RiskWeightsResponse:
        """Записывает набор в `config/risk_weights.yaml` и поднимает версию конфигурации.

        Правится только то, что названо: комментарии файла и остальные разделы —
        корреляция, хранилище, каталог инвариантов — остаются как были.
        """
        path = ctx.risk_weights_path
        if not path.is_file():
            raise HTTPException(status_code=409, detail="risk weights config file is not available")

        weights = body.weights.model_dump()
        thresholds = body.thresholds.model_dump()
        version = next_version(ctx.risk_weights_version(), ctx.clock.now_utc().date())
        try:
            source, newline = read_source(path)
            updated = rewrite_risk_weights(
                source,
                weights=weights,
                thresholds=thresholds,
                version=version,
            )
        except WeightsRewriteError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except OSError as error:
            raise HTTPException(status_code=409, detail=f"risk weights config is not readable: {error}") from error

        try:
            write_source(path, updated, newline)
        except OSError as error:
            raise HTTPException(status_code=409, detail=f"risk weights config is not writable: {error}") from error

        # Файл записан — приводим действующую конфигурацию к нему. Словарь правится на месте:
        # ссылку на него держат и `app.state.risk_weights`, и точки входа CLI, и подмена
        # объекта оставила бы часть читателей на старом наборе.
        ctx.risk_weights.update(weights)
        ctx.risk_weights.setdefault("risk_class_thresholds", {})
        thresholds_section = ctx.risk_weights["risk_class_thresholds"]
        if isinstance(thresholds_section, dict):
            thresholds_section.update(thresholds)
        else:  # pragma: no cover - файл прошёл разбор, секция обязана быть отображением
            ctx.risk_weights["risk_class_thresholds"] = dict(thresholds)
        ctx.risk_weights["version"] = version
        app.state.risk_weights_version = version

        security_log = getattr(app.state, "security_log", None)
        if security_log is not None:
            security_log.record(
                "risk_weights_changed",
                {
                    "actor_id": str(getattr(request.state, "takt_actor_id", "") or ""),
                    "version": version,
                    "reason": body.reason,
                    **{f"weight_{name}": weights[name] for name in EDITABLE_WEIGHTS},
                    **{f"threshold_{name}": thresholds[name] for name in EDITABLE_THRESHOLDS},
                },
            )

        return _snapshot()
