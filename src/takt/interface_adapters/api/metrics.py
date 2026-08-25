from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import FastAPI, Response


def register_prometheus_if_enabled(
    application: FastAPI,
    *,
    package_version: str,
    build_revision_from_env: Callable[[], str | None],
    logger: logging.Logger,
) -> None:
    from takt.infrastructure.http.prometheus_metrics import (
        PrometheusMetricsMiddleware,
        metrics_enabled_from_env,
        prometheus_client_available,
        prometheus_metrics_response,
        register_process_boot_monotonic,
        register_prometheus_build_info,
        register_prometheus_rate_limit_app,
    )

    application.state.prometheus_metrics_active = False
    if not metrics_enabled_from_env():
        return
    if not prometheus_client_available():
        logger.warning("TAKT_METRICS is set but prometheus-client is not installed; /metrics is disabled")
        return
    register_process_boot_monotonic(float(application.state.boot_monotonic))
    register_prometheus_build_info(
        version=package_version,
        build_revision=build_revision_from_env(),
    )
    register_prometheus_rate_limit_app(application)
    application.add_middleware(PrometheusMetricsMiddleware)
    application.state.prometheus_metrics_active = True

    @application.get(
        "/metrics",
        tags=["System"],
        summary="Метрики Prometheus",
        response_class=Response,
    )
    def prometheus_metrics_endpoint():
        return prometheus_metrics_response()

    @application.head(
        "/metrics",
        tags=["System"],
        summary="HEAD /metrics",
    )
    def prometheus_metrics_head():
        response = Response()
        response.headers["Cache-Control"] = "no-store, private"
        return response
