from __future__ import annotations

import logging
import os
import socket
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI


def build_app_lifespan(
    *,
    package_version: str,
    python_runtime_tag: Callable[[], str],
    validate_startup_auth_or_raise: Callable[[], None],
    security_startup_config_snapshot: Callable[[], dict[str, Any]],
    logger: logging.Logger,
):
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        validate_startup_auth_or_raise()
        slog = getattr(app.state, "security_log", None)
        if slog is not None:
            slog.record_service_start({"config": security_startup_config_snapshot()})
        yield
        if slog is not None:
            slog.record_service_stop()
            slog.close()
        for attr in ("repo", "baseline", "audit_engagement_store", "recent_event_store", "assembly_queue"):
            obj = getattr(app.state, attr, None)
            closer = getattr(obj, "close", None)
            if callable(closer):
                closer()
        logger.info(
            "TAKT API shutdown version=%s python=%s pid=%s hostname=%s platform=%s python_executable=%s cwd=%s",
            package_version,
            python_runtime_tag(),
            os.getpid(),
            socket.gethostname(),
            sys.platform,
            sys.executable,
            os.getcwd(),
        )

    return lifespan
