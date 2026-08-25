from __future__ import annotations

import contextlib
import os
import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_Counter: Any = None
_DURATION: Any = None
_IN_PROGRESS: Any = None
_UPTIME: Any = None
_BOOT_MONOTONIC: float | None = None
_APP_FOR_RATE_LIMIT: Any = None
_RL_TRACKED_IPS: Any = None
_BUILD_INFO: Any = None


def register_prometheus_build_info(*, version: str, build_revision: str | None) -> None:
    """Один раз за процесс: **takt_build_info** с **`version`** (пакет) и **`revision`** (**`TAKT_BUILD_REVISION`** или **`unset`**)."""
    global _BUILD_INFO
    if _BUILD_INFO is not None:
        return
    from prometheus_client import Info

    rev = build_revision.strip() if isinstance(build_revision, str) and build_revision.strip() else "unset"
    _BUILD_INFO = Info(
        "takt_build",
        "Package version and optional TAKT_BUILD_REVISION (same semantics as GET /health build_revision)",
    )
    _BUILD_INFO.info({"version": version, "revision": rev})


def clear_prometheus_build_info() -> None:
    """Снять **takt_build** из глобального **REGISTRY** (между **pytest**-кейсами с разным **TAKT_BUILD_REVISION**)."""
    global _BUILD_INFO
    if _BUILD_INFO is None:
        return
    from prometheus_client import REGISTRY

    with contextlib.suppress(KeyError):
        REGISTRY.unregister(_BUILD_INFO)
    _BUILD_INFO = None


def metrics_enabled_from_env() -> bool:
    v = os.environ.get("TAKT_METRICS", "").strip().lower()
    return v in ("1", "true", "yes")


def prometheus_client_available() -> bool:
    try:
        import prometheus_client  # noqa: F401
    except ImportError:
        return False
    return True


def register_process_boot_monotonic(boot_monotonic: float) -> None:
    """Тот же момент, что **`app.state.boot_monotonic`** в **`create_app`** (для **takt_process_uptime_seconds**)."""
    global _BOOT_MONOTONIC
    _BOOT_MONOTONIC = float(boot_monotonic)


def register_prometheus_rate_limit_app(app: Any) -> None:
    """Связка с **`FastAPI`**: при **`/metrics`** обновляется **takt_rate_limit_tracked_ips** (если **`TAKT_RATE_LIMIT_PER_MIN`** > 0)."""
    global _APP_FOR_RATE_LIMIT
    _APP_FOR_RATE_LIMIT = app


def _rate_limit_per_min_positive() -> bool:
    raw = os.environ.get("TAKT_RATE_LIMIT_PER_MIN", "").strip()
    if not raw:
        return False
    try:
        return int(raw, 10) > 0
    except ValueError:
        return False


def _rate_limit_tracked_ips_gauge() -> Any:
    global _RL_TRACKED_IPS
    if _RL_TRACKED_IPS is None:
        from prometheus_client import Gauge

        _RL_TRACKED_IPS = Gauge(
            "takt_rate_limit_tracked_ips",
            "In-memory rate limiter table size (GET /health rate_limit_tracked_ips)",
        )
    return _RL_TRACKED_IPS


def _refresh_rate_limit_tracked_gauge() -> None:
    if not metrics_enabled_from_env() or not _rate_limit_per_min_positive():
        return
    app = _APP_FOR_RATE_LIMIT
    if app is None:
        return
    try:
        lock = app.state.rate_limit_lock
        store = app.state.rate_limit_buckets
        with lock:
            n = len(store)
        _rate_limit_tracked_ips_gauge().set(float(n))
    except Exception:
        return


_RL_REJECT: Any = None
_BIZ_RISK_SCORE: Any = None
_BIZ_INVARIANT_HITS: Any = None
_BIZ_DQ_DEGRADED_RATIO: Any = None
_BIZ_EVENT_TO_CASE_LATENCY: Any = None
_BIZ_CASE_MERGES: Any = None
_BIZ_DQ_TOTAL: int = 0
_BIZ_DQ_DEGRADED: int = 0


def record_rate_limit_rejection() -> None:
    """Увеличивает **takt_rate_limit_rejected_total**, если включены **`TAKT_METRICS`** и **prometheus-client**."""
    if not metrics_enabled_from_env():
        return
    try:
        global _RL_REJECT
        if _RL_REJECT is None:
            from prometheus_client import Counter

            _RL_REJECT = Counter(
                "takt_rate_limit_rejected_total",
                "HTTP 429 responses from the in-memory per-IP rate limiter (TAKT_RATE_LIMIT_PER_MIN)",
            )
        _RL_REJECT.inc()
    except ImportError:
        return


def record_business_assessment(
    *,
    risk_class: str,
    risk_score: float,
    invariant_hits: list[str],
    dq_partial: bool,
    merged_into_existing: bool,
    event_to_case_latency_seconds: float | None,
) -> None:
    """Business-level Prometheus metrics from assess/process flow."""
    if not metrics_enabled_from_env():
        return
    global _BIZ_RISK_SCORE, _BIZ_INVARIANT_HITS, _BIZ_DQ_DEGRADED_RATIO, _BIZ_EVENT_TO_CASE_LATENCY
    global _BIZ_CASE_MERGES, _BIZ_DQ_TOTAL, _BIZ_DQ_DEGRADED
    try:
        from prometheus_client import Counter, Gauge, Histogram
    except ImportError:
        return
    if _BIZ_RISK_SCORE is None:
        _BIZ_RISK_SCORE = Gauge(
            "takt_business_risk_score",
            "Latest assessed risk score by risk class",
            ("risk_class",),
        )
    if _BIZ_INVARIANT_HITS is None:
        _BIZ_INVARIANT_HITS = Counter(
            "takt_business_invariant_hits_total",
            "Total invariant hits observed in assessed cases",
            ("invariant_id",),
        )
    if _BIZ_DQ_DEGRADED_RATIO is None:
        _BIZ_DQ_DEGRADED_RATIO = Gauge(
            "takt_business_dq_degraded_ratio",
            "Ratio of assessed cases with partial/degraded data quality",
        )
    if _BIZ_EVENT_TO_CASE_LATENCY is None:
        _BIZ_EVENT_TO_CASE_LATENCY = Histogram(
            "takt_business_event_to_case_latency_seconds",
            "Latency between event observed_at and case assessment output",
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0, 30.0, 120.0),
        )
    if _BIZ_CASE_MERGES is None:
        _BIZ_CASE_MERGES = Counter(
            "takt_business_case_merges_total",
            "How many assessments were merged into an existing case",
        )

    _BIZ_RISK_SCORE.labels((risk_class or "").upper() or "UNKNOWN").set(float(risk_score))
    for hit in invariant_hits:
        if hit:
            _BIZ_INVARIANT_HITS.labels(hit).inc()
    _BIZ_DQ_TOTAL += 1
    if dq_partial:
        _BIZ_DQ_DEGRADED += 1
    _BIZ_DQ_DEGRADED_RATIO.set(float(_BIZ_DQ_DEGRADED) / float(_BIZ_DQ_TOTAL))
    if merged_into_existing:
        _BIZ_CASE_MERGES.inc()
    if event_to_case_latency_seconds is not None and event_to_case_latency_seconds >= 0.0:
        _BIZ_EVENT_TO_CASE_LATENCY.observe(event_to_case_latency_seconds)


_BIZ_CASE_TO_DECISION: Any = None
_BIZ_VERDICTS: Any = None
_BIZ_UNDET_RESOLVED: Any = None
_BIZ_FORENSIC_BUNDLES: Any = None

_TRIAD = ("LEG", "ILLEG", "UNDET")


def _triad_label(verdict: str) -> str:
    """Метка триады. Всё непонятное считается неопределённым, а не теряется."""
    value = (verdict or "").strip().upper()
    return value if value in _TRIAD else "UNDET"


def record_business_decision(
    *,
    verdict: str,
    next_status: str,
    seconds_to_first_decision: float | None,
) -> None:
    """Метрики пути клиента в момент решения по делу.

    Отвечают на вопрос «стало ли лучше»: сколько прошло от заведения дела до решения и в каком
    соотношении расходятся вердикты триады. Разрыв G-4 из ``docs/customer_value_map.md``.

    Время берётся из журнала дела (создание → первое решение), а не из момента скрапа: иначе
    показатель мерил бы работу Prometheus, а не работу аналитика.
    """
    if not metrics_enabled_from_env():
        return
    global _BIZ_CASE_TO_DECISION, _BIZ_VERDICTS
    try:
        from prometheus_client import Counter, Histogram
    except ImportError:
        return
    if _BIZ_CASE_TO_DECISION is None:
        _BIZ_CASE_TO_DECISION = Histogram(
            "takt_business_case_to_decision_seconds",
            "Time from case creation to the first operator decision, taken from the case journal",
            buckets=(60.0, 300.0, 900.0, 1800.0, 3600.0, 4 * 3600.0, 8 * 3600.0, 24 * 3600.0, 3 * 24 * 3600.0),
        )
    if _BIZ_VERDICTS is None:
        _BIZ_VERDICTS = Counter(
            "takt_business_verdicts_total",
            "Decisions by triad verdict (LEG / ILLEG / UNDET) and resulting case status",
            ("verdict", "status"),
        )
    _BIZ_VERDICTS.labels(_triad_label(verdict), (next_status or "").upper() or "UNKNOWN").inc()
    if seconds_to_first_decision is not None and seconds_to_first_decision >= 0.0:
        _BIZ_CASE_TO_DECISION.observe(seconds_to_first_decision)


def record_business_verdict_transition(*, prev: str, next_value: str) -> None:
    """Снятая неопределённость: дело вышло из ``UNDET`` после добора контекста.

    Главный показатель обещания продукта — не «сколько сработало», а «сколько неопределённых
    случаев доведено до определённого вывода».
    """
    if not metrics_enabled_from_env():
        return
    global _BIZ_UNDET_RESOLVED
    try:
        from prometheus_client import Counter
    except ImportError:
        return
    if _BIZ_UNDET_RESOLVED is None:
        _BIZ_UNDET_RESOLVED = Counter(
            "takt_business_undet_resolved_total",
            "Cases moved out of the undetermined verdict after organizational context was added",
            ("resolved_to",),
        )
    was_undetermined = _forensic_triad(prev) == "UNDET"
    resolved_to = _forensic_triad(next_value)
    if was_undetermined and resolved_to != "UNDET":
        _BIZ_UNDET_RESOLVED.labels(resolved_to).inc()


def record_business_forensic_bundle(*, status: str) -> None:
    """Доказательные пакеты по исходу: собран, проверен, отклонён."""
    if not metrics_enabled_from_env():
        return
    global _BIZ_FORENSIC_BUNDLES
    try:
        from prometheus_client import Counter
    except ImportError:
        return
    if _BIZ_FORENSIC_BUNDLES is None:
        _BIZ_FORENSIC_BUNDLES = Counter(
            "takt_business_forensic_bundles_total",
            "Forensic evidence bundles by outcome (built / verified / rejected)",
            ("status",),
        )
    _BIZ_FORENSIC_BUNDLES.labels((status or "unknown").strip().lower() or "unknown").inc()


_FORENSIC_TRIAD_BY_VALUE = {
    "легитимное": "LEG",
    "нелегитимное": "ILLEG",
    "неопределённое": "UNDET",
}


def _forensic_triad(value: str) -> str:
    return _FORENSIC_TRIAD_BY_VALUE.get((value or "").strip().lower(), "UNDET")


def _http_requests_counter() -> Any:
    global _Counter
    if _Counter is None:
        from prometheus_client import Counter

        _Counter = Counter(
            "takt_http_requests_total",
            "Total HTTP requests",
            ("method", "route", "status_class"),
        )
    return _Counter


def _http_request_duration_histogram() -> Any:
    global _DURATION
    if _DURATION is None:
        from prometheus_client import Histogram

        _DURATION = Histogram(
            "takt_http_request_duration_seconds",
            "HTTP request latency in seconds",
            ("method", "route", "status_class"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )
    return _DURATION


def _in_progress_gauge() -> Any:
    global _IN_PROGRESS
    if _IN_PROGRESS is None:
        from prometheus_client import Gauge

        _IN_PROGRESS = Gauge(
            "takt_http_requests_in_progress",
            "HTTP requests currently being processed inside this process",
        )
    return _IN_PROGRESS


def _process_uptime_gauge() -> Any:
    global _UPTIME
    if _UPTIME is None:
        from prometheus_client import Gauge

        _UPTIME = Gauge(
            "takt_process_uptime_seconds",
            "Seconds since FastAPI app creation (time.monotonic() − boot), same basis as GET /health uptime_seconds",
        )
    return _UPTIME


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None) if route is not None else None
    return str(path) if path else "unmatched"


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Счётчик, гистограмма латентности (labels: method, route, status_class) и gauge «в работе» без labels."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            prog = _in_progress_gauge()
            ctr = _http_requests_counter()
            hist = _http_request_duration_histogram()
        except ImportError:
            return await call_next(request)

        t0 = time.perf_counter()
        prog.inc()
        try:
            response = await call_next(request)
            elapsed = time.perf_counter() - t0
            route = _route_template(request)
            cls = f"{response.status_code // 100}xx"
            method = request.method.upper()
            ctr.labels(method, route, cls).inc()
            hist.labels(method, route, cls).observe(elapsed)
            return response
        finally:
            prog.dec()


def prometheus_metrics_response() -> Response:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    boot = _BOOT_MONOTONIC
    if boot is not None:
        _process_uptime_gauge().set(time.monotonic() - boot)
    _refresh_rate_limit_tracked_gauge()

    r = Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
    r.headers["Cache-Control"] = "no-store, private"
    return r
