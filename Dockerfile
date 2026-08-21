# Build: docker build -t takt-risk-layer .
# С меткой ревизии в /health (см. TAKT_BUILD_REVISION): docker build --build-arg TAKT_BUILD_REVISION=$(git rev-parse HEAD) -t takt-risk-layer .
# Run:   docker run --rm -p 8090:8090 -e TAKT_STORAGE=sqlite -e TAKT_SQLITE_PATH=data/takt.db takt-risk-layer

FROM python:3.13-slim-bookworm

ARG TAKT_BUILD_REVISION=
LABEL org.opencontainers.image.revision="${TAKT_BUILD_REVISION}"

WORKDIR /app

# PYTHONPATH обязателен. Корень проекта вычисляется от расположения модуля
# (`app.py`, `_ROOT = parents[4]`) — это верно для раскладки `src/`, но у пакета,
# установленного в `site-packages`, корнем оказывается каталог интерпретатора, и
# `config/risk_weights.yaml` там отсутствует. Контейнер падал на старте с
# FileNotFoundError; `TAKT_CONFIG` не помогал, потому что проверка требует путь
# внутри того же (ложного) корня. Каталог `/app/src` идёт в sys.path раньше
# site-packages, поэтому импортируется исходная раскладка и корнем становится `/app`.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    TAKT_BUILD_REVISION=${TAKT_BUILD_REVISION}


COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config

# extras: **metrics** — **prometheus-client** для **TAKT_METRICS** / **GET /metrics**;
# **export** — **fpdf2** для паспорта инцидента и сводки для ЛПР. Без него
# `GET /cases/{id}/export.pdf` и `/decision-brief.pdf` отвечают **501**.
RUN pip install --no-cache-dir ".[metrics,export]"

EXPOSE 8090

# Readiness: хранилище + baseline (без тела ответа — HEAD).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8090/ready', method='HEAD'), timeout=4)"

# По SIGTERM/SIGINT uvicorn ждёт завершения запросов и lifespan shutdown (закрытие SQLite, лог «TAKT API shutdown»).
CMD ["uvicorn", "takt.interface_adapters.api.main:app", "--host", "0.0.0.0", "--port", "8090", "--workers", "1", "--timeout-graceful-shutdown", "15"]
