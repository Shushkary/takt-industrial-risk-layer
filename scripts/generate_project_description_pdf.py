#!/usr/bin/env python3
"""Полное расширенное описание проекта в PDF (кириллица через TTF)."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUTPUT = DOCS / "Описание_проекта_TAKT_Industrial_Risk_Layer.pdf"


def _find_unicode_font() -> str | None:
    candidates = [
        ROOT / "assets" / "fonts" / "DejaVuSans.ttf",
        ROOT / "assets" / "fonts" / "Arial.ttf",
        ROOT / "assets" / "fonts" / "LiberationSans-Regular.ttf",
    ]
    env = __import__("os").environ.get("TAKT_PROJECT_DESC_FONT", "").strip()
    if env:
        candidate = Path(env).expanduser()
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        p = candidate.resolve()
        try:
            p.relative_to(ROOT.resolve())
        except ValueError:
            return None
        if p.is_file():
            return str(p)
    for p in candidates:
        if p.is_file():
            return str(p.resolve())
    return None


def _version() -> str:
    try:
        import tomllib

        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return str(data.get("project", {}).get("version", "?"))
    except Exception:
        return "?"


def _invariant_catalog_lines() -> list[str]:
    """Синхронизировано с takt.domain.invariants.catalog."""
    src = ROOT / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from takt.domain.invariants.catalog import INVARIANT_RECORDS

    lines: list[str] = []
    for r in INVARIANT_RECORDS:
        lines.append(f"• {r.id}  [{r.block_key}]  —  {r.title_ru}")
    return lines


def main() -> int:
    try:
        from fpdf import FPDF
    except ImportError:
        print("Установите: pip install 'takt-industrial-risk-layer[export]'", file=sys.stderr)
        return 1

    font_path = _find_unicode_font()
    ver = _version()
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    class TaktDocPDF(FPDF):
        def __init__(self, body_font: str) -> None:
            super().__init__()
            self._body = body_font

        def footer(self) -> None:
            self.set_y(-12)
            self.set_font(self._body, "", 8)
            self.set_text_color(90, 90, 90)
            self.cell(
                0,
                8,
                f"ТАКТ Industrial Risk Layer · v{ver} · стр. {self.page_no()}",
                align="C",
            )
            self.set_text_color(0, 0, 0)

    pdf = TaktDocPDF("DescUni" if font_path else "Helvetica")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(left=18, top=18, right=18)

    if font_path:
        pdf.add_font("DescUni", "", font_path)
        body = "DescUni"
    else:
        body = "Helvetica"
        print(
            "Предупреждение: TTF для кириллицы не найден; задайте TAKT_PROJECT_DESC_FONT.",
            file=sys.stderr,
        )

    def p(text: str, size: int = 10, lh: float = 5.4) -> None:
        pdf.set_font(body, "", size)
        pdf.multi_cell(0, lh, text, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def heading(text: str, size: int = 13) -> None:
        pdf.ln(2)
        pdf.set_font(body, "", size)
        pdf.multi_cell(0, 6.5, text, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(0.5)

    def subheading(text: str) -> None:
        pdf.set_font(body, "", 11)
        pdf.multi_cell(0, 5.5, text, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(0.5)

    # --- title page ---
    pdf.add_page()
    pdf.set_font(body, "", 22)
    pdf.multi_cell(0, 11, "Полное описание проекта", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(body, "", 17)
    pdf.multi_cell(0, 9, "ТАКТ Industrial Risk Layer (MVP)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font(body, "", 10)
    pdf.set_text_color(75, 75, 75)
    p(f"Версия пакета: {ver}", size=10)
    p(f"Документ сформирован (UTC): {now}", size=10)
    p("Репозиторий: .", size=10)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    pdf.set_font(body, "", 10)
    pdf.multi_cell(
        0,
        5.4,
        "Документ объединяет сведения из README, docs/product_boundary.md, "
        "конфигурации config/risk_weights.yaml и структуры исходного кода. "
        "Назначение — дать целостную картину продукта для архитекторов, "
        "инженеров эксплуатации и аналитиков ИБ.",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(6)
    heading("Структура документа")
    toc = [
        "1. Контекст и нормативная база (ТЗ MVP 2.0)",
        "2. Цели, зона ответственности и границы продукта",
        "3. Архитектура: слои L1–L4 и правила зависимостей",
        "4. Доменный слой L1: сущности, движки, инварианты",
        "5. Прикладной слой L2: сценарии использования",
        "6. REST API: обзор маршрутов и семантика",
        "7. Модель кейса, очередь событий и слияние (alert fatigue)",
        "8. Конфигурация YAML и переменные окружения",
        "9. Хранилища, персистентность SQLite",
        "10. Экспорт, интеграции SIEM, backtest",
        "11. Наблюдаемость, безопасность HTTP, лимиты",
        "12. Сборка, Docker, Kubernetes",
        "13. Качество: тесты, CI, SBOM, extras пакета",
        "14. Направления дальнейшей разработки",
    ]
    for line in toc:
        p(line, size=10, lh=5.2)

    # --- section 1 ---
    pdf.add_page()
    heading("1. Контекст и нормативная база")
    p(
        "Проект реализует автономный аналитический компонент экосистемы ТАКТ — "
        "«Industrial Risk Layer» для критической информационной инфраструктуры и АСУ ТП. "
        "Концепция и требования выведены из ТЗ MVP 2.0 (слои L1–L5, 25 инвариантов, "
        "Chaos Predictor с целевой константой Фейгенбаума δ≈4.669, Causal Mesh, Risk/XAI). "
        "Сопутствующие материалы спринтов и чек-листов размещаются в каталоге docs/ "
        "(извлечённые тексты из исходных DOCX). Кодовая база следует этим документам на уровне MVP."
    )

    heading("2. Цели, зона ответственности и границы продукта")
    subheading("В зоне ответственности")
    p(
        "Приём и нормализация событий из JSON/CSV-конвейеров. Оценка качества данных (DQ), "
        "учёт контекста (заявки, окна работ, фазы), ритма опроса и топологии (Causal Mesh). "
        "Агрегация факторов в индекс риска и формирование объяснимых выводов (XAI) без «чёрного ящика». "
        "Управление кейсами с участием человека (HITL), экспорт отчётов и карточек, воспроизводимый backtest."
    )
    subheading("Строгие запреты")
    p(
        "ТАКТ не является SIEM, XDR, СКЗИ, системой активного управления или автоматической блокировки. "
        "В слое L1 Domain запрещены криптография, вызовы ОС/сети, ORM, FastAPI и прочая инфраструктура. "
        "MVP не выполняет активное управление оборудованием АСУ ТП."
    )
    subheading("Задел")
    p(
        "Порты на границах L2/L4 допускают подключение постквантовой криптографии и внешних адаптеров "
        "без изменения доменных сущностей и правил."
    )

    heading("3. Архитектура: слои L1–L4 и правила зависимостей")
    p(
        "L1 Domain — каталог src/takt/domain: сущности (событие, кейс, актив, заявки), "
        "движки риска, данных, топологии, XAI, Chaos Predictor, контекст и фазы; "
        "каталог 25 инвариантов и модуль invariants/evaluator с расширенными правилами; "
        "порты репозитория кейсов и baseline. Слой не импортирует FastAPI, uvicorn и инфраструктуру."
    )
    p(
        "L2 Application — src/takt/application/use_cases: оркестрация домена без HTTP. "
        "Контракт import-linter: прикладной слой не зависит от infrastructure и interface_adapters."
    )
    p(
        "L3 Interface adapters — src/takt/interface_adapters/api: приложение FastAPI, маршруты, "
        "валидация входа, отображение доменных объектов в DTO ответов."
    )
    p(
        "L4 Infrastructure — src/takt/infrastructure: загрузка YAML, фабрики хранилищ, SQLite, "
        "импорт CSV, экспорт PDF (fpdf2), webhook SIEM (httpx), HTTP middleware "
        "(идентификатор запроса, gzip, CORS, HSTS, rate limit, лимит тела, метрики Prometheus)."
    )

    heading("4. Доменный слой L1: сущности, движки, инварианты")
    subheading("Ключевые модули")
    p(
        "engines: risk_engine — агрегация факторов; data_quality — DQ и частичная наблюдаемость; "
        "causal_mesh — граф и паттерны (в т.ч. обход jump-сервера); chaos_predictor — связь с ритмом опроса; "
        "context_matcher, phase_time_tagger — контекст ТО и временные фазы; "
        "xai — человекочитаемые объяснения; alert_fatigue — ключ слияния burst_fingerprint "
        "(source|asset_id|operation), раздельные кейсы при разных source."
    )
    subheading("Каталог из 25 инвариантов (id, block_key, заголовок)")
    for line in _invariant_catalog_lines():
        p(line, size=9, lh=4.9)
    p(
        "Ключи блоков для фильтрации API: rhythm, topology, identity, physics, integrity, data_hitl. "
        "GET /invariants отдаёт полный справочник с метаданными для UI и интеграций."
    )

    heading("5. Прикладной слой L2: сценарии использования")
    p(
        "AssessRiskUseCase — оценка риска с учётом InvariantContext из конфигурации и последних событий.\n"
        "ProcessEventUseCase — ingest одного события или элемент пакетной обработки: обогащение, DQ, "
        "инварианты, обновление/создание кейса.\n"
        "SubmitCaseDecisionUseCase — смена статуса кейса; при EXPECTED_BEHAVIOR обновляется baseline пар актив+операция.\n"
        "RunBacktestUseCase — прогон фикстуры (например config/demo/plc_polling_demo.csv) с теми же рёбрами графа "
        "и ingest_trust, что у работающего API."
    )

    heading("6. REST API: обзор маршрутов и семантика")
    subheading("Система и документация")
    p(
        "GET/HEAD /live — liveness без обращения к БД. GET/HEAD /ready — readiness: чтение хранилища кейсов и baseline "
        "(503 при сбое). GET/HEAD /health — расширенная диагностика (версия пакета, Python, лимиты, SQLite, метрики, CORS, "
        "HSTS, gzip, rate limit, openapi servers, счётчики кейсов и т.д.). "
        "GET/HEAD /metrics — текст Prometheus при TAKT_METRICS и установленном prometheus-client. "
        "GET/HEAD /openapi.json, UI /docs и /redoc. Заголовки X-Request-ID, X-Process-Time; опционально API-ключ X-TAKT-API-Key."
    )
    subheading("Каталог и демо-данные")
    p(
        "GET /invariants — все InvariantId с фильтром ?block_key=. GET /catalog/event-sources — допустимые source и коэффициенты ingest_trust. "
        "GET /topology/demo-graph — jump_host, plc_hosts, demo_graph_edges, признак has_jump_bypass_pattern."
    )
    subheading("Ingest и оценка")
    p(
        "POST /assess — оценка по демо-телу (PLC_POLLING): опционально без сохранения (**persist_case**); "
        "слияние по burst_fingerprint при сохранении. Устаревший путь POST /assess/demo. "
        "POST /events — одно событие (окно последних событий в памяти до 64, в контекст оценки — последние 5). "
        "POST /events/batch — до 100 событий за запрос, ответ с итогами по позициям. "
        "Нормализация IEC-104 полей задаётся iec104_type_aliases и iec104_disallowed_type_ids в YAML."
    )
    subheading("Кейсы")
    p(
        "GET /cases — список с богатым набором фильтров (источник, время создания, класс риска, score, "
        "число событий, текстовые подстроки, инварианты, DQ и др.), сортировка, limit до 1000, X-Total-Count, Link rel=next/prev. "
        "GET /cases/{id} — полная карточка. GET /cases/stats — агрегаты по статусам, классам, источникам, DQ. "
        "GET /cases/export/full.json и POST /cases/import/full.json — выгрузка/импорт до 10000 карточек (транзакция в SQLite)."
    )
    subheading("Решение по кейсу и качество данных")
    p(
        "POST /cases/{id}/decision — JSON со статусом (TRIAGE и др.). GET /data-quality — снимок после последней оценки/ingest."
    )
    subheading("Экспорт и интеграции")
    p(
        "GET /cases/{id}/export.pdf — «паспорт инцидента»; при export.pdf_unicode_font в YAML указан путь к .ttf, "
        "в PDF корректна кириллица в XAI. GET /cases/{id}/export/siem.json — полезная нагрузка для SIEM "
        "(last_event_source, invariant_hits, invariant_details, data_quality). "
        "POST /integrations/siem/forward и .../forward/async — отправка в webhook по allowlist из siem_webhook; "
        "при пустом allowlist разрешены только loopback URL."
    )
    subheading("Аналитика")
    p(
        "POST /backtest/fixture — прогон демо CSV с конфигурацией API. Маршруты в Swagger сгруппированы по тегам: "
        "System, Catalog, Ingest, Cases, Export, Integrations, Analytics."
    )

    heading("7. Модель кейса, очередь событий и слияние")
    p(
        "Кейс накапливает историю событий, срабатывания инвариантов, risk_score и risk_class (LOW/MEDIUM/HIGH/CRITICAL), "
        "XAI-summary и показатели DQ. Слияние при совпадающем burst_fingerprint объединяет invariant_hits, "
        "берёт максимум risk_score, при равенстве — более высокий risk_class, обновляет пояснения с последнего события. "
        "Разные source при той же паре актив+операция дают разные кейсы — отражение доверия к каналу данных."
    )

    heading("8. Конфигурация YAML и переменные окружения")
    subheading("Файл config/risk_weights.yaml")
    p(
        "Веса факторов Risk = F(R, G, C, U, DQ): rhythm, graph, context, user, data_quality; пороги mandelbrot_entropy_cap, "
        "dq_degraded_threshold, feigenbaum_target, eps_soft_cap. Секции topology, invariants, enrichment, ingest_trust.by_source, "
        "storage (backend memory|sqlite, sqlite_path), siem_webhook (allowed_url_prefixes, retries, backoff_sec), export.pdf_unicode_font."
    )
    subheading("Переменные окружения (см. README и .env.example)")
    p(
        "TAKT_CONFIG, TAKT_STORAGE, TAKT_SQLITE_PATH, TAKT_SQLITE_BUSY_TIMEOUT_MS, TAKT_API_KEY, TAKT_CORS_ORIGINS, "
        "TAKT_HSTS_MAX_AGE, TAKT_HSTS_PRELOAD, TAKT_LOG_LEVEL, TAKT_REQUEST_ID_HEADER, TAKT_SLOW_REQUEST_LOG_SEC, "
        "TAKT_MAX_REQUEST_BODY_MB, TAKT_RATE_LIMIT_PER_MIN, TAKT_RATE_LIMIT_MAX_IPS, TAKT_RATE_LIMIT_IP_HEADER, "
        "TAKT_CATALOG_CACHE_MAX_AGE_SEC, TAKT_METRICS, TAKT_OPENAPI_SERVER_URL, TAKT_BUILD_REVISION. "
        "Uvicorn ≥0.30 поддерживает --env-file .env для локального запуска."
    )

    heading("9. Хранилища и персистентность SQLite")
    p(
        "Режим memory по умолчанию: кейсы и expected_behavior в процессе; окно последних событий всегда в RAM. "
        "Режим sqlite: файловая БД с WAL, PRAGMA busy_timeout (по умолчанию 5000 мс, переопеределение через env), "
        "таблицы кейсов, baseline и app_metadata (schema_version). При остановке приложения — корректное закрытие "
        "и wal_checkpoint. Импорт полного JSON выполняется в одной транзакции."
    )

    heading("10. Экспорт, интеграции SIEM, backtest")
    p(
        "PDF строится fpdf2; без Unicode-шрифта поля с кириллицей деградируют в latin-1 substitution. "
        "Webhook использует политику URL из конфигурации и ретраи с backoff. Backtest воспроизводит демо-поток для валидации "
        "логики без продакшен-трафика."
    )

    heading("11. Наблюдаемость, безопасность HTTP, лимиты")
    p(
        "Метрики: takt_http_requests_total, takt_http_request_duration_seconds, takt_build_info, при лимите — отказов и tracked IPs. "
        "Gzip ответов от порога 512 байт. Security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy; "
        "опционально HSTS. Rate limit по IP (или доверенному заголовку) в минуту; публичные пути /live, /ready, /health, /metrics, "
        "документация — без квоты. Ответы 403/411/413/429 с телом MiddlewareErrorJson и request_id. "
        "Кэш Cache-Control для каталожных GET; /cases — private, no-store."
    )

    heading("12. Сборка, Docker, Kubernetes")
    p(
        "Локально: pip install -e \".[dev]\", pytest, uvicorn takt.interface_adapters.api.main:app. "
        "Dockerfile: Python 3.13 slim; optional build-arg TAKT_BUILD_REVISION; HEALTHCHECK на HEAD /ready; "
        "uvicorn запускается с --workers 1, потому что окно последних событий process-local; "
        "graceful shutdown uvicorn с таймаутом 15 с (для K8s рекомендуется terminationGracePeriodSeconds ≥ 20). "
        "Примеры kube-проб: liveness GET /live, readiness GET /ready на порт 8090. docker-compose в репозитории с согласованным healthcheck."
    )

    heading("13. Качество: тесты, CI, SBOM, extras пакета")
    p(
        "pytest покрывает домен, use cases, API, middleware, SQLite, экспорт и интеграции. import-linter фиксирует границы слоёв. "
        "GitHub Actions: сборка образа (без push, кэш BuildKit) и pytest на Python 3.11–3.14; Dependabot для pip и actions. "
        "Скрипт scripts/generate_sbom.py формирует полноценный CycloneDX JSON dist/sbom.cdx.json "
        "и alias dist/sbom.cyclonedx.json; локальные file:// ссылки из SBOM удаляются. "
        "Опциональные extras: dev (pytest, import-linter, fpdf2, prometheus-client), metrics, export."
    )

    heading("14. Направления дальнейшей разработки")
    p(
        "По README: расширение покрытия инвариантами из полного ТЗ, углублённый разбор IEC-104 (сейчас нормализация и подсказки), "
        "асинхронный backtest на 100k+ событий, целевые стенды (Astra/Baikal)."
    )

    DOCS.mkdir(parents=True, exist_ok=True)
    pdf.output(str(OUTPUT))
    print(f"Записано: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
