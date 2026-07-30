# ТАКТ Industrial Risk Layer (MVP)

> **🚀 Демо-стенд + АРМ оператора (одна команда):**
> `docker compose -f docker-compose.stand.yml up --build` → фронтенд на http://localhost:3000,
> экран сравнения «ручной режим vs ТАКТ» (метрика — время обработки данных оператором) на
> http://localhost:3000/compare. Полная инструкция и запуск без Docker — в [`stand/README.md`](stand/README.md).
> Отчёт по метрике — [`docs/METRIC_OPERATOR_TIME.md`](docs/METRIC_OPERATOR_TIME.md).


Автономный проект по **ТЗ MPV 2.0** и спринтам из `docs/` (извлечённые тексты из DOCX):

- `Такт ТЗ MPV 2.0.txt` — концепция, слои L1–L5, 25 инвариантов (+ слияние кейсов как отдельный L2-пайплайн), Chaos Predictor (δ≈4.669), Causal Mesh, Risk/XAI.
- `ТАКТ чек-листы 13.txt` — спринты 0–12.
- `Такт Спринты 13.txt` — детальный план.

## Слои

| Слой | Каталог | Назначение |
|------|---------|------------|
| L1 Domain | `src/takt/domain` | Сущности, движки, каталог 25 инвариантов, **`invariants/evaluator`** (расширенные правила), DQ, порты |
| L2 Application | `src/takt/application/use_cases` | Assess (+ **InvariantContext**), ProcessEvent, CaseDecision, Backtest |
| L3 | `src/takt/interface_adapters/api` | REST (FastAPI) |
| L4 | `src/takt/infrastructure` | YAML, CSV, stores, **export (PDF, SIEM webhook)** |

Границы продукта: [`docs/product_boundary.md`](docs/product_boundary.md).
Операционный source of truth (актуальные API/gates/env): [`docs/current_operational_reference.md`](docs/current_operational_reference.md).

## Быстрый старт

```powershell
cd <repo-root>
python -m pip install -e ".[dev]"
python -m pytest
uvicorn takt.interface_adapters.api.main:app --reload --host 127.0.0.1 --port 8090
```

Переменные из файла **`.env`** удобно подставить так: `uvicorn … --env-file .env` (флаг поддерживается **uvicorn** ≥ **0.30**). Полный список переменных окружения и security-периметр: [`docs/configuration.md`](docs/configuration.md).

**Docker** (`Dockerfile`: **Python 3.13** slim; при сборке ставится **`prometheus-client`** (`pip install ".[metrics]"`); для **`GET /metrics`** / **`HEAD /metrics`** передайте **`TAKT_METRICS=1`** (в **`docker-compose.yml`** есть закомментированный пример). Опционально **`--build-arg TAKT_BUILD_REVISION=…`** (в образе — **`ENV`** и label **`org.opencontainers.image.revision`**; в **`GET /health`** — **`build_revision`**). В **GitHub Actions** CI аргумент задаётся от **`github.sha`**.

```powershell
docker build -t takt-risk-layer .
# с полным SHA в /health (build_revision):
docker build --build-arg TAKT_BUILD_REVISION=$(git rev-parse HEAD) -t takt-risk-layer .
docker compose up --build
```

Один контейнер без Compose (том вручную):

```powershell
docker run --rm -p 8090:8090 -e TAKT_STORAGE=sqlite -e TAKT_SQLITE_PATH=/data/takt.db -v takt-data:/data takt-risk-layer
```

Образ объявляет **`HEALTHCHECK`** на **`HEAD /ready`** (проверка SQLite и baseline; без загрузки JSON). В **`CMD`** задано **`--timeout-graceful-shutdown 15`** (секунды): при остановке контейнера (**SIGTERM**) **uvicorn** успевает завершить активные запросы и **lifespan** приложения. В **`docker-compose.yml`** для сервиса **`api`** задан тот же **`healthcheck`** — удобно для `depends_on: condition: service_healthy`.

**Kubernetes** (фрагмент **`httpGet`**-проб: kubelet по умолчанию использует **GET**; **`/live`** и **`/ready`** в базовой конфигурации не требуют **`TAKT_API_KEY`**):

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8090
  initialDelaySeconds: 15
  periodSeconds: 20
readinessProbe:
  httpGet:
    path: /ready
    port: 8090
  initialDelaySeconds: 5
  periodSeconds: 10
```

Для **graceful shutdown** образа ( **`--timeout-graceful-shutdown 15`** ) задайте в Pod **`terminationGracePeriodSeconds`** не меньше **20**, чтобы после **SIGTERM** успели завершиться активные запросы и **lifespan** (закрытие SQLite и лог остановки).

**HEAD** к тем же путям — для Docker **HEALTHCHECK** и ручных проверок без тела ответа.

В репозитории есть **GitHub Actions** (`.github/workflows/ci.yml`): сборка **Docker**-образа (без push, кэш слоёв **GHA** / BuildKit); **`pytest`** + import linter на Python **3.11**–**3.14**; джоба **`frontend-ci`** (`npm ci`, lint, `npm run test:frontend`, dependency audit, Storybook build); джобы **`release-gates`** (SBOM, артефакты мониторинга, ledger verifier fixture, `pip-audit`, Schemathesis, mutation для `weights_loader.py`) и **`release-evidence-dry-run`** (`release_finalize.py` с локальным API smoke, frontend evidence dry run с **frontend SBOM**, затем `build_release_package` + verify манифеста); **Dependabot** (`.github/dependabot.yml`) — еженедельные обновления pip и actions. Подробнее: [`docs/current_operational_reference.md`](docs/current_operational_reference.md).

## HTTP API

Полный перечень эндпоинтов (ingest, кейсы, доказательный пакет, экспорт в SIEM/ГосСОПКА, compliance, аудит): [`docs/api_reference.md`](docs/api_reference.md).

Демо-оценка: Swagger **`/docs`** (маршруты сгруппированы по тегам: System, Catalog, Ingest, Cases, Export, Integrations, Analytics).

## Security (периметр HTTP)

Кратко: строгая аутентификация по умолчанию (`TAKT_AUTH_REQUIRED`), allowlist для SIEM webhook, доверенные прокси для rate limit. Полное описание — [`docs/configuration.md`](docs/configuration.md#security-периметр-http).

## Конфигурация

Веса и пороги: [`config/risk_weights.yaml`](config/risk_weights.yaml).
Переменные окружения, security-периметр и хранилище: [`docs/configuration.md`](docs/configuration.md).
Шаблон переменных окружения для API: [`.env.example`](.env.example) (скопируйте в **`.env`** в корне проекта).

## Операционный handoff

Единая точка контроля перед выкладкой:

- Pre-deploy: [`docs/releases/runbook_pre_deploy.md`](docs/releases/runbook_pre_deploy.md)
- Smoke после выкладки: [`docs/releases/runbook_smoke_checks.md`](docs/releases/runbook_smoke_checks.md)
- Rollback: [`docs/releases/runbook_rollback.md`](docs/releases/runbook_rollback.md)
- Закрытие аудита в среде (чеклист эксплуатации): [`docs/releases/2026-05-08_ops_handover.md`](docs/releases/2026-05-08_ops_handover.md) · сводка статуса: [`docs/releases/2026-05-08_audit_closure_note.md`](docs/releases/2026-05-08_audit_closure_note.md)
- Фронтенд АРМ (MVP UI по внешнему фронтенд-чек-листу проекта): [`frontend/takt-arm/README.md`](frontend/takt-arm/README.md)

Для `TAKT_FORENSIC_CRYPTO_MODE=gost_strict`:

- обязательны `TAKT_FORENSIC_SIGN_URL` и `TAKT_FORENSIC_VERIFY_URL`;
- `GET /ready` должен возвращать `forensic_strict_ready=true` и пустой `forensic_strict_missing`;
- в доказательном пакете ожидается `signature_status=external_gost2012_detached` (без резервного HMAC-режима).

## Дальнейшая разработка

Добавить оставшиеся инварианты из ТЗ, полноценный разбор IEC-104 (сейчас — нормализация полей и подсказки), стенд Astra/Baikal. Потоковый бэктест на 100k+ событий (без материализации всего набора в память) и baseline true positive / false positive — см. [`docs/detection_quality.md`](docs/detection_quality.md).

План спринтов v0.7 (промпты, DoD, зависимости): [`docs/sprint_prompts_checklists.md`](docs/sprint_prompts_checklists.md).
Аудит и статус ремедиации: [`AUDIT_REPORT.md`](AUDIT_REPORT.md), [`docs/backend_remediation_sprint_plan.md`](docs/backend_remediation_sprint_plan.md), [`docs/frontend_api_alignment_sprint_plan.md`](docs/frontend_api_alignment_sprint_plan.md).
Сертификационный трек (ФСТЭК/ФСБ, отдельно от MVP-готовности): [`docs/certification_risk_roadmap.md`](docs/certification_risk_roadmap.md), модель угроз [`docs/threat_model.md`](docs/threat_model.md), матрица инвариантов [`docs/invariant_matrix.md`](docs/invariant_matrix.md).
Релизные документы: [`docs/release_checklist.md`](docs/release_checklist.md), [`docs/release_readiness_status.md`](docs/release_readiness_status.md), [`docs/release_readiness_template.md`](docs/release_readiness_template.md), [`docs/backend_release_readiness.md`](docs/backend_release_readiness.md).
