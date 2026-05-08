# ТАКТ Industrial Risk Layer (MVP)

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

Переменные из файла **`.env`** удобно подставить так: `uvicorn … --env-file .env` (флаг поддерживается **uvicorn** ≥ **0.30**).

**Docker** (`Dockerfile`: **Python 3.13** slim; при сборке ставится **`prometheus-client`** (`pip install ".[metrics]"`); для **`GET /metrics`** / **`HEAD /metrics`** передайте **`TAKT_METRICS=1`** (в **`docker-compose.yml`** есть закомментированный пример). Опционально **`--build-arg TAKT_BUILD_REVISION=…`** (в образе — **`ENV`** и label **`org.opencontainers.image.revision`**; в **`GET /health`** — **`build_revision`**, см. **`TAKT_BUILD_REVISION`**). В **GitHub Actions** CI аргумент задаётся от **`github.sha`**.

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

Образ объявляет **`HEALTHCHECK`** на **`HEAD /ready`** (проверка SQLite и baseline; без загрузки JSON). В **`CMD`** задано **`--timeout-graceful-shutdown 15`** (секунды): при остановке контейнера (**SIGTERM**) **uvicorn** успевает завершить активные запросы и **lifespan** приложения (в т.ч. **`close()`** для SQLite и строка **INFO** **`TAKT API shutdown`** в **`takt.api`**). В **`docker-compose.yml`** для сервиса **`api`** задан тот же **`healthcheck`** — удобно для `depends_on: condition: service_healthy`.

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

В репозитории есть **GitHub Actions** (`.github/workflows/ci.yml`): сборка **Docker**-образа (без push, кэш слоёв **GHA** / BuildKit); **`pytest`** + import linter на Python **3.11**–**3.14**; джобы **`release-gates`** (SBOM, артефакты мониторинга, ledger verifier fixture, `pip-audit`, Schemathesis, mutation для `weights_loader.py`) и **`release-evidence-dry-run`** (`release_finalize.py` с локальным API smoke через `close_operational_tails`, затем `build_release_package` + verify манифеста); **Dependabot** (`.github/dependabot.yml`) — еженедельные обновления pip и actions. Подробнее: [`docs/current_operational_reference.md`](docs/current_operational_reference.md).

Необязательно: **`TAKT_CONFIG`**, **`TAKT_STORAGE`**, **`TAKT_SQLITE_PATH`**, **`TAKT_SQLITE_BUSY_TIMEOUT_MS`** (мс: **PRAGMA busy_timeout** для SQLite, допустимо **100**–**300000**, невалидное или вне диапазона — **5000**; в **`GET /health`** при SQLite — **`sqlite_busy_timeout_ms`**), **`TAKT_REQUEST_ID_HEADER`** (необязательное имя входящего заголовка для ID запроса: **1**–**64** символов, буквы/цифры/**`-`**/**`_`**, напр. **`X-Correlation-ID`**; просматривается раньше **`X-Request-ID`**; ответ по-прежнему **`X-Request-ID`**; невалидное значение игнорируется; в **`GET /health`** — **`request_id_alternate_header`**, если задано и не дублирует **`X-Request-ID`**), **`TAKT_API_KEY`**, **`TAKT_CORS_ORIGINS`** (список origin через запятую; одно значение `*` — любой origin, без credentials), **`TAKT_HSTS_MAX_AGE`**, **`TAKT_HSTS_PRELOAD`**, **`TAKT_LOG_LEVEL`** (**`DEBUG`**, **`INFO`**, **`WARNING`** / **`WARN`**, **`ERROR`**, **`CRITICAL`** — уровень логгера **`takt.api`**; неверное значение игнорируется; в **`GET /health`** — **`api_log_level`**, эффективное имя уровня), **`TAKT_SLOW_REQUEST_LOG_SEC`** (порог в секундах: при **`X-Process-Time` ≥ порога** — запись **WARNING** в **`takt.api`**: метод, путь, длительность, **`request_id`**), **`TAKT_MAX_REQUEST_BODY_MB`** (положительное число мегабайт: для **POST**/**PUT**/**PATCH** при **`Transfer-Encoding: chunked`** — **411** (нужен **`Content-Length`**, иначе размер на входе неизвестен); при **`Content-Length`** больше лимита — **413**; без **`Content-Length`** и без chunked лимит до чтения тела не применяется; **411**/**413** снабжаются **`X-Request-ID`** и **`X-Process-Time`**), **`TAKT_RATE_LIMIT_PER_MIN`** (положительное целое: in-memory лимит запросов в минуту на IP клиента; без переменной — выключено; опционально **`TAKT_RATE_LIMIT_IP_HEADER`** — доверенный заголовок для ключа лимита (token **1–64** символов: буквы, цифры, **`-`**, **`_`**, напр. **`CF-Connecting-IP`**), первый hop при списке через запятую; иначе первый hop **`X-Forwarded-For`**, если заголовок есть — иначе адрес сокета; доверяйте заголовкам только за известным прокси / CDN; пути **`/live`**, **`/ready`**, **`/health`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`** не лимитируются; превышение — **429** и **`Retry-After`**; ответы (в т.ч. успешные до исчерпания квоты) с **`X-RateLimit-Limit`**, **`X-RateLimit-Remaining`**, **`X-RateLimit-Reset`** (Unix UTC, начало следующей минуты); **`TAKT_RATE_LIMIT_MAX_IPS`** — максимум IP в памяти счётчика, по умолчанию **8192**, допустимый диапазон **256**–**500000** (невалидное значение → **8192**); вычищаются прошлые минутные окна и избыток ключей; в **`GET /health`** при включённом лимите — **`rate_limit_per_minute`**, **`rate_limit_max_tracked_ips`**, **`rate_limit_tracked_ips`** (текущее число ключей в памяти) и при заданном **`TAKT_RATE_LIMIT_IP_HEADER`** — **`rate_limit_ip_header`**), **`TAKT_CATALOG_CACHE_MAX_AGE_SEC`** (кэш каталожных **GET** **`/invariants`**, **`/catalog/event-sources`**, **`/topology/demo-graph`**: по умолчанию **`60`** секунд, **`public, max-age=…`**; **`0`** или отрицательное — заголовок не выставляется; верхняя граница секунд — **86400**; **GET** по путям **`/cases…`** всегда получают **`Cache-Control: private, no-store`**) — см. ниже и раздел «Конфигурация». **`TAKT_METRICS`** (`1` / `true` / `yes`): эндпоинт **`GET /metrics`** (текст Prometheus); нужен **`prometheus-client`** (`pip install ".[metrics]"` или extras **`dev`**); при **`TAKT_API_KEY`** scrape выполняют с тем же ключом. **`TAKT_OPENAPI_SERVER_URL`** (один или несколько абсолютных **https://…** / **http://…** через запятую, без завершающего слэша у одного URL не обязательно — он нормализуется): поле **`servers`** в **`/openapi.json`** и база для **Try it out** в Swagger за reverse proxy. **`TAKT_BUILD_REVISION`** (необязательно: непустая строка после **trim**, до **256** символов в ответе — в **`GET /health`** поле **`build_revision`** для метки CI / образа (**`GET /health`**, строка **INFO** **`TAKT API ready`** в **`takt.api`** с **`build_revision=…`**); пустое — ключа в JSON нет и суффикса в ready-логе нет). Для ответов включается **gzip** (порог **512** байт, см. **`GET /health`**: **`gzip_minimum_size_bytes`**). Заголовок **`X-Request-ID`** добавляется в каждый ответ (или сохраняется переданный клиентом); в JSON-телах ошибок middleware (**`403`** без ключа API, **`411`**, **`413`**, **`429`**) то же значение повторяется в поле **`request_id`**. **`X-Process-Time`** — время обработки запроса в секундах (строка с float), в том числе при ответах ошибок (напр. **403** без ключа API). При **`TAKT_CORS_ORIGINS`** в **`Access-Control-Expose-Headers`** перечислены **`X-Request-ID`**, **`X-Process-Time`**, **`X-Total-Count`**, **`Link`**, **`Cache-Control`**, **`Retry-After`**, **`X-RateLimit-Limit`**, **`X-RateLimit-Remaining`**, **`X-RateLimit-Reset`** (чтобы фронт мог их читать из JS).

Опция **`export`** (только `fpdf2`, если не ставите `dev`, где он уже включён):

```powershell
python -m pip install -e ".[export]"
```

### HTTP API (MVP 0.6.23)

В [`config/risk_weights.yaml`](config/risk_weights.yaml) добавлены:

- **`topology`** — `jump_host`, `plc_hosts`, **`demo_graph_edges`** (рёбра для демо-графа и API).
- **`enrichment`** — обогащение payload (сегменты air-gap → `new_node_airgap`); **`iec104_type_aliases`** — нормализация колонок в `iec104_type_id` в конвейере **ProcessEvent** (**`POST /assess`**, **`POST /events`**).
- **`invariants.iec104_disallowed_type_ids`** — запрещённые type id в поле `iec104_type_id` события.
- **`siem_webhook`** — allowlist URL, **`retries`**, **`backoff_sec`**; синхронный и асинхронный POST.
- **`ingest_trust.by_source`** — коэффициенты доверия по значению `source` события (DQ / Inv_DQ_03); попадают в **`GET /health`** как **`ingest_trust_sources`** (число настроенных ключей).

- `GET /invariants` — каталог **всех** `InvariantId`: `id`, `block_key`, `block_label_ru`, `title_ru`; опционально **`?block_key=`** (`rhythm`, `topology`, `identity`, `physics`, `integrity`, `data_hitl`)
- `GET /catalog/event-sources` — допустимые значения **`source`** для ingest: `id` + **`ingest_trust`** из конфига (или `null`, если ключа нет в YAML — тогда в DQ используется **1.0**)
- `GET /topology/demo-graph` — `jump_host`, `plc_hosts`, **`demo_graph_edges`** и флаг **`has_jump_bypass_pattern`** (паттерн «к ПЛК не с jump» на загруженном графе)
- `GET /openapi.json`, **`HEAD /openapi.json`** — OpenAPI 3; **HEAD** — **200** без тела (спецификация не строится), удобно для лёгких проверок за прокси
- `GET /live`, **`HEAD /live`** — **liveness**: минимальный ответ без БД (**`live`**, **`product`**, **`version`** для GET; при **`TAKT_BUILD_REVISION`** — ещё **`build_revision`**, как в **`GET /health`**) для Kubernetes **livenessProbe**; **HEAD** — только статус **200**, без тела
- `GET /health`, **`HEAD /health`** — **`version`**: номер установленного пакета (`importlib.metadata`); **`python_version`**: версия интерпретатора (**`major.minor.micro`**); **`python_implementation`**: **`sys.implementation.name`** (напр. **`cpython`**); **`api_log_level`**: эффективный уровень логгера **`takt.api`** (см. **`TAKT_LOG_LEVEL`**); **`uptime_seconds`**: аптайм процесса с момента создания приложения (секунды, **`time.monotonic()`**); **`booted_at_utc`**: время создания приложения в **UTC** (строка **ISO-8601** с разрешением до секунд, неизменно в рамках одного процесса); **`process_id`**: PID процесса (**`os.getpid()`**); **`hostname`**: имя узла ОС (**`socket.gethostname()`**); **`platform`**: **`sys.platform`** (напр. **`linux`**, **`win32`**); **`python_executable`**: **`sys.executable`**; **`api_key_enabled`**: задана ли переменная **`TAKT_API_KEY`**; при **`TAKT_RATE_LIMIT_PER_MIN`** — **`rate_limit_per_minute`**, **`rate_limit_max_tracked_ips`**, **`rate_limit_tracked_ips`** и при настройке — **`rate_limit_ip_header`**; **`cors_enabled`**: подключён ли **CORS** по **`TAKT_CORS_ORIGINS`** (непустой список origin после разбора); **`hsts_enabled`**: включён ли **HSTS** по **`TAKT_HSTS_MAX_AGE`** (> 0); **`gzip_minimum_size_bytes`** — порог размера ответа для **gzip** (**512** байт); **`openapi_servers_count`** — число принятых URL из **`TAKT_OPENAPI_SERVER_URL`** для поля **`servers`** в OpenAPI (**0**, если не задано или все значения отклонены); **`case_storage`** и **`expected_behavior_storage`**: `memory` или `sqlite` (при `storage.backend: sqlite` baseline **EXPECTED_BEHAVIOR** хранится в том же файле БД, что и кейсы); при SQLite — **`sqlite_schema_version`** (версия схемы таблиц кейсов), **`sqlite_busy_timeout_ms`** (**PRAGMA busy_timeout**, см. **`TAKT_SQLITE_BUSY_TIMEOUT_MS`**); при заданном **`TAKT_MAX_REQUEST_BODY_MB`** — **`max_request_body_bytes`** (лимит для **POST**/**PUT**/**PATCH** по **`Content-Length`**); при заданном **`TAKT_SLOW_REQUEST_LOG_SEC`** — **`slow_request_log_threshold_sec`** (порог логирования медленных запросов); при активном кэше каталожных **GET** — **`catalog_cache_max_age_sec`** (секунды для **`public, max-age`**, как **`TAKT_CATALOG_CACHE_MAX_AGE_SEC`**, по умолчанию **60**; поле без ключа, если каталожный кэш выключен **`0`**); **`prometheus_metrics_enabled`** — открыт ли **`GET /metrics`** ( **`TAKT_METRICS`** и **`prometheus-client`**); **`full_json_max_cases`** — максимум карточек в одном запросе **`GET /cases/export/full.json`** / **`POST /cases/import/full.json`** (сейчас **10000**); **`ingest_event_window_max`**, **`ingest_recent_for_context`**, **`ingest_batch_max_events`** — соответственно размер ring-buffer последних событий (**64**), сколько последних событий в контексте оценки (**5**), лимит **`POST /events/batch`** (**100**); **`cases_list_max_limit`** — верхняя граница **`limit`** в **`GET /cases`** (**1000**); **`cases_list_default_sort`** — значение **`sort`** по умолчанию (**`risk_score_desc`**); **`siem_webhook_retries`**, **`siem_webhook_backoff_sec`**, **`siem_webhook_allowlist_prefixes_count`** (из **`siem_webhook`** в конфиге; **0** префиксов — для forward разрешён только **loopback**); **`export_pdf_unicode_font_configured`** — в **`export.pdf_unicode_font`** задана непустая строка (сам путь к **`.ttf`** в **JSON** не возвращается); **`cases_total`**, **`cases_open`** (NEW/TRIAGE), **`event_window_len`**, **`ingest_trust_sources`**, **`ingest_trust_by_source`** (карта из `ingest_trust.by_source`, пустой объект, если секция не задана). Ответы снабжаются заголовком **`X-Request-ID`** (входящий ID берётся из **`TAKT_REQUEST_ID_HEADER`**, если задан и валиден, иначе из **`X-Request-ID`**, иначе генерируется; см. **`GET /health`**: **`request_id_alternate_header`**). **HEAD** выполняет те же обращения к хранилищу, что и GET, без JSON-тела
- `GET /ready`, **`HEAD /ready`** — **readiness**: проверка чтения хранилища кейсов, baseline и forensic crypto-контура (тело GET: **`ready`**, **`case_storage`**, **`expected_behavior_storage`**, **`forensic_crypto_mode`**, **`forensic_strict_ready`**, **`forensic_strict_missing`**, при **`TAKT_BUILD_REVISION`** — **`build_revision`**); при сбое — **503** и текст **`not_ready:`** … (Kubernetes **readinessProbe**; **`livenessProbe`** лучше вешать на **`/live`**); **HEAD** — тот же контракт по кодам ответа, без тела при **200**
- Forensic observability в **`GET /health`**: **`forensic_crypto_mode`**, **`forensic_strict_ready`**, **`forensic_strict_missing`** (помогают заранее обнаружить некорректную strict-конфигурацию до экспорта bundle).
- `GET /metrics`, **`HEAD /metrics`** — при **`TAKT_METRICS=1`** и установленном **`prometheus-client`**: **GET** — текст Prometheus (**`takt_build_info`** — **`version`** пакета и **`revision`**: **`TAKT_BUILD_REVISION`** или **`unset`**; **`takt_http_requests_total`**, **`takt_http_request_duration_seconds`**, **`takt_http_requests_in_progress`**, **`takt_rate_limit_rejected_total`** и **`takt_rate_limit_tracked_ips`** при включённом **`TAKT_RATE_LIMIT_PER_MIN`** — последняя совпадает с **`rate_limit_tracked_ips`** в **`GET /health`** на момент scrape), **`takt_process_uptime_seconds`** — тот же аптайм, что **`uptime_seconds`** в **`GET /health`**, стандартные метрики процесса вроде **`process_cpu_seconds_total`**; **HEAD** — **200** без тела, **`Cache-Control: no-store`** (проверка доступности без выгрузки метрик); иначе **404**; не публичный при заданном **`TAKT_API_KEY`**
- `POST /assess` — оценка по демо-телу источника PLC_POLLING: по умолчанию **`persist_case: true`** (сохранение в хранилище и добавление в общее окно событий); при **`persist_case: false`** — только ответ (**`case_id`** может отсутствовать в **`GET /cases/{id}`**). Слияние по **`burst_fingerprint`**: по умолчанию в **`config/risk_weights.yaml`** режим **`alert_fatigue.mode: bucketed`** — ключ **`asset_id|operation|time_bucket(UTC)`** при **`bucket_sec`** обычно **300**, без расщепления по **`source`**; режим **`legacy`** — **`source|asset_id|operation`**). У кейса ведутся **`observations`** (канал + **`ingest_trust`** + **`event_ids`**) и **`invariant_hit_records`** (срабатывания с привязкой к событию и DQ). При слиянии: объединение **`invariant_hits`** и записей срабатываний, **`risk_score` = max** с учётом в **`ingest_trust`** для текущего события (**`new_score * trust`** против накопленного **`risk_score`**), при равенстве — более высокий **`risk_class`**, обновление **`xai_summary`** и **`trigger_operation`** по последнему событию. Общее окно последних событий с **`POST /events`**. В ответе — **`invariant_details`**; **`risk_score`** / **`risk_class`** как у рассчитанного (и при сохранении — у сохранённого) кейса. Устаревший путь **`POST /assess/demo`** — тот же контракт).
- `POST /events` — ingest: **`source`**, опционально **`event_id`** и **`payload`** (напр. `type_id` для IEC-подсказок; семантика **`conflict_logic`**, **`expert_dissonance`**, **`polling_jitter`** и др.); в памяти до **64** событий, в контекст оценки — последние **5**. Тело ответа — как у **`POST /assess`** при сохранении.
- `POST /events/batch` — до **100** событий в одном запросе; ответ **`BatchAssessResponse`** (итоги по каждой позиции).
- `GET /cases`, **`GET /cases/{id}`** — список: **`last_event_source`** (значение **`source`** последнего события в потоке кейса после merge), **`event_count`**, **`trigger_operation`**, DQ; фильтр **`event_source`** (точное совпадение с **`EventSource`**); фильтры по времени **`created_after`**, **`created_before`** (ISO-8601); **`risk_class`** или **`risk_classes`** (несколько значений через запятую); **`min_risk_score`**, **`max_risk_score`**, **`min_event_count`**, **`max_event_count`**, **`audit_contains`**, а также (**в т.ч. **`min_invariant_hits`**, **`max_invariant_hits`**, **`xai_contains`**, **`trigger_operation_contains`**, **`primary_asset_id`**, **`fingerprint`** (точное), **`fingerprint_prefix`**, **`case_id_prefix`**, **`title_contains`**, **`min_dq_score`**, **`max_dq_score`**, **`dq_partial`**, **`has_dq_reason`**, инвариант); сортировка по **`risk_score`**, **`created_at`**, **`dq_score`**, **`invariant_hits`**, **`event_count`**, **`title`**, **`case_id`**, **`primary_asset_id`** (`*_desc` / `*_asc`), **`limit`**/**`offset`**; заголовок ответа **`X-Total-Count`** — число записей после всех фильтров и сортировки (до среза по **`offset`**/**`limit`**); при переданном **`limit`** — заголовок **`Link`** (RFC 8288, **`rel=next`** / **`rel=prev`**) с сохранением остальных query-параметров; в строке списка — **`dq_score`**, **`dq_partial`**; карточка: полная семантика + XAI + **`dq_score`**, **`dq_partial`**, **`dq_reasons`** (последняя оценка в потоке).
- `GET /cases/stats` — сводка: **`total`**, **`open`** (NEW+TRIAGE), **`by_status`**, **`by_risk_class`**, **`by_last_event_source`** (число кейсов по **`last_event_source`**; пустое значение — ключ **`unknown`**), **`avg_risk_score`**, **`avg_dq_score`**, **`dq_partial_count`**, **`normalized_events_total`** (сумма `event_ids` по кейсам, с учётом merge), **`distinct_invariant_hits`** (число уникальных id срабатываний по всем кейсам), **`invariant_hits_occurrences_total`** (сумма длин списков `invariant_hits` по кейсам)
- `GET /cases/export/full.json` — выгрузка кейсов (как **`GET /cases/{id}`**): **`exported_at`**, **`count`** (число в ответе), **`total_in_repo`**, **`offset`**, **`limit`** (опционально, по умолчанию без ограничения после offset, макс. **10000**), **`cases`**; заголовок **`X-Total-Count`** = **`total_in_repo`** (до среза по offset/limit); при переданном **`limit`** — заголовок **`Link`** (RFC 8288, **`rel=next`** / **`rel=prev`**); сортировка по **`created_at`** по убыванию
- `POST /cases/import/full.json` — импорт списка **`cases`** в том же формате (тело **`{ "cases": [...], "mode": "upsert" | "skip_existing" }`**; по умолчанию **`upsert`** — запись/перезапись по **`case_id`**; ответ **`imported`**, **`skipped`**, **`mode`**; не более **10000** карточек за запрос). При **`storage.backend: sqlite`** пакет выполняется в одной транзакции (при ошибке сохранения откат).
- `GET /cases/{id}/export.pdf` — при **`export.pdf_unicode_font`** (путь к `.ttf` внутри репозитория, напр. `assets/fonts/DejaVuSans.ttf`) кириллица в XAI сохраняется; иначе — latin-1 fallback; в PDF — блок **Last event source**
- `GET /cases/{id}/forensic-bundle/manifest` — машинно-читаемый манифест доказательного пакета: `root_hash_sha256`, `signature_status`, `process_suitability`, список файлов с SHA-256, **`chain_sha256`** и размером. Поддерживаются статусы `unsigned_mvp`, `hmac_sha256_mvp`, `external_qualified_detached`, `external_gost2012_detached` (через внешний адаптер подписи). Query `engagement_id` включает сервисный аудит (`engagement.json`, `engagement-report.json`) при корректной привязке engagement к кейсу. При недоступной подписи в `gost_strict` endpoint возвращает **503** с `detail=forensic_signing_unavailable: ...`.
- `GET /cases/{id}/forensic-bundle.zip` — ZIP-пакет с `manifest.json`, `case.json`, `siem.json`, `gossopka-card.json`, `compliance-data-quality-report.json`, `forensic-readiness-report.json`, `case-evidence-checklist.json`, `audit.txt`; заголовки **`X-TAKT-Forensic-Root-Hash`** и **`X-TAKT-Forensic-Signature-Status`** позволяют проверить корневой хеш без распаковки. Query `engagement_id` добавляет `engagement.json` и `engagement-report.json` (если финальный отчет зафиксирован). Пакет является первым слоем Forensic Bundle; факт генерации записывается в audit trail кейса с `root_hash` и `signature_status`; ГОСТ-подпись корневого хеша добавляется отдельным адаптером СКЗИ. При недоступной подписи в `gost_strict` endpoint возвращает **503** с `detail=forensic_signing_unavailable: ...`.
- `POST /forensic-bundle/verify` — проверка ZIP-пакета по raw body (`Content-Type: application/zip`): сверяет `manifest.json`, наличие файлов, SHA-256 каждого элемента, **`chain_sha256`** и `root_hash_sha256`; ответ содержит `ok`, `checked_items` и список `issues`.
- **`TAKT_FORENSIC_HMAC_SECRET`** — опциональная MVP-подпись корневого хеша Forensic Bundle через HMAC-SHA256. При заданном секрете manifest получает `signature_status=hmac_sha256_mvp`, `signature_ref=root-hash-signature.json`, а ZIP содержит этот файл. Это проверяемая целостность MVP, **не** КЭП и **не** сертифицированная ГОСТ-криптография.
- **`TAKT_FORENSIC_CRYPTO_MODE`**, **`TAKT_FORENSIC_SIGN_URL`**, **`TAKT_FORENSIC_VERIFY_URL`**, **`TAKT_FORENSIC_SIGNATURE_TIMEOUT_SEC`** — контур подписи root hash. Режимы: `mvp` (по умолчанию) и `gost_strict`; при `gost_strict` для readiness обязательны `TAKT_FORENSIC_SIGN_URL` и `TAKT_FORENSIC_VERIFY_URL`, а HMAC-режим не используется как fallback статуса подписи.
- `GET /cases/{id}/export/siem.json` — JSON для SIEM: в т.ч. **`last_event_source`**, **`invariant_hits`**, **`invariant_details`**, **`data_quality`** (снимок DQ последнего события в потоке кейса: score, partial_observability, reasons)
- `GET /cases/{id}/export/gossopka.json` — карточка инцидента **TAKT-GosSOPKA-MVP**: Risk Case, объект/актив КИИ, категория события, доказательства, DQ, manual permits, audit tail и контекст **ст. 274.1 УК РФ**. Это стабильный внутренний JSON-контракт для последующего маппинга в официальный workflow эксплуатанта, не сертифицированный обменный формат.
- `GET /cases/{id}/export/gossopka-transport.json` — transport-envelope (`contract`, `contract_version`, `exchange`, `payload`) для интеграционного обмена поверх GosSOPKA-карточки; поддерживает query `exchange_mode`.
- `GET /compliance/data-quality-report` — машинно-читаемый Sprint 6/7 отчет по готовности данных и evidence trail: агрегаты по статусам/классам риска, средний DQ, причины partial observability, наличие manual permits, HITL-решений по high-risk кейсам, фактов генерации Forensic Bundle, remediation attempts по `kind`/`status`, а также `audit_engagements` (`total`, `active`, `completed`, `with_final_report`).
- `GET /compliance/forensic-readiness` — per-case Sprint 6 readiness: для каждого Risk Case показывает `ready`, список недостающих evidence-предпосылок (`complete_observability`, `invariant_evidence`, `hitl_decision`, `manual_permit`, `forensic_bundle_audit`), `allowed_missing_codes` и агрегат `missing_by_code`; query `only_not_ready=true` возвращает в `cases` только проблемные кейсы, `missing_code=manual_permit` фильтрует по конкретному блокеру, неизвестный `missing_code` возвращает **400**.
- `GET /cases/{id}/compliance/evidence-checklist` — Sprint 7 checklist по одному Risk Case: каждый evidence-пункт возвращается как `code`, `ok`, `detail`, `remediation_kind`, `remediation_action`, `remediation_attempted`, `latest_remediation_status`; `remediation_summary` агрегирует нужные действия, итоговый `ready` равен true только если все пункты закрыты.
- `GET /compliance/remediation-kinds` — Sprint 7 справочник допустимых `remediation_kind` с описаниями для UI/оркестрации.
- `GET /compliance/remediations` — Sprint 7 список remediation attempts с фильтрами `case_id`, `kind`, `status`, `limit` для операторского контроля выполнения.
- `POST /cases/{id}/compliance/remediations` — Sprint 7 append-only журнал remediation attempts: `kind`, `status` (`recorded` / `started` / `completed` / `failed`), `action`, `result`, `note`; запись сохраняется в `remediation_attempts`, audit trail, Forensic Bundle и ГосСОПКА-MVP.
- `POST /cases/{id}/compliance/remediations/recheck-readiness` — повторная проверка evidence-readiness с привязкой к `attempt_id` (опционально), обновлением `readiness_after`/`status` и аудитом.
- `GET /cases/{id}/compliance/remediations/recheck-readiness/history` — история readiness-recheck с фильтрами (`attempt_id`, `ready`, `limit`, `offset`) и заголовками пагинации.
- `POST /audit-engagements` / `GET /audit-engagements` / `GET /audit-engagements/{id}` — сервисный workflow аудита 5-10 дней (этапы intake / forensic_collection / reporting).
- `POST /audit-engagements/{id}/advance-stage` — перевод engagement на следующий этап с заметкой.
- `POST /audit-engagements/{id}/findings` — append-only findings по engagement.
- `POST /audit-engagements/{id}/final-report` — фиксация финального отчёта и завершение этапов.
- `GET /audit-engagements/{id}/export/report.json` — machine-readable отчёт сервисного аудита (`format`, `engagement`, `findings_count`, `stages_completed`, `stages_total`, `has_final_report`).
- `POST /integrations/siem/forward` — синхронная отправка кейса в webhook (ретраи внутри вызова); политика URL: при **пустом** allowlist — только **loopback**, иначе префиксы из конфига
- `POST /integrations/siem/forward/async` — то же **асинхронно** (`httpx.AsyncClient`), ответ содержит `"async": true`
- `POST /cases/{id}/manual-permits` — ручное прикрепление наряда к Risk Case: `work_order_number`, опционально `asset_id`, `operation`, `note`. Ответ содержит `verdict` (`legitimate` / `illegitimate` / `undetermined`), `confidence`, `rationale` и `counterfactual`; запись сохраняется в `manual_permits`, audit trail и попадает в Forensic Bundle / ГосСОПКА-MVP карточку.
- `POST /cases/{id}/decision` — `{"status": "TRIAGE" | ..., "reason": "..."}`; при `EXPECTED_BEHAVIOR` обновляется baseline. Каждое решение сохраняется как структурный `decision_records` (`prev_status`, `next_status`, `actor`, `reason`, `request_id`, `ts`) и попадает в Forensic Bundle / ГосСОПКА-MVP.
- `GET /cases/{id}/audit-ledger/verify` — верификация append-only hash-chain аудита кейса (для SQLite backend).
- `GET /audit-ledger/operations/verify` — верификация append-only hash-chain операционного ledger (`decision:*`, `import:*`; для SQLite backend).
- `GET /data-quality` — после последнего **`POST /assess`** (с сохранением) или **`POST /events`**
- `POST /backtest/fixture` — прогон `tests/fixtures/plc_polling_demo.csv` с теми же **`demo_graph_edges`**, что у API, и тем же **`ingest_trust.by_source`**, что у **`POST /assess`** / **`/events`**

### SBOM (спринт 12, упрощённо)

```powershell
python scripts/generate_sbom.py
```

Создаётся `dist/sbom.cyclonedx.json` (полный CycloneDX SBOM JSON через `cyclonedx-py environment`).

Демо-оценка: Swagger **`/docs`** (маршруты сгруппированы по тегам: System, Catalog, Ingest, Cases, Export, Integrations, Analytics). В **`/openapi.json`** всегда описана схема **`TaktApiKey`** (заголовок **`X-TAKT-API-Key`**); если задана **`TAKT_API_KEY`**, к непубличным операциям добавляется требование этой схемы (кнопка **Authorize** в Swagger). К операциям добавлены общие ответы **401** / **411** / **413** / **429** с телом по схеме **`MiddlewareErrorJson`** (**`detail`**, опционально **`request_id`**).

По умолчанию ко всем ответам добавляются заголовки **`X-Content-Type-Options: nosniff`**, **`X-Frame-Options: DENY`**, **`Referrer-Policy: strict-origin-when-cross-origin`**, **`Permissions-Policy`** (ограничение геолокации/микрофона/камеры/оплаты). Опционально за HTTPS-прокси: **`TAKT_HSTS_MAX_AGE`** (секунды, > 0) и **`TAKT_HSTS_PRELOAD`** (`1` / `true` / `yes`) → **`Strict-Transport-Security`** с **`includeSubDomains`** и при необходимости **`preload`**. После полной инициализации приложения в лог **`takt.api`** пишется строка **INFO** **`TAKT API ready`**: режим хранилища, путь к YAML, версия пакета, **`python=`**`<implementation>/<major.minor.micro>` (те же **`python_implementation`** и **`python_version`**, что в **`GET /health`**), **`pid=`** (как **`process_id`** в **`GET /health`**), **`hostname=`** (как **`hostname`** в **`GET /health`**), **`platform=`** (как **`platform`**, **`sys.platform`**), при **`TAKT_BUILD_REVISION`** — **`build_revision=`**…. При остановке процесса (закрытие lifespan в **uvicorn** / **`TestClient`**) — **INFO** **`TAKT API shutdown`**: **`version=`**…, **`python=`**`<implementation>/<major.minor.micro>` (тот же тег, что в **`TAKT API ready`**), **`pid=`**, **`hostname=`**, **`platform=`**, **`python_executable=`**; при **`storage.backend: sqlite`** вызывается **`close()`** у репозитория кейсов и baseline: перед разрывом соединений выполняется **`PRAGMA wal_checkpoint`** (сброс **WAL** в основной файл, по возможности).

## Security (периметр HTTP)

- **`TAKT_AUTH_REQUIRED`** (по умолчанию включён): при старте приложения (**lifespan**) без **`TAKT_API_KEY`** процесс завершается с ошибкой. Отключение: **`0`** / **`false`** / **`no`** / **`off`**. В **`GET /health`** поле **`auth.mode`**: **`required`** | **`optional`** | **`disabled`**.
- Публичные пути без ключа: **`/live`**, **`/ready`**, **`/health`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`**. Остальные при строгом режиме и заданном ключе — **401** без верного **`X-TAKT-API-Key`** или **`Authorization: Bearer`**.
- **`TAKT_SECURITY_PROFILE`**: **`prod`** (или **`production`**) — только **https** для SIEM webhook, фильтрация DNS на частные/loopback адреса; иначе профиль **`dev`**.
- **`TAKT_TRUSTED_PROXIES`**: CIDR через запятую. Заголовки **`X-Forwarded-For`** / **`TAKT_RATE_LIMIT_IP_HEADER`** для rate limit учитываются только если прямой peer входит в эти сети. В **`GET /health`**: **`proxy.trusted_count`**.
- SIEM URL: структурный allowlist по **`siem_webhook.allowed_url_prefixes`**; исходящий запрос после DNS использует закреплённый IP для всех ретраев. Подробности — **`CHANGELOG.md`**.

## Конфигурация

Веса и пороги: [`config/risk_weights.yaml`](config/risk_weights.yaml).

Шаблон переменных окружения для API: [`.env.example`](.env.example) (скопируйте в **`.env`** в корне проекта или задайте переменные иначе — **uvicorn** сам по себе **`.env`** не подхватывает).

Переменные процесса API (пути, хранилище, ключ, CORS): см. абзац «Необязательно» в **Быстрый старт**.

Секция **`storage`**: **`backend`**: `memory` (по умолчанию) или **`sqlite`**; при sqlite — **`sqlite_path`** (путь к файлу БД; относительный путь — от корня проекта). То же **`backend`** можно задать или переопределить переменной окружения **`TAKT_STORAGE`**, не меняя YAML. В SQLite сохраняются **кейсы** и таблица **expected_behavior** (пары актив+операция после решения **EXPECTED_BEHAVIOR**); для файла включаются **WAL**, **`busy_timeout`** (по умолчанию **5000** мс; переопределение — **`TAKT_SQLITE_BUSY_TIMEOUT_MS`** в диапазоне **100**–**300000**, иначе **5000**; в **`GET /health`** при SQLite — **`sqlite_busy_timeout_ms`**) и таблица **`app_metadata`** (ключ **`schema_version`** для будущих миграций). Окно последних событий остаётся в памяти процесса.

## Операционный handoff

Единая точка контроля перед выкладкой:

- Pre-deploy: [`docs/releases/runbook_pre_deploy.md`](docs/releases/runbook_pre_deploy.md)
- Smoke после выкладки: [`docs/releases/runbook_smoke_checks.md`](docs/releases/runbook_smoke_checks.md)
- Rollback: [`docs/releases/runbook_rollback.md`](docs/releases/runbook_rollback.md)

Для `TAKT_FORENSIC_CRYPTO_MODE=gost_strict`:

- обязательны `TAKT_FORENSIC_SIGN_URL` и `TAKT_FORENSIC_VERIFY_URL`;
- `GET /ready` должен возвращать `forensic_strict_ready=true` и пустой `forensic_strict_missing`;
- в forensic bundle ожидается `signature_status=external_gost2012_detached` (без HMAC fallback).

## Дальнейшая разработка

Добавить оставшиеся инварианты из ТЗ, полноценный разбор IEC-104 (сейчас — нормализация полей и подсказки), async back-test на 100k+ событий, стенд Astra/Baikal.

План спринтов v0.7 (промпты, DoD, зависимости): [`docs/sprint_prompts_checklists.md`](docs/sprint_prompts_checklists.md).
Релизные документы: [`docs/release_checklist.md`](docs/release_checklist.md), [`docs/release_readiness_status.md`](docs/release_readiness_status.md), [`docs/release_readiness_template.md`](docs/release_readiness_template.md).
