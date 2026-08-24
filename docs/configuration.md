# Конфигурация и переменные окружения

Полный список переменных процесса API. Быстрый старт — в [`README.md`](../README.md);
перечень эндпоинтов — в [`docs/api_reference.md`](api_reference.md).

Шаблон переменных окружения для API: [`.env.example`](../.env.example) (скопируйте в **`.env`** в корне проекта или задайте переменные иначе — **uvicorn** сам по себе **`.env`** не подхватывает: используйте `uvicorn … --env-file .env`, флаг поддерживается **uvicorn** ≥ **0.30**).

Веса и пороги риска: [`config/risk_weights.yaml`](../config/risk_weights.yaml).

## Переменные окружения

| Переменная | Назначение | Поле в `GET /health` |
|---|---|---|
| `TAKT_CONFIG` | Путь к YAML с весами/порогами (по умолчанию `config/risk_weights.yaml`) | — |
| `TAKT_STORAGE` | `memory` или `sqlite`; переопределяет `storage.backend` из YAML без правки файла | `case_storage`, `expected_behavior_storage` |
| `TAKT_RISK_SCALE` | `industrial` (по умолчанию) или `soc`; выбирает шкалу классов риска — пороги SOC-контура пересчитаны на достижимый максимум балла 0.800, см. `docs/risk_scale_calibration.md` | — |
| `TAKT_SQLITE_PATH` | Путь к файлу SQLite (при `storage.backend: sqlite`) | — |
| `TAKT_SQLITE_BUSY_TIMEOUT_MS` | `PRAGMA busy_timeout`, мс; диапазон **100–300000**; невалидное или вне диапазона — **5000** | `sqlite_busy_timeout_ms` |
| `TAKT_REQUEST_ID_HEADER` | Необязательное имя входящего заголовка для ID запроса (1–64 символов: буквы/цифры/`-`/`_`, напр. `X-Correlation-ID`); просматривается раньше `X-Request-ID`; ответ всегда содержит `X-Request-ID`; невалидное значение игнорируется | `request_id_alternate_header` (если задано и не дублирует `X-Request-ID`) |
| `TAKT_API_KEY` | Ключ API для защищённых маршрутов (заголовок `X-TAKT-API-Key` или `Authorization: Bearer`) | `api_key_enabled` |
| `TAKT_CORS_ORIGINS` | Список origin через запятую; `*` — любой origin, без credentials | `cors_enabled` |
| `TAKT_HSTS_MAX_AGE` / `TAKT_HSTS_PRELOAD` | HSTS за HTTPS-прокси (секунды > 0; `1`/`true`/`yes` для preload) | `hsts_enabled` |
| `TAKT_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`/`WARN`, `ERROR`, `CRITICAL` — уровень логгера `takt.api`; неверное значение игнорируется | `api_log_level` |
| `TAKT_SLOW_REQUEST_LOG_SEC` | Порог в секундах: при `X-Process-Time` ≥ порога — `WARNING` в `takt.api` (метод, путь, длительность, `request_id`) | `slow_request_log_threshold_sec` |
| `TAKT_MAX_REQUEST_BODY_MB` | Лимит тела запроса в МБ для `POST`/`PUT`/`PATCH`; при `Transfer-Encoding: chunked` без `Content-Length` — **411**; при превышении `Content-Length` — **413**; без `Content-Length` и без chunked лимит до чтения тела не применяется | `max_request_body_bytes` |
| `TAKT_RATE_LIMIT_PER_MIN` | In-memory лимит запросов в минуту на IP; без переменной — выключено; превышение — **429** и `Retry-After`; ответы несут `X-RateLimit-Limit`/`Remaining`/`Reset` | `rate_limit_per_minute`, `rate_limit_tracked_ips` |
| `TAKT_RATE_LIMIT_IP_HEADER` | Доверенный заголовок-источник IP для лимита (1–64 символов: буквы/цифры/`-`/`_`, напр. `CF-Connecting-IP`); учитывается только если прямой peer в `TAKT_TRUSTED_PROXIES` | `rate_limit_ip_header` |
| `TAKT_RATE_LIMIT_MAX_IPS` | Максимум IP в памяти счётчика лимита; по умолчанию **8192**, диапазон **256–500000** | `rate_limit_max_tracked_ips` |
| `TAKT_TRUSTED_PROXIES` | CIDR через запятую; `X-Forwarded-For`/`TAKT_RATE_LIMIT_IP_HEADER` учитываются только если прямой peer входит в эти сети | `proxy.trusted_count` |
| `TAKT_CATALOG_CACHE_MAX_AGE_SEC` | Кэш каталожных `GET /invariants`, `/catalog/event-sources`, `/topology/demo-graph`: по умолчанию **60** секунд, `public, max-age=…`; `0`/отрицательное — заголовок не выставляется; верхняя граница — **86400**. `GET /cases…` всегда получают `Cache-Control: private, no-store` | `catalog_cache_max_age_sec` |
| `TAKT_METRICS` | `1`/`true`/`yes`: включает `GET /metrics` (текст Prometheus); нужен `prometheus-client` (`pip install ".[metrics]"` или extras `dev`); при `TAKT_API_KEY` scrape выполняют с тем же ключом | `prometheus_metrics_enabled` |
| `TAKT_OPENAPI_SERVER_URL` | Один или несколько абсолютных `https://…`/`http://…` через запятую — поле `servers` в `/openapi.json` и база для Try it out за reverse proxy | `openapi_servers_count` |
| `TAKT_BUILD_REVISION` | Непустая строка (до 256 символов) — метка CI/образа | `build_revision` |
| `TAKT_AUTH_REQUIRED` | По умолчанию включён: при старте без `TAKT_API_KEY`/`TAKT_API_KEYS` процесс завершается с ошибкой (fail-closed); отключение — `0`/`false`/`no`/`off` | `auth.mode` (`required`/`optional`/`disabled`) |
| `TAKT_API_KEYS` | Именованные ключи с ролями: `ключ:actor_id:роль,ключ2:actor_id2:роль2` (роль — `analyst_l1`/`analyst_l2`/`manager`/`admin`; legacy: `operator`/`auditor`). Некорректные записи отбрасываются с предупреждением. См. `docs/pt_techlab/rbac_matrix.md` | `auth.roles_configured`, `auth.role_counts` |
| `TAKT_SECURITY_PROFILE` | `prod`/`production` — только https для SIEM webhook, фильтрация DNS на частные/loopback адреса; иначе `dev` | — |
| `TAKT_COMPLIANCE_MODE` | `1` — маркировка режима соответствия в `GET /compliance/mode` (не добавляет активного управления, не делает продукт СКЗИ) | — |
| `TAKT_FORENSIC_HMAC_SECRET` | MVP-подпись root hash доказательного пакета через HMAC-SHA256 | — |
| `TAKT_FORENSIC_CRYPTO_MODE` | `mvp` (по умолчанию) или `gost_strict` | `forensic_crypto_mode` |
| `TAKT_FORENSIC_SIGN_URL` / `TAKT_FORENSIC_VERIFY_URL` / `TAKT_FORENSIC_SIGNATURE_TIMEOUT_SEC` | Внешний HTTP signer/verifier для root hash; обязательны при `gost_strict` | `forensic_strict_ready`, `forensic_strict_missing` |

Общие для всех запросов: gzip (порог **512** байт, `gzip_minimum_size_bytes`); `X-Request-ID` в каждом ответе; `X-Process-Time` (секунды, включая ответы ошибок); при `TAKT_CORS_ORIGINS` — `Access-Control-Expose-Headers` со списком `X-Request-ID`, `X-Process-Time`, `X-Total-Count`, `Link`, `Cache-Control`, `Retry-After`, `X-RateLimit-*`.

## Security (периметр HTTP)

- **`TAKT_AUTH_REQUIRED`** (по умолчанию включён): при старте приложения (**lifespan**) без **`TAKT_API_KEY`** процесс завершается с ошибкой.
- Публичные пути без ключа: **`/live`**, **`/ready`**, **`/health`**, **`/metrics`**, **`/openapi.json`**, **`/docs`**, **`/redoc`**. Остальные при строгом режиме и заданном ключе — **401** без верного **`X-TAKT-API-Key`** или **`Authorization: Bearer`**.
- **`TAKT_SECURITY_PROFILE`**: **`prod`** (или **`production`**) — только **https** для SIEM webhook, фильтрация DNS на частные/loopback адреса; иначе профиль **`dev`**.
- **`TAKT_TRUSTED_PROXIES`**: CIDR через запятую. Заголовки **`X-Forwarded-For`** / **`TAKT_RATE_LIMIT_IP_HEADER`** для rate limit учитываются только если прямой peer входит в эти сети.
- SIEM URL: структурный allowlist по **`siem_webhook.allowed_url_prefixes`**; исходящий запрос после DNS использует закреплённый IP для всех ретраев. Подробности — **`CHANGELOG.md`**.

## Роли (RBAC)

По умолчанию (**`TAKT_API_KEY`**, один ключ) любой валидный ключ имеет полный доступ (роль **`admin`**) —
поведение не изменилось для существующих развёртываний. Для разделения ролей задайте **`TAKT_API_KEYS`**
вместо (или в дополнение к) **`TAKT_API_KEY`**: список записей `ключ:actor_id:роль` через запятую.

Роли: **`analyst_l1`**, **`analyst_l2`**, **`manager`**, **`admin`**. `analyst_l2` включает права L1,
`manager` работает только на чтение, `admin` имеет полный доступ. Legacy-роли: `operator` = `analyst_l2`,
`auditor` = `manager`. Полная матрица: `docs/pt_techlab/rbac_matrix.md`.

| Правило | Минимальная роль |
|---|---|
| Любой `GET`/`HEAD` | любая аутентифицированная роль (включая `manager`) |
| `POST /forensic-bundle/verify` | любая аутентифицированная роль (только проверяет уже сформированный пакет, не меняет состояние) |
| `POST /cases/import/full.json`, `POST /integrations/siem/forward(/async)`, `/audit-engagements*` | `admin` |
| Квалификация, findings/artifacts, решения и ingest | `analyst_l1` (или L2/admin) |
| Ручная корреляция, merge/split и углублённое реагирование | `analyst_l2` (или admin) |

Несоответствие роли маршруту — **403 Forbidden** с телом `{"detail": "...", "request_id": "..."}`.

`actor_id` из сработавшего ключа `TAKT_API_KEYS` попадает в `decision_records`, `operator_action_history`,
доказательный пакет и ГосСОПКА-карточку через `security_actor_from_request` — с приоритетом ниже проверенного
mTLS DN (`TAKT_MTLS_DN_HEADER`), но выше IP-адреса запроса (fallback, когда ключ не аутентифицирован по имени).

Если ни `TAKT_API_KEY`, ни `TAKT_API_KEYS` не заданы и `TAKT_AUTH_REQUIRED=0` (только для разработки),
роль по умолчанию — **`admin`** без разделения, как и до появления ролей.

`GET /health` → `auth.roles_configured` (число настроенных ключей) и `auth.role_counts` (карта роль → число
ключей) позволяют проверить конфигурацию ролей без раскрытия самих ключей.

## Хранилище (`storage` в `risk_weights.yaml`)

Секция **`storage`**: **`backend`**: `memory` (по умолчанию) или **`sqlite`**; при sqlite — **`sqlite_path`** (путь к файлу БД; относительный путь — от корня проекта). То же **`backend`** можно задать или переопределить переменной окружения **`TAKT_STORAGE`**, не меняя YAML. В SQLite сохраняются **кейсы** и таблица **expected_behavior** (пары актив+операция после решения **EXPECTED_BEHAVIOR**); для файла включаются **WAL**, **`busy_timeout`** (по умолчанию **5000** мс) и таблица **`app_metadata`** (ключ **`schema_version`** для будущих миграций). Окно последних событий остаётся в памяти процесса.

Опция **`export`** (только `fpdf2`, если не ставите `dev`, где он уже включён):

```powershell
python -m pip install -e ".[export]"
```
