# Changelog

## Unreleased

### Breaking (домен / данные)

- **`burst_fingerprint`** по умолчанию — режим **`bucketed`** (`**asset_id|operation|time_bucket**` в UTC, окно из **`alert_fatigue.bucket_sec`** в **`risk_weights.yaml`**, по умолчанию **300** с). Разные каналы **`source`** с тем же активом и операцией в одном бакете сливаются в **один** открытый кейс. Режим **`legacy`** (`**source|asset_id|operation**`) сохранён для обратной совместимости.
- Каталог инвариантов: **26** доменных записей в **`InvariantId`** / **`GET /invariants`**; **`alert_fatigue_guard`** удалён из enum (дедупликация только в L2).
- Схема SQLite кейсов: версия **6**. Включает поля наблюдаемости/форензики (**`observations`**, **`invariant_hit_records`**, **`manual_permits`**, **`decision_records`**, **`remediation_attempts`**, **`pdf_last_sha256`**, **`pdf_last_generated_at`**, **`raw_evidence_refs`**) и append-only ledger-таблицы (**`case_audit_ledger`**, **`operation_audit_ledger`**). Старые БД дополняются миграциями (`scripts/db_migrate.py`) и совместимым `ALTER TABLE` при старте.
- Экспорт/импорт кейса (**`CaseDetail`**): поля **`observations`**, **`invariant_hit_records`**.
- Инвариант **`polling_chaos_feigenbaum`** переименован в **`polling_period_doubling_suspect`** (см. **`docs/feigenbaum_rationale.md`**). Интеграциям, завязанным на старый id, нужна миграция.

### Добавлено

- **RBAC для API-ключей**: **`TAKT_API_KEYS`** — список именованных ключей `ключ:actor_id:роль` (роль — **`operator`** / **`auditor`** / **`admin`**); RBAC-матрица маршрутов в `takt.infrastructure.security.rbac` (по умолчанию не-GET требует **`operator`**, массовый импорт/SIEM-forward/audit-engagements требуют **`admin`**, **`POST /forensic-bundle/verify`** доступен любой роли). Несоответствие роли — **403**. Одиночный **`TAKT_API_KEY`** сохраняет прежнее поведение (роль **`admin`**, полный доступ) для обратной совместимости. `actor_id` из сработавшего ключа теперь попадает в `decision_records`/аудиторский след вместо IP-адреса (через `security_actor_from_request`, приоритет ниже mTLS DN). **`GET /health`**: **`auth.roles_configured`**, **`auth.role_counts`**. См. **`docs/configuration.md`**, раздел «Роли (RBAC)».
- Спринт 3 (часть): порты **`SystemClockPort`** / **`IdProviderPort`**, реализации по умолчанию в **`application/system_defaults.py`**; **`AssessRiskUseCase`** принимает **`clock`** и **`ids`**; глубина контекста для оценки: **max(5, auth_fail_window, максимум `context_window_events` по `config/invariants/*.yaml`)** (**`GET /health`**: **`ingest_recent_for_context`**); декларативный каталог **`config/invariants/`** (в т.ч. **`params.auth_fail_threshold`** для **`brute_force`**, флаг **`experimental`**); **`blind_command`** учитывает **только непосредственно предыдущее** событие по тому же активу; тест **`tests/test_domain_ast_policy.py`** (запрет **`datetime.now`/`utcnow`**, **`time.time`**, **`uuid.uuid4`** в **`takt.domain`**); Hypothesis-свойства для **`combine_risk`** (**`tests/test_risk_engine_properties.py`**).

- Сущности **`Observation`**, **`InvariantHitRecord`** на **`Case`**; при слиянии учитывается **`ingest_trust`** из конфига для сравнения **`risk_score`** (взвешенное значение входящего события).
- Доменная миграция **v0.7.0**: **`case_bucket_burst_fingerprint`**, **`merge_open_cases_group_v070`**, метод **`SqliteCaseStore.merge_duplicate_open_cases_v070`**, **`delete_cases_by_id`**; золотой снимок **`tests/fixtures/backtest_plc_polling_demo_legacy_golden.json`** для регрессии backtest в режиме **`legacy`**.

### Breaking (оператор / развёртывание)

- По умолчанию включён **`TAKT_AUTH_REQUIRED`** (строгий режим): при старте приложения без непустого **`TAKT_API_KEY`** процесс завершается с ошибкой. Для сценариев вроде локальных тестов без ключа задайте **`TAKT_AUTH_REQUIRED=0`** / **`false`**.
- Ответ API при отсутствии или неверном ключе для защищённых маршрутов изменён с **403** на **401 Unauthorized** (тело **`MiddlewareErrorJson`** без изменений по полям).
- Эндпоинт **`/metrics`** (и **HEAD**) объявлен публичным: доступен без ключа наряду с **`/health`**, **`/live`**, **`/ready`**, документацией OpenAPI.
- **SIEM webhook**: проверка URL по конфигу переведена на структурный allowlist; в профиле **`TAKT_SECURITY_PROFILE=prod`** разрешён только **https**, для loopback — тоже **https**; исходящий запрос резолвит хост один раз и переиспользует тот же IP при ретраях; в **prod** адреса из DNS не должны попадать в RFC1918 / loopback / link-local.
- **Rate limit**: заголовки **`X-Forwarded-For`** / **`TAKT_RATE_LIMIT_IP_HEADER`** учитываются только если прямой peer входит в **`TAKT_TRUSTED_PROXIES`** (список CIDR через запятую); иначе для лимита используется адрес сокета.

### Добавлено

- **`GET /health`**: блоки **`auth`** (`mode`: required | optional | disabled), **`siem`** (`allowlist_mode`, `profile`), **`proxy`** (`trusted_count`).
- Переменные: **`TAKT_AUTH_REQUIRED`**, **`TAKT_SECURITY_PROFILE`**, **`TAKT_TRUSTED_PROXIES`**.

### Исправлено

- Сортировка кейсов по **`created_at`** нормализует naive-datetime через границу UTC, чтобы не сравнивать offset-naive и aware в одном ключе.

### Added (forensic/legal hardening)

- **Forensic raw evidence**:
  - в модель кейса добавлены **`raw_evidence_refs`**;
  - ingest пути (`/events`, `/events/batch`, `/integrations/ingest/*`) сохраняют сырой payload как доказательство;
  - forensic bundle включает `raw/*.bin` + `evidence-index.json`.
- **Forensic API contract**:
  - `GET /cases/{id}/forensic-bundle.zip` теперь возвращает **`X-TAKT-Forensic-Signature-Status`**;
  - manifest/zip поддерживают `external_gost2012_detached`.
- **Strict forensic readiness gate**:
  - режим **`TAKT_FORENSIC_CRYPTO_MODE=gost_strict`**;
  - `/health` и `/ready` возвращают `forensic_crypto_mode`, `forensic_strict_ready`, `forensic_strict_missing`;
  - при missing `TAKT_FORENSIC_SIGN_URL`/`TAKT_FORENSIC_VERIFY_URL` readiness (`/ready`) возвращает **503**;
  - при недоступном signer forensic export endpoints возвращают **`503`** с `detail=forensic_signing_unavailable: ...`.
- **SQLite immutability hardening**:
  - триггеры запрета `UPDATE/DELETE` для `case_audit_ledger` и `operation_audit_ledger`;
  - схема/миграции обновлены до версии **6** (включая `raw_evidence_refs` и append-only triggers).
- **Protocol ingest uplift (MVP+)**:
  - выделены специализированные payload-модели для `syslog/rfc5424`, `snmp/trap`, `netflow`, `ipfix`;
  - добавлено базовое RFC5424 PRI-decode (facility/severity).
- **Audit Engagement workflow (service audit 5-10 days)**:
  - новые API: `/audit-engagements*`, этапы `intake` / `forensic_collection` / `reporting`;
  - экспорт `GET /audit-engagements/{id}/export/report.json`;
  - SQLite persistence для engagement;
  - интеграция в forensic bundle по query `engagement_id` (`engagement.json`, `engagement-report.json`).
- **Release smoke/release docs alignment**:
  - evidence и `release_finalize` учитывают `gossopka_official_ok`, `forensic_verify_ok`, `forensic_signing_unavailable=false` и `audit_engagement_api_ok` (порядок проверок зафиксирован в скрипте и в runbook);
  - `fill_prod_ready_from_evidence.py` переносит те же флаги в smoke-summary (поле 8 prod-ready);
  - `scripts/build_release_package.py` при сборке под корнем репозитория пишет в `manifest.json` переносимый **`package_dir`** (относительный POSIX-путь), иначе — абсолютный каталог сборки;
  - документация и чеклисты разведены по фактическим CI-джобам **`release-gates`** vs **`release-evidence-dry-run`**; обновлены runbooks (в т.ч. GosSOPKA official transport smoke).
