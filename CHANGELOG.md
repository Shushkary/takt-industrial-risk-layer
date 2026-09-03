# Changelog

## Unreleased

### Стоимость приёма при включённой SOC-корреляции

После включения `correlation.mode: generalized` приём на SQLite ощутимо замедлился:
`SqliteCaseStore.save` на каждое событие делал `DELETE FROM case_correlation_keys
WHERE case_id = ?` и заново вставлял все ключи дела — O(число ключей дела) на
**каждое** событие. Ключи практически всегда только накапливаются, поэтому на
растущем деле полная перезапись росла вместе с ним: приём корпуса INC-002
(1030 событий) занимал **268 с**, 222 мс на событие.

Пишется только дельта — новые ключи вставляются, ключи, которых у дела больше
нет, удаляются (вынесено в `sqlite_correlation_keys.py`). Тот же прогон —
**31 с**, 33 мс на событие; разрыв с режимом `legacy` (27 мс) практически закрыт.
Проверено, что состав индекса после дельта-записи не отличается от того, что
давала полная перезапись. Сторож — `tests/test_sqlite_correlation_key_delta.py`.

### Группировка событий после приёма

По замечанию: 27 связанных событий атаки, принятых штатным механизмом, давали **21 отдельное
дело** вместо одного связанного инцидента. Воспроизведено на `tests/fixtures/pt_techlab/inc_002/`
(1030 событий, 27 из них — размеченная цепочка). Все числа ниже — замер на этом корпусе,
разбор — [`docs/pt_techlab/correlation_quality.md`](docs/pt_techlab/correlation_quality.md).

**Исправлено**

- **SOC-корреляция была выключена в поставляемом конфиге** (`correlation.mode: legacy`): правила
  не применялись вовсе, работал только ключ подавления шума `актив|операция|окно`. Цепочка атаки
  по определению состоит из разных операций на разных узлах и таким ключом не связывается.
- **Первый ключ корреляции затирал `burst_fingerprint`**: включение корреляции **выключало**
  подавление шума — 223 дела вместо 121. Теперь оба ключа складываются.
- **Событие, совпавшее сразу с несколькими открытыми делами, попадало только в первое**;
  остальные получали ссылку `related_cases`. Ссылка не собирает инцидент. Теперь такие дела
  сливаются: выживает дело правила с высшим приоритетом (правило старшинства не изменилось),
  поглощённое получает статус **`MERGED`** и ссылки в обе стороны.
- **Ключи события переходят делу при любом слиянии**, а не только при совпадении по правилу
  корреляции: раньше дело содержало событие и при этом не находилось по его узлу.
- **Раскладка таблицы состава дела**: доли колонок считались от начала ряда, а слева стоит
  необязательная колонка отметки — она забирала долю времени (161 px под флажок), и последняя
  колонка оставалась без ширины («Артефакт» схлопывался в ноль).

**Добавлено**

- **Автоматическая сборка инцидента после приёма** — `POST /cases/assemble/auto`, и тот же шаг
  в конце `python -m takt.tools.load_dataset` (отключается флагом `--no-assemble`). Собирает
  ядро по отличительным сущностям дел, где сработал инвариант; отличительной считается
  сущность, встречающаяся в потоке не чаще `distinctive_max_events` раз (по умолчанию **12** —
  середина замеренного плато 10–25, на котором цепочка собирается полнее всего и фон в инцидент
  не попадает вовсе; с порога 40 начинается смешивание). Узел сидом не бывает: расширение до уровня узла добирает штатную
  активность и остаётся решением аналитика. Идентификатор инцидента выводится из состава
  сущностей, поэтому повторный прогон даёт тот же инцидент, а не его копию; промежуточная
  редакция, пересобранная при догрузке следующего источника, закрывается как `MERGED`.
  Результат на корпусе: **один инцидент из 23 событий, все 23 — из цепочки, фона ноль**
  (было 21 дело).
- **Область применения правила корреляции** — поле `sources` в `config/risk_weights.yaml`.
  Задаётся явно; неизвестное имя класса источника отбрасывает правило целиком, а не расширяет
  его молча. Промышленный контур (`plc_polling`, `auth_logs`, `service_desk`) под правила не
  попадает — его ключом слияния остаются актив и операция. Сторож:
  `tests/test_correlation_config_contract.py`.
- **Окно правила корреляции** — поле `window`: `calendar` (по умолчанию) или `sliding`.
  Скользящее окно снимает календарную границу, из-за которой два события одного узла в двух
  минутах друг от друга расходились по разным делам. В поставляемых правилах по узлу не
  включено: замер показал, что скользящее окно по `host_id` стягивает весь корпус в **одно
  дело из 982 событий**, где цепочка неотличима от фона.
- **Сборка инцидентов запускается из АРМ** — кнопка «Собрать инциденты» в очереди.
  Загрузка датасета выполняет шаг сама, но приём через `POST /events` — нет, и без кнопки
  аналитик оставался с лентой мелких дел и без способа что-либо с ней сделать. Действие
  доступно роли с правом записи, ничего не закрывает и не меняет состав дел конвейера —
  только добавляет собранный кейс; повторный запуск пересобирает тот же кейс.
- **Карточка процесса открывается из основного интерфейса.** Backend отдавал
  `GET /entities/{type}/{id}/card` для `host`, `user` и `process`, но в АРМ кликабельны были
  только узел и учётная запись. В таблице состава дела добавлена колонка «Процесс» с переходом
  в карточку, в поиске по событиям — колонка «Процесс» (фильтр по процессу там был и раньше).

- **Стоимость сборки перестала расти по двум множителям сразу.** Хранилище дел обходилось
  трижды за прогон плюс ещё по разу на каждый собранный инцидент. Замер: 8000 дел и 40
  инцидентов — **20,3 с** только на обходы. Снимок дел берётся один раз и раскладывается
  по событиям (`CaseEventIndex`): те же данные — **1,8 с**. Сторож — счётчик обходов в
  `tests/test_auto_assemble_incidents.py`.
- **Загрузка датасета собирает инцидент и при сбойных строках.** Раньше единственная
  непрочитанная строка из тысячи молча отменяла шаг: оператор видел `failed=1` и не знал,
  что сборка вообще не запускалась.

**Изменение поведения тестов**

- `tests/test_pt_techlab_generalized_correlation.py::test_priority_selects_first_case_and_records_other_as_related`
  закреплял прежний контракт «пересечение фиксируется ссылкой `related_cases`» — ровно то
  поведение, которое разбирало цепочку на отдельные дела. Тест переписан под новый контракт
  (`test_priority_selects_survivor_and_absorbs_the_other_case`).

### Breaking (домен / данные)

- **`burst_fingerprint`** по умолчанию — режим **`bucketed`** (`**asset_id|operation|time_bucket**` в UTC, окно из **`alert_fatigue.bucket_sec`** в **`risk_weights.yaml`**, по умолчанию **300** с). Разные каналы **`source`** с тем же активом и операцией в одном бакете сливаются в **один** открытый кейс. Режим **`legacy`** (`**source|asset_id|operation**`) сохранён для обратной совместимости.
- Каталог инвариантов: **26** доменных записей в **`InvariantId`** / **`GET /invariants`**; **`alert_fatigue_guard`** удалён из enum (дедупликация только в L2).
- Схема SQLite кейсов: версия **6**. Включает поля наблюдаемости/форензики (**`observations`**, **`invariant_hit_records`**, **`manual_permits`**, **`decision_records`**, **`remediation_attempts`**, **`pdf_last_sha256`**, **`pdf_last_generated_at`**, **`raw_evidence_refs`**) и append-only ledger-таблицы (**`case_audit_ledger`**, **`operation_audit_ledger`**). Старые БД дополняются миграциями (`scripts/db_migrate.py`) и совместимым `ALTER TABLE` при старте.
- Экспорт/импорт кейса (**`CaseDetail`**): поля **`observations`**, **`invariant_hit_records`**.
- Инвариант **`polling_chaos_feigenbaum`** переименован в **`polling_period_doubling_suspect`** (см. **`docs/feigenbaum_rationale.md`**). Интеграциям, завязанным на старый id, нужна миграция.

### Добавлено

- **Потоковый бэктест**: `RunBacktestUseCase.execute` принимает `Iterable[NormalizedEvent]` вместо `Sequence` (в т.ч. генератор), окно контекста — `collections.deque(maxlen=n)`, входной набор больше не материализуется целиком в памяти. Новый `takt.infrastructure.importers.csv_events.iter_normalized_from_csv` — потоковый построчный загрузчик CSV. Регрессия пропускной способности: `tests/test_backtest_streaming_100k.py` (100k событий через полный конвейер из генератора).
- **Протокол true positive / false positive**: `scripts/eval_detection.py` + размеченный корпус `tests/fixtures/detection_eval/` — baseline TPR/FPR для 11 из 26 инвариантов на синтетических сценариях (не промышленная выборка). Регрессия: `tests/test_detection_quality.py`. См. `docs/detection_quality.md`.
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
- **`InMemoryCaseStore.find_open_by_fingerprint`** делал линейный скан всех кейсов в хранилище на каждое входящее событие — O(n²) за прогон при большом числе кейсов/событий (обнаружено при подготовке streaming-бэктеста на 100k+ событий: прогон занимал ~21 минуту вместо секунд). Добавлен индекс **`_open_by_fingerprint`** (fingerprint → case_id), поддерживаемый на `save()`; поиск открытого кейса — O(1). Помимо производительности бэктеста закрывает потенциальный вектор деградации: поток входящих событий с большим числом различных `burst_fingerprint` (напр. флуд от множества активов) ранее замедлял `POST /events`/`POST /assess` пропорционально текущему размеру хранилища кейсов при `storage: memory`. Тесты: `tests/test_memory_case_store.py`.

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
