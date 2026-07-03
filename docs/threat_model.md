# Модель угроз ТАКТ Industrial Risk Layer

Документ описывает модель угроз и ограничений самого продукта ТАКТ (не защищаемой АСУ ТП) для
предварительной оценки по Приказу ФСТЭК №239 (см. `docs/certification_risk_roadmap.md`) и для
разговора с Positive Technologies о поверхности атаки второго аналитического эшелона.

Границы продукта, в рамках которых действует эта модель: `docs/product_boundary.md`.
Актуальные значения переменных окружения и security-периметра: `docs/configuration.md`.

## 1. Что защищаем (активы ТАКТ)

| Актив | Почему важен | Где реализован |
|---|---|---|
| Доказательный пакет (forensic bundle: `manifest.json`, `case.json`, root hash, статус подписи) | Юридическая/следственная значимость по ст. 274.1 УК РФ; подмена = потеря доказательной силы | `src/takt/infrastructure/export/forensic_bundle.py` |
| Append-only аудиторский след кейса и операционный ledger | Источник истины о решениях оператора; подмена скрывает манипуляцию решениями | `src/takt/infrastructure/stores/sqlite_audit_ledger.py`, `case_audit_ledger`, `operation_audit_ledger` |
| База кейсов (SQLite/`memory`) | Единственное хранилище оценок риска и решений; потеря = потеря видимости инцидентов | `src/takt/infrastructure/stores/sqlite_store.py` |
| API-ключ (`TAKT_API_KEY`) и производные секреты (`TAKT_FORENSIC_HMAC_SECRET`, форензик signer/verifier URL) | Компрометация даёт запись решений от чужого имени и подделку подписи root hash | `.env`, переменные окружения процесса |
| Организационный контекст (наряды, окна ТО, `manual_permits`) | Основа формального вердикта ФИПС (`legitimate`/`illegitimate`); подмена меняет юридическую квалификацию события | `src/takt/application/use_cases/manual_permit.py` |
| Каталог инвариантов и веса (`config/risk_weights.yaml`, `config/invariants/*.yaml`) | Определяет, что вообще детектируется; тихое отключение правила = слепая зона (см. `docs/invariant_matrix.md`) | `src/takt/infrastructure/config/invariant_catalog_yaml.py` |
| SIEM/ГосСОПКА экспортные каналы | Утечка карточек инцидентов вовне или подмена исходящего трафика | `src/takt/interface_adapters/api/routers/integrations.py`, `export.py` |

## 2. Явно НЕ актив ТАКТ (граница ответственности)

Сама АСУ ТП/ПЛК и их управление — вне модели угроз ТАКТ: продукт не выполняет активное управление
(`docs/product_boundary.md`), поэтому компрометация ТАКТ не даёт нарушителю прямого канала воздействия на
технологический процесс. Максимальный ущерб от компрометации ТАКТ — потеря/искажение **видимости и
доказательств**, не потеря управления процессом.

## 3. Модель нарушителя

| Нарушитель | Возможности | Мотивация |
|---|---|---|
| Внешний сетевой атакующий без доступа к сегменту АСУ ТП | Доступ к API ТАКТ через периметр (если экспонирован), к SIEM webhook как к получателю | Скрыть следы атаки на АСУ ТП, подделать доказательства, DoS системы видимости |
| Внутренний нарушитель — оператор/администратор со штатным доступом к АРМ | Легитимные API-ключи/сессия, знание процесса принятия решений | Замаскировать несанкционированное действие под легитимное (манипуляция `manual_permits`, `decision`) |
| Внутренний нарушитель — администратор инфраструктуры (ОС, БД, конфиги) | Прямой доступ к файлу SQLite, к `config/risk_weights.yaml`, `config/invariants/*.yaml`, к переменным окружения | Отключить детектирование конкретного инварианта незаметно для оператора (см. Блок 6 матрицы инвариантов — уже есть прецедент несогласованного отключения 7 правил) |
| Скомпрометированный источник событий (PLC_POLLING, AUTH_LOGS, NETWORK_EVENTS и т.д.) | Может слать произвольные, в т.ч. поддельные, нормализованные события в `POST /events`/`POST /events/batch` | Инъекция ложных событий, подавление реальных алертов через alert fatigue merge, снижение `ingest_trust` доверенных источников |
| Атакующий с сетевым доступом к SIEM webhook получателю (MITM/подмена DNS) | Может попытаться перенаправить исходящий SIEM/ГосСОПКА трафик | Перехват карточек инцидентов, подмена получателя |

## 4. Поверхность атаки и реализованные меры

### 4.1 HTTP-периметр API

| Угроза | Мера | Подтверждение |
|---|---|---|
| Доступ к write-эндпоинтам без аутентификации | `TAKT_AUTH_REQUIRED=1` по умолчанию, fail-closed при старте без `TAKT_API_KEY`; 401 без `X-TAKT-API-Key`/`Bearer` | `tests/test_takt_api_key.py`, `tests/test_sprint1_security.py` |
| Подмена клиентского IP для обхода rate limit | `TAKT_TRUSTED_PROXIES` — `X-Forwarded-For`/`TAKT_RATE_LIMIT_IP_HEADER` учитываются только от доверенного upstream | `tests/test_sprint1_security.py` |
| DoS через большое тело запроса | `TAKT_MAX_REQUEST_BODY_MB`: 411 без `Content-Length` при chunked, 413 при превышении | `docs/configuration.md` |
| DoS через объём запросов | `TAKT_RATE_LIMIT_PER_MIN`, ограничение памяти счётчика `TAKT_RATE_LIMIT_MAX_IPS` | `tests/test_sprint1_security.py` |
| SSRF/подмена получателя через SIEM webhook | Структурный allowlist `siem_webhook.allowed_url_prefixes`, в `prod`-профиле только https, DNS-резолв с фиксацией IP на все ретраи, запрет RFC1918/loopback/link-local в `prod` | `tests/test_siem_sprint1_checklist.py` |
| Утечка информации через избыточные заголовки/CORS | `TAKT_CORS_ORIGINS` явный allowlist origin, HSTS опционален и явен | `docs/configuration.md` |
| Однопользовательская модель (нет ролей) | Именованные ключи `TAKT_API_KEYS` (`ключ:actor_id:роль`), роли `operator`/`auditor`/`admin`, RBAC-матрица по маршруту в `src/takt/infrastructure/security/rbac.py`; `actor_id` из ключа попадает в `decision_records`/аудит вместо IP. Одиночный `TAKT_API_KEY` (обратная совместимость) по-прежнему даёт роль `admin` без разделения | `tests/test_rbac.py`, `docs/configuration.md#роли-rbac` |

### 4.2 Доказательный пакет / forensic

| Угроза | Мера | Подтверждение |
|---|---|---|
| Zip-slip / path traversal при распаковке пакета | Проверка путей в `forensic-bundle/verify` и при импорте | `tests/test_forensic_bundle.py` |
| Zip-bomb (избыточное сжатие/раздутие архива) | Лимиты числа файлов, размера архива, коэффициента сжатия | `tests/test_forensic_bundle.py` |
| Подмена содержимого пакета без обнаружения | SHA-256 на каждый файл, `chain_sha256`, `root_hash_sha256`, независимая верификация `POST /forensic-bundle/verify` | `tests/test_forensic_bundle.py` |
| Подделка подписи root hash | HMAC-SHA256 (MVP) или внешний сертифицированный signer/verifier (`gost_strict`); в `gost_strict` HMAC не считается валидным fallback | `docs/current_operational_reference.md` |
| Подмена доказательства при недоступности внешнего signer | В `gost_strict` export-эндпоинты возвращают 503 `forensic_signing_unavailable` вместо тихой деградации до HMAC | README, `docs/api_reference.md` |

### 4.3 Аудиторский след и хранилище

| Угроза | Мера | Подтверждение |
|---|---|---|
| Ретроактивное изменение истории решений | Append-only таблицы `case_audit_ledger`, `operation_audit_ledger` (SQLite backend), hash-chain верифицируется отдельным эндпоинтом/CLI | `GET /cases/{id}/audit-ledger/verify`, `scripts/verify_audit_ledger.py` |
| Отсутствие ledger в `memory`-backend | **Известное ограничение**: append-only гарантии есть только при `storage.backend: sqlite`; при `memory` ledger не персистентен | `docs/backend_release_readiness.md` (раздел «Частично / зависит от эксплуатации») |
| Гонки при конкурентной записи в SQLite | `PRAGMA busy_timeout` (`TAKT_SQLITE_BUSY_TIMEOUT_MS`), WAL-режим | `docs/configuration.md` |
| Прямой доступ к файлу SQLite в обход API (актив инфраструктурного администратора) | **Не в объёме ТАКТ** — за пределами продукта; ответственность эксплуатанта (права доступа к файлу/тому) | — |

### 4.4 Конвейер ingest / детектирование

| Угроза | Мера | Подтверждение |
|---|---|---|
| Инъекция поддельных событий от скомпрометированного источника | `ingest_trust.by_source` снижает вес недоверенных источников в DQ и в сравнении `risk_score` при merge | `config/risk_weights.yaml`, `tests/test_data_quality.py` |
| Подавление алертов через merge по `burst_fingerprint` | Слияние сохраняет полный список `invariant_hits`/`invariant_hit_records`, `risk_score = max`, а не последний | `docs/backend_remediation_sprint_plan.md` (S2) |
| Тихое отключение правила детектирования через конфиг (инсайдер с доступом к `config/invariants/`) | **Обнаружено, не устранено**: 7 из 26 инвариантов уже отключены (`predicate_ref: builtin:noop`) без пометки `experimental: true` и без явного предупреждения в `GET /health`/`GET /invariants` | `docs/invariant_matrix.md` — открытый пункт, отдельная задача |
| Ограниченная наблюдаемость (partial observability) маскирует пропуски | `data_quality` снимок (`dq_score`, `partial_observability`, `reasons`) не скрывается даже при деградации данных — явное требование `docs/product_boundary.md` | `tests/test_data_quality.py` |

## 5. Известные открытые риски (не переоткрывать как новые находки)

1. **Noop-инварианты в проде** (Блок 6 промпта v0.8, `docs/invariant_matrix.md`) — 7 правил не исполняются,
   не помечены `experimental`, не видны как отключённые в `GET /health`/`GET /invariants`. Возможное усиление:
   явный флаг «правило задекларировано, но не активно» в ответе каталога.
2. ~~Отсутствие ролей/RBAC~~ — **устранено**: именованные ключи `TAKT_API_KEYS` с ролями `operator`/`auditor`/`admin`
   и RBAC-матрица по маршруту (`docs/configuration.md#роли-rbac`, `tests/test_rbac.py`). Одиночный `TAKT_API_KEY`
   по-прежнему не различает роли (полный доступ) — это осознанная обратная совместимость, а не разрыв.
3. **Ledger только для SQLite** — при `storage.backend: memory` append-only гарантии отсутствуют; для боевой
   эксплуатации SQLite обязателен, это нужно явно фиксировать в runbook по развёртыванию.
4. **Нет TPR/FPR-протоколов** — детектирующая способность инвариантов не подтверждена статистически ни для
   одного правила (промпт v0.8, Блок 3).
5. **Ingest только push/REST** — есть JSON-эндпоинты `POST /integrations/ingest/syslog/rfc5424`, `snmp/trap`,
   `netflow`, `ipfix` (структурированное тело, не нативный UDP/TCP-приёмник), но нет прямого приёма из PT ISIM /
   MaxPatrol SIEM в их родном формате; при интеграции с PT это отдельная поверхность атаки (доверие к приёмнику,
   разбор CEF) — вне объёма этого документа до появления кода интеграции (промпт v0.8, Блок 1).

## 6. Соответствие требованиям ФСТЭК №239 (предварительно, не итог)

Этот раздел — рабочая заготовка для gap-анализа с аккредитованной лабораторией, не итоговая оценка.
Полная методология и трек — `docs/certification_risk_roadmap.md`.

- Идентификация и аутентификация субъектов доступа: базовая ролевая модель есть (`operator`/`auditor`/`admin`
  через `TAKT_API_KEYS`); полноценное управление учётными записями (LDAP/OIDC) не входит в объём MVP.
- Регистрация событий безопасности: append-only ledger при SQLite (см. п. 5.3 — ограничение backend).
- Контроль целостности: SHA-256/hash-chain доказательного пакета и аудита реализованы.
- Защита периметра: аутентификация, rate limit, allowlist исходящих соединений реализованы (раздел 4.1).
- Обнаружение вторжений/аномалий: 26 задекларированных правил, 19 реально активных в проде (раздел 4.4,
  `docs/invariant_matrix.md`), без статистического подтверждения FPR/TPR.
