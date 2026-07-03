# Строгий аудит проекта `TAKT Industrial Risk Layer`

Дата: 2026-05-20
Аудитор: Cline (внешний инженерный аудит)
Объём: backend (`src/takt/**`), frontend АРМ (`frontend/takt-arm/**`),
документация (`README.md`, `docs/**`, `frontend/takt-arm/README.md`),
конфигурация (`config/**`), CI/Ops.

Цель: проверить соответствие реализации заявленным границам продукта
(`docs/product_boundary.md`), README, и собственной архитектурной матрице
(Clean Architecture L1–L4, MVP без активного управления, без СКЗИ,
человек в контуре, доказательный пакет).

---

## 0. Краткое заключение (TL;DR)

| Контур | Состояние | Серьёзность |
|--------|-----------|-------------|
| Доменное ядро `domain/` | Зрелое, разделено по движкам и инвариантам, без сторонних зависимостей. | OK |
| Слой Application | Use-case'ы есть, но часть логики «утекла» в `interface_adapters/api/main.py`. | СРЕДНЯЯ |
| API L3 (`main.py`) | **God-object 3 600 строк / 60 эндпоинтов в одном файле**. Нет роутеров. | **ВЫСОКАЯ** |
| Frontend АРМ | UI каркас собран, но **5 из 6 экранов работают только на демо-данных** и игнорируют реальный API. | **ВЫСОКАЯ** |
| Соответствие документации | README обещает функции, которых в UI нет (Vitest, Playwright, CSP, SBOM фронта, экраны «из `/invariants`», «causal mesh» и т.д.). | **ВЫСОКАЯ** |
| Безопасность HTTP | Реализовано серьёзно (rate-limit, auth, HSTS, trusted proxies). | OK |
| Криптография / `gost_strict` | Граница продукта соблюдена (нет собственной криптографии в `domain/`). | OK |
| Тесты backend | 12 827 строк тестов на 12 404 строк боевого кода — соотношение хорошее. | OK |
| Тесты frontend | Vitest/Playwright **не подключены**. | **ВЫСОКАЯ** |
| Compliance Mode end-to-end | Backend поддерживает, frontend **не отображает** `/compliance/mode`. | СРЕДНЯЯ |

**Общий вердикт:** доменное ядро и HTTP-периметр близки к production-grade,
но фронтенд АРМ в значительной мере **витрина**: он демонстрирует UX,
но не реализует операторский сценарий MVP против настоящего API.
Документация и реализация фронта расходятся.

---

## 1. Метрики и инвентаризация

### 1.1 Backend

- `src/takt/interface_adapters/api/main.py`: **3 600 строк, 152 168 байт**.
- Всего Python в `src/`: **12 404 строки**.
- Тесты `tests/`: **12 827 строк** (хорошее соотношение 1.03×).
- Зарегистрировано **60 HTTP-эндпоинтов** (полный список — Приложение А).
- Топ-5 крупнейших файлов:
  1. `interface_adapters/api/main.py` — 152 168 B
  2. `infrastructure/stores/sqlite_store.py` — 48 780 B
  3. `infrastructure/export/forensic_bundle.py` — 31 529 B
  4. `application/use_cases/manual_permit.py` — 12 554 B
  5. `infrastructure/export/gossopka.py` — 12 541 B

### 1.2 Frontend (`frontend/takt-arm/`)

- 6 страниц (`pages/*.tsx`) — соответствует чек-листу из README.
- 17 UI-компонентов (`components/ui/*`) + 7 stories.
- 1 файл API-клиента: `src/app/taktApi.ts` — **172 строки**.
- 5 файлов «demo» (`src/demo/*`) — статические данные и эмулятор.
- Зависимости: React 19, Vite 6, Tailwind 3, Zustand 5, react-router-dom 7,
  lucide-react **1.14** (см. п. 4.4 — некорректная версия).
- **Нет:** `vitest`, `@testing-library/react`, `playwright`,
  `@tanstack/react-query`, `axios`, `msw`, `zod`/`valibot`.

### 1.3 Маркеры готовности кода

В `main.py` **нет** `TODO`/`FIXME`/`XXX`/`stub` — что хорошо для слоя L3.
Но это парадоксально для файла такого объёма: критический рефакторинг
ему всё равно необходим.

---

## 2. Анализ архитектуры

### 2.1 Clean Architecture: формально слои соблюдены

В `docs/product_boundary.md` явно зафиксировано, что в `domain/`
**запрещены** криптография, ОС, сеть, ORM, FastAPI. Проверка
(`grep -R "import fastapi" src/takt/domain/`) подтверждает: домен чист.

### 2.2 Грубое нарушение SRP в L3

**Главная архитектурная проблема:** `interface_adapters/api/main.py`
монолитен:

- 60 эндпоинтов в одном модуле;
- 3 600 строк, очевидно концентрирует сборку DI, middleware, pydantic
  моделей, бизнес-склейку, форматирование ответов и регистрацию роутов.

Это нарушает:

- собственный архитектурный принцип «L3 — тонкий интерфейс»;
- закон Conway: добавление новой группы эндпоинтов (`compliance/*`,
  `audit-engagements/*`, `integrations/ingest/*`) превращается в
  merge-конфликты;
- ремонтопригодность: средний эндпоинт сейчас живёт где-то в районе
  60-й строки чужого по смыслу соседа.

**Требуется**: разнести по `interface_adapters/api/routers/` минимум
по тегам, уже описанным в README (System, Catalog, Ingest, Cases,
Export, Integrations, Analytics, Compliance, AuditEngagements,
Forensic).

### 2.3 Дублирование в API между «assess» и «events»

`POST /assess`, `POST /assess/demo`, `POST /events`, `POST /events/batch`
возвращают «как у POST /assess при сохранении». В коде это, скорее всего,
4 близких ветки. Нужно вынести единый `IngestEvent` use-case и сократить
дублирование контракта.

### 2.4 Forensic bundle: смешение ZIP-сборки и подписи

`infrastructure/export/forensic_bundle.py` (31 KB) и связка
с `infrastructure/security/root_hash_signature.py` (9.4 KB).
Граница (MVP HMAC vs gost_strict через адаптер) проведена корректно,
но в `main.py` обработка `gost_strict → 503 forensic_signing_unavailable`
повторяется в двух эндпоинтах (`/manifest` и `.zip`) — должна быть
обобщена в одной декорации/зависимости FastAPI.

---

## 3. Анализ backend по логике

### 3.1 Положительные стороны

- Доменные сущности (`Case`, `ManualPermit`, `FormalVerdictRecord`,
  `CaseDecisionRecord`, `RemediationAttempt`, `Observation`,
  `InvariantHitRecord`) — соответствуют документации
  `docs/product_boundary.md` и README.
- Движки (`alert_fatigue`, `causal_mesh`, `chaos_predictor`,
  `context_matcher`, `phase_time_tagger`, `risk_engine`,
  `data_quality`) — реализованы и используются в
  `AssessRiskUseCase.execute`.
- HTTP-периметр: API key через `X-TAKT-API-Key` + `Authorization: Bearer`,
  rate-limit с заголовками RFC 6585/8288, CORS, HSTS, CSP/security
  headers по умолчанию, `X-Request-ID`, `X-Process-Time`.
- Прозрачное `/health` с большим набором runtime-полей —
  важно для эксплуатации, особенно в `gost_strict`.

### 3.2 Дефекты соответствия README

В README заявлены контракты, которых, судя по объёму
`taktApi.ts` (172 строки) и проверке списка эндпоинтов,
**не верифицированы интеграционно** на фронте:

| Эндпоинт (README) | Использован фронтом | Замечание |
|-------------------|--------------------|-----------|
| `GET /cases` (фильтры, сортировка, `X-Total-Count`, `Link`) | ❌ | Очередь использует только демо-данные. |
| `GET /cases/{id}` | ✅ | Используется. |
| `GET /cases/stats` | ❌ | Отсутствует на главной (SegmentOverview). |
| `POST /cases/{id}/decision` | ❌ | UI имитирует «Зафиксировать решение» локально. |
| `POST /cases/{id}/operator-actions/viewed` | ❌ | UI открывает кейс без аудиторской фиксации. |
| `POST /cases/{id}/operator-actions/additional-review` | ❌ | Нет кнопки/потока. |
| `GET /cases/{id}/operator-actions/history` | ❌ | История смешивается с локальным `localAudit`. |
| `POST /cases/{id}/manual-permits` | ❌ | Документ «ручной наряд» не вводится через UI. |
| `POST /cases/{id}/compliance/remediations` (+ recheck-readiness) | ❌ | Sprint 7 не выведен в UI. |
| `GET /compliance/mode` | ❌ | Маркер режима соответствия отсутствует. |
| `GET /compliance/forensic-readiness` | ❌ | Готовность кейса не показана оператору. |
| `GET /cases/{id}/compliance/evidence-checklist` | ❌ | Чек-лист не выведен. |
| `GET /invariants` / `/catalog/event-sources` | ❌ | InvariantLibrary рендерит локальный `demoInvariantGroups`. |
| `GET /topology/demo-graph` | ❌ | TopologyMap не подключён к API. |
| `POST /forensic-bundle/verify` | ❌ | Кнопки «Проверить пакет» нет. |
| `GET /audit-engagements/**` | ❌ | Workflow аудита 5–10 дней не реализован в UI. |
| `GET /audit-ledger/operations/verify` | ❌ | Проверка hash-chain доступна только из CLI. |

### 3.3 Структурные риски в `main.py`

Что **очень вероятно** при таком объёме (нужно валидировать построчно):

- разные эндпоинты повторяют построение Pydantic-моделей вместо
  переиспользования;
- сериализация дат и нормализация query-параметров повторяется
  для каждого `/cases`-эндпоинта;
- авторизация (`X-TAKT-API-Key`) проверяется внутри хэндлеров или в
  middleware — это нужно унифицировать через `Depends(get_api_caller)`.

Эти пункты требуют ручной валидации, поэтому фиксирую как
«ВЕРОЯТНЫЙ ДЕФЕКТ» в плане.

### 3.4 Что хорошо подтверждено

- Контур `formal_verdict/confirmation` существует и пишется в
  историю — но **только если фронт пошлёт реальный запрос**.
  Сейчас при отсутствии `VITE_TAKT_API_BASE_URL` фронт
  возвращает **сфабрикованный** `FormalVerdictRecord` локально
  (см. `taktApi.ts:108-119`). Это допустимо для демо, но
  опасно для регуляторных демонстраций — нужно явное визуальное
  отличие «локально» от «зафиксировано на сервере».

---

## 4. Анализ frontend

### 4.1 Несоответствие документации

`frontend/takt-arm/README.md` сам признаёт нерешённые пункты в разделе
«Следующие шаги»:

> 1. Дизайн-система: StatusPill, DataTable, Callout, NodeIcon; Storybook. **(частично сделано)**
> 2. Экраны: причинная сетка, виртуализация очереди, XAI из API,
>    библиотека инвариантов из `/invariants`, топология, аудит. **(не сделано)**
> 3. Сценарий «обход переходного сервера инженером» end-to-end на данных
>    теплоэнергетики. **(нет интеграции с реальным API)**
> 4. Vitest + Playwright, CSP/nginx, SBOM фронта (CycloneDX) в CI. **(не сделано)**

Однако корневой `README.md` презентует АРМ как часть MVP
без оговорок. Это и есть основное расхождение «доки vs реализация».

### 4.2 IncidentQueue (`pages/IncidentQueue.tsx`)

- Не использует `taktApi.ts` совсем (импорт отсутствует).
- Данные строятся из `selectDemoIncidents(...)` поверх состояния Zustand.
- «Очередь» — статическая и зависит только от `scenarioId`,
  `segmentMode`, `shiftPhase`. Это **витрина**, не операционная очередь.
- Действия «Сформировать отчёт» / «Выгрузить отчёт» делают
  `Blob` локально. На сервере параллельных артефактов не создаётся,
  аудиторский след не пишется.

**Требование MVP:** очередь должна тянуть `/cases` с фильтрами
(`risk_class`, `created_after`, `event_source`, `min_risk_score`,
сортировка `risk_score_desc`), показывать `X-Total-Count` и
постраничный `Link`. Сейчас этого нет.

### 4.3 CaseDetail (`pages/CaseDetail.tsx`)

Единственный экран с интеграцией. Замечания:

1. **Решение оператора** (`Зафиксировать решение оператора`) — пишется
   только в локальный state `localAudit`. **Должно**
   `POST /cases/{id}/decision` со статусом и `reason`.
2. **Открытие карточки** не вызывает `POST /cases/{id}/operator-actions/viewed`,
   хотя README настаивает на «явной фиксации просмотра».
3. **Дополнительная проверка** (`/operator-actions/additional-review`)
   отсутствует в UI.
4. **Ручной наряд** (`manual-permits`) — поля для ввода
   `work_order_number`, `executor`, `approver`, `valid_from/to` отсутствуют.
   Без этого MVP не закрывает основной кейс «легитимное действие при
   действующем наряде».
5. **Remediations / evidence-checklist** не отображаются. Sprint 7
   фактически невидим в UI.
6. **`audit_log: string[]`** в `CaseDetailResponse` (taktApi.ts:23)
   плохо типизирован. Реально (см. `domain/entities/case.py`) бэкенд
   ведёт `decision_records`, `manual_permits`, `formal_verdict_records`,
   `remediation_attempts`, `operator_action_history`. Фронт смешивает их
   в одну простыню строк.
7. **Дублирование функций**:
   `exportLocalCaseDocument()` и `exportForensicBundle()` создают разный
   контент с пересекающимся UI — оператор может выгрузить
   «локальный паспорт» вместо реального ZIP с root-hash и не заметить.
   Нужно отказаться от локального паспорта или явно пометить его как
   **немашинно-доказательный**.

### 4.4 InvariantLibrary

- Полностью отрезана от `GET /invariants`.
- Веса и пороги (`'0,${(index+2)*7}'`) — **синтетические заполнители**,
  никак не связанные с реальной конфигурацией `config/risk_weights.yaml`.
- Триггеры за период вычисляются от `demoIncidents` — это вводит
  оператора в заблуждение.

Это самое опасное расхождение для регуляторной демонстрации:
оператор видит **выдуманные** веса/пороги.

### 4.5 TopologyMap

- 16 808 байт без вызовов API. Должна была подключаться к
  `GET /topology/demo-graph` (с `has_jump_bypass_pattern`).
- Сейчас рисует локальный граф из `selectDemoTopology`.

### 4.6 SettingsAudit

- 4 679 байт демо-страница. Не подключена к:
  - `GET /audit-ledger/operations/verify` (проверка hash-chain),
  - `GET /cases/{id}/audit-ledger/verify`,
  - `GET /compliance/mode`,
  - `GET /health` (для отображения runtime-метаданных).
- Кнопка «Подтвердить изоляцию контура» пишет строку в локальный массив —
  никакой проверки фактической изоляции (например, проверка отсутствия
  webhook'ов в режиме production) не выполняется.

### 4.7 SegmentOverview

(73 строки исходного — судя по размеру в 8 KB) — обзорный экран,
вероятно показывает агрегаты, но не использует `GET /cases/stats` и
`GET /compliance/data-quality-report`. Требуется верификация.

### 4.8 Технологический долг во фронтенд-стеке

- **lucide-react `^1.14.0`** — несуществующая стабильная версия.
  Актуальная серия — `0.x` (на 2026-05 — `~0.460+`). Версия `1.14.0`
  либо тянет старый форк, либо это ошибка в package.json. Нужно
  привести к `^0.475.0` (или фиксированной актуальной).
- **Vite 6.1.x** требует Node ≥ 18.18; в репозитории нет
  `.nvmrc`/`engines.node`.
- **TS 5.7.2** — нормально, но нет `strict`-проверок (нужно
  верифицировать `tsconfig.json`).
- **Storybook 8.6.x** включён, но нет CI-сборки stories и тестов
  взаимодействий, хотя `@storybook/test` установлен.
- **Нет `vitest`/`@testing-library/react`/`@axe-core/react`/`playwright`**.
- **Нет `@tanstack/react-query`**: каждый `fetch` пишется руками,
  без retry/cache/dedup; кейсы будут шторм-нагружать API при возврате
  на страницу.
- **Нет `zod`/`valibot`**: ответы API не валидируются — это критично
  для регуляторного контура («доказательный пакет, но без схемы»).
- **Нет CSP, security headers**, статической поставки nginx-конфига —
  хотя backend сам пишет такие заголовки.
- **Нет SBOM фронта (CycloneDX)** — backend имеет `scripts/generate_sbom.py`,
  фронт — нет.
- **Доступность (a11y):** клик по строке через
  `onClick` на `<div>` (`IncidentQueue.tsx:183`) — для скринридеров
  это «нет», нужно вести по `aria-rowindex`/клавиатуре.

### 4.9 Локализация и числа

UI использует «русский европейский» формат чисел через
`String.replace('.', ',')`. Это работает, но правильнее использовать
`Intl.NumberFormat('ru-RU', { minimumFractionDigits: 3 })`.

---

## 5. Тесты, CI

### 5.1 Backend

- Объём тестов сопоставим с боевым кодом (12.8k vs 12.4k LOC) — это
  хороший базовый показатель.
- В CI указаны: `pytest` на Python 3.11–3.14, `pip-audit`, `Schemathesis`
  (важно для контракта OpenAPI), мутационное тестирование
  `weights_loader.py`, `release-evidence-dry-run` (полная пересборка
  доказательного пакета). Это сильный contract-grade pipeline.
- **Требуется проверить:** покрытие `interface_adapters/api/main.py`
  отдельно — есть подозрение на дыры в редко вызываемых эндпоинтах
  (`/cases/{id}/export/gossopka-official-transport.json`,
  `/integrations/ingest/snmp/trap`, `/integrations/ingest/syslog/rfc5424`).

### 5.2 Frontend

- `npm test` отсутствует.
- `npm run lint` есть (eslint + react-hooks).
- `tsc -b` в `build` — компиляция, но не **тесты типов** контрактов API.
- **CI фронта** в репозитории не описан (по README — только backend).
- Storybook собирается, но snapshot/visual regression тестов нет.

---

## 6. Безопасность и регуляторика

### 6.1 Сильные стороны

- `TAKT_AUTH_REQUIRED` запрещает старт без `TAKT_API_KEY`.
- `TAKT_TRUSTED_PROXIES`, `TAKT_RATE_LIMIT_IP_HEADER` — корректно решают
  X-Forwarded-For подмену.
- Forensic режим (`mvp` / `gost_strict`) с явным failure modes
  и `forensic_strict_ready` в `/ready`.
- Domain отделён от криптографии, что соответствует
  `docs/product_boundary.md`.

### 6.2 Риски

1. **CORS** конфигурируется ENV-переменной `TAKT_CORS_ORIGINS=*`.
   В сочетании с пустым `TAKT_AUTH_REQUIRED=0` это даёт
   public open API. Нужен явный health-check, кричащий ERROR
   при таком сочетании в `production` профиле.
2. **PDF unicode font**: README говорит, что без
   `export.pdf_unicode_font` кириллица в PDF падает к latin-1.
   Это означает, что выгруженный паспорт инцидента может оказаться
   нечитаемым — критично для бумажной части аудита.
3. **`POST /integrations/ingest/syslog/rfc5424`** и SNMP/trap.
   В README они не описаны полно. Нужны: лимит размера тела,
   защита от парсера-bomb, белый список источников по IP.
4. **Webhook allowlist для SIEM** — реализован. Но
   `POST /integrations/siem/forward/async` использует общий event loop
   uvicorn — при шторме retries это может задрать event loop. Нужно
   ограничить количество одновременных webhook'ов.
5. **`POST /forensic-bundle/verify`** принимает raw zip — нужен
   жёсткий лимит размера через `TAKT_MAX_REQUEST_BODY_MB` и
   защита от zip-bomb (распакованный размер).
6. **Frontend не валидирует ответы API**. Любой XSS-payload в
   `case.xai_summary` пойдёт прямо в DOM (хотя React экранирует),
   но в `audit.txt` и `manifest.signature_status` — поведение зависит
   от рендера. Нужен `zod`.

---

## 7. Расхождения «документация — реализация»

Строгие расхождения, требующие либо правки кода, либо правки доков:

| # | Источник | Заявлено | Факт |
|---|----------|----------|------|
| D1 | `frontend/README.md` | Vitest + Playwright в CI | Не подключено. |
| D2 | `frontend/README.md` | SBOM фронта (CycloneDX) в CI | Не подключено. |
| D3 | `frontend/README.md` | CSP/nginx | Не подключено. |
| D4 | Корневой `README.md` | «АРМ MVP по чек-листу» | 5/6 экранов — демо. |
| D5 | README §HTTP API | `GET /invariants`, `/topology/demo-graph` | Бэкенд есть, фронт не использует. |
| D6 | README §HTTP API | `POST /cases/{id}/decision` | UI имитирует локально. |
| D7 | README §Compliance | `GET /compliance/mode` | UI не отображает. |
| D8 | README §Forensic | manifest + ZIP + verify | UI выгружает, но не проверяет. |
| D9 | README §Manual permit | `formal_verdict` ФИПС + organizational_context | UI шлёт `formal-verdict/confirmation`, но `manual-permits` не использует. |
| D10 | README | «Sprint 7 remediations» | UI не отображает. |
| D11 | `product_boundary.md` | «не выполняет блокировку, останов» | Соблюдено. |
| D12 | `product_boundary.md` | «режим compliance отключает демо-данные в рабочих отчётах» | На фронте отчёты строятся **только** на демо-данных вне зависимости от compliance. |
| D13 | README §Frontend | `npm run lint` доступен | Доступен. ✅ |
| D14 | README §Security | TAKT_AUTH_REQUIRED по умолчанию | Реализовано. ✅ |
| D15 | README | export.pdf поддерживает Unicode | Реализовано через `pdf_unicode_font`. ✅ |

---

## 8. План исправления

Приоритизация: **P0** = блокирует регуляторную демонстрацию,
**P1** = блокирует production, **P2** = технический долг.

### 8.1 P0 — Блокирующие задачи

**P0-1. Разделить `main.py` на роутеры (backend).**
Действия:
1. Создать `interface_adapters/api/routers/`:
   `system.py`, `catalog.py`, `ingest.py`, `cases.py`, `export.py`,
   `integrations.py`, `analytics.py`, `compliance.py`,
   `audit_engagements.py`, `forensic.py`.
2. Перенести соответствующие эндпоинты по тегам (которые уже описаны
   в README — Swagger).
3. Оставить `main.py` ≤ 300 строк: создание `FastAPI`, lifespan,
   подключение middleware, регистрация роутеров.
4. Вынести Pydantic-модели в `interface_adapters/api/schemas/`.
5. Регрессии: прогнать существующий `pytest` + `Schemathesis` без
   правок тестов (контракты сохраняются).
*DoD:* `tests/` зелёные, `wc -l main.py < 400`.

**P0-2. Подключить frontend к реальному `/cases` и `/cases/{id}/decision`.**
1. В `IncidentQueue.tsx` заменить демо-данные на загрузку из
   `GET /cases?sort=risk_score_desc&limit=200` через
   `@tanstack/react-query`.
2. Сохранить демо-режим **только** при отсутствии
   `VITE_TAKT_API_BASE_URL` и пометить плашкой
   «локальный демонстрационный режим».
3. В `CaseDetail.tsx`:
   - кнопка «Зафиксировать решение» → `POST /cases/{id}/decision`;
   - при mount страницы — `POST /cases/{id}/operator-actions/viewed`;
   - кнопка «Передать на доп. проверку» →
     `POST /cases/{id}/operator-actions/additional-review`;
   - таб «История» → `GET /cases/{id}/operator-actions/history` и
     `GET /cases/{id}/formal-verdict/history`.
*DoD:* в Network DevTools каждое действие оператора видно как
реальный POST; в `audit_log` кейса появляется запись.

**P0-3. Добавить блок «Ручной наряд» в `CaseDetail.tsx`.**
1. Форма: `work_order_number`, `asset_id`, `operation`,
   `action_class`, `executor`, `approver`, `valid_from`, `valid_to`,
   `document_status`, `restrictions`, `note`.
2. `POST /cases/{id}/manual-permits` и обновление
   `formal_verdict` из ответа.
3. Показать `organizational_context_sha256`, `verdict`, `rationale`,
   `counterfactual` рядом с формой (transparent UX).
*DoD:* end-to-end сценарий «легитимное действие при действующем
наряде» проходит через UI и фиксируется в `manual_permits` бэкенда.

**P0-4. Подключить `InvariantLibrary` к `/invariants`.**
1. Заменить `demoInvariantGroups` на ответ
   `GET /invariants` + `GET /catalog/event-sources`.
2. Веса и пороги показывать **только** если они приходят от API
   (или из `/health` / отдельного `/config/risk_weights`-эндпоинта,
   если он будет добавлен).
3. Запретить локальные «синтетические» веса в compliance-режиме.
*DoD:* при включённом API в UI исчезают строки с поддельными
порогами `0,07`, `0,14`, …

**P0-5. Compliance Mode на фронте.**
1. Подключить `GET /compliance/mode` в `AppShell`/header — бэйдж
   «Compliance ON / OFF».
2. В compliance-режиме скрывать или дизейблить локальные demo-отчёты
   (`IncidentQueue.tsx`, `InvariantLibrary.tsx`, `SettingsAudit.tsx`).
3. Добавить экран `/compliance` с агрегатом из
   `/compliance/data-quality-report` + `/compliance/forensic-readiness`.
*DoD:* при `TAKT_COMPLIANCE_MODE=1` оператор не может выгрузить
демо-отчёт без явного маркера «демонстрационный».

### 8.2 P1 — Production-blocking

**P1-1. Контрактная валидация на фронте через `zod`.**
1. Добавить `zod` (или `valibot`).
2. Описать схемы ответов: `CaseSummary`, `CaseDetail`, `Invariant`,
   `EventSource`, `ForensicBundleManifest`, `ComplianceMode`.
3. `taktApi.ts` парсит ответы через `schema.parse(...)`.
4. На несоответствие — единая обработка ошибок в React Query
   `onError`.

**P1-2. Vitest + Testing Library + Playwright.**
1. `vitest` + `@testing-library/react` для:
   - `taktApi.ts` (моки через `msw`);
   - `CaseDetail.tsx` (snapshot + сценарий decision/manual-permit);
   - `IncidentQueue.tsx` (фильтры, сортировка, пагинация по Link).
2. `playwright` для smoke:
   - подъём бэкенда (с `tests/fixtures/plc_polling_demo.csv`)
     и UI, прогон сценария «обход переходного сервера».
3. Включить в GitHub Actions отдельный job `frontend-ci`.

**P1-3. CSP / nginx / SBOM фронта.**
1. Сгенерировать `frontend/takt-arm/nginx/csp.conf` с CSP, X-Frame-Options
   (бэкенд уже выставляет аналог, но фронт может за nginx).
2. `scripts/generate_frontend_sbom.py` через `@cyclonedx/cyclonedx-npm`.
3. Добавить в `release-evidence-dry-run`.

**P1-4. lucide-react и зависимости.**
1. Привести `lucide-react` к актуальной мажорной версии (или
   зафиксировать причину текущей).
2. Добавить `engines.node ≥ 20.10`, `.nvmrc`.
3. Включить `npm audit` / `pnpm audit` в CI.

**P1-5. Унификация авторизации в `main.py`.**
1. Один `Depends(get_authenticated_caller)`,
   возвращающий `Caller` с ролью.
2. Удалить дубли проверки `X-TAKT-API-Key` в эндпоинтах.

**P1-6. Защита `POST /forensic-bundle/verify`.**
1. Лимит размера через `TAKT_MAX_REQUEST_BODY_MB` (явный отдельный
   `TAKT_FORENSIC_VERIFY_MAX_MB`, по умолчанию 64).
2. Защита от zip-bomb: проверка отношения compressed/uncompressed
   и общего размера распакованного.

**P1-7. Sprint 7 в UI.**
1. Виджет `Remediation Attempts` в `CaseDetail` и сводный экран
   `/compliance/remediations`.
2. Кнопка «Перепроверить готовность» → recheck-readiness + история.

### 8.3 P2 — Технический долг

**P2-1. Объединить use-case ingest.** `POST /assess`, `/assess/demo`,
`/events`, `/events/batch` → `IngestEventUseCase` + тонкие хэндлеры.

**P2-2. Pydantic-модели и сериализаторы дат.** Унификация через
`from datetime import datetime`-сериализатор и
общий `model_config = ConfigDict(json_encoders=...)`.

**P2-3. PDF-экспорт по умолчанию использует Unicode-шрифт**, если он
есть в дистрибутиве `assets/fonts/`. Без явной настройки.

**P2-4. Дополнительные тесты для редких endpoint'ов**
(`/integrations/ingest/*`, `/cases/{id}/export/gossopka-official-transport.json`)
с моделями входных данных «грязный мир».

**P2-5. Доступность (a11y).** В IncidentQueue заменить кликабельный
`<div>` строки на правильную таблицу с `onKeyDown` и `tabIndex`,
добавить `aria-live` для счётчиков риска.

**P2-6. Локализация чисел.** Перевести все
`risk.toFixed(3).replace('.', ',')` на `Intl.NumberFormat`.

**P2-7. Удаление «локального паспорта инцидента»** или явное
визуальное разграничение «доказательный пакет» vs
«локальный паспорт» в `CaseDetail.tsx` (например, баннер
«Этот PDF не входит в доказательный пакет»).

**P2-8. Документация-«правда».** Привести `frontend/README.md`
к актуальному состоянию (что **уже сделано**, что в roadmap).
Корневой `README.md` помечать «АРМ MVP — каркас, не полное
покрытие операторских сценариев».

---

## 9. Метрики «после исправления» (DoR/DoD)

Для перехода к следующему релизу (предлагается `MVP 0.7`) считать
готовыми:

- [ ] `main.py` ≤ 400 строк; роутеры разнесены.
- [ ] 100% эндпоинтов из README покрыты Schemathesis-тестами
      (включая `/integrations/ingest/*`).
- [ ] Frontend имеет ≥ 30 unit-тестов Vitest и ≥ 3 e2e-сценария
      Playwright (включая «обход переходного сервера» end-to-end).
- [ ] Frontend SBOM CycloneDX генерируется в CI.
- [ ] UI не работает на демо-данных в compliance-режиме без явного
      маркера; все действия оператора пишутся в реальный аудиторский след.
- [ ] InvariantLibrary, TopologyMap, SettingsAudit подключены к API.
- [ ] CaseDetail полностью покрывает: decision, viewed,
      additional-review, manual-permits, remediations,
      forensic-bundle verify, formal-verdict-history,
      operator-actions/history.
- [ ] lucide-react и Node engines обновлены и зафиксированы.
- [ ] `zod` валидирует все ответы API.

---

## 10. Дорожная карта (sprint-grade)

| Sprint | Скоуп | DoD |
|--------|-------|-----|
| S1 (1 неделя) | P0-1 (роутеры), P1-5 (auth depends) | green CI, 0 регрессий контракта |
| S2 (1 неделя) | P0-2, P0-3 (frontend → real API; manual permits) | e2e: «легитимное действие» через UI |
| S3 (1 неделя) | P0-4, P0-5 (invariants, compliance в UI) | compliance-banner и реальные веса |
| S4 (1 неделя) | P1-1, P1-2 (zod + vitest/playwright) | покрытие фронта ≥ 60% |
| S5 (1 неделя) | P1-3, P1-4 (CSP, SBOM, deps) | release-evidence-dry-run включает фронт |
| S6 (1 неделя) | P1-6, P1-7, P2-* | внутренняя приёмка MVP 0.7 |

---

## Приложение А. Список зарегистрированных HTTP-эндпоинтов

(60 уникальных пар метод+путь)

```
GET    /audit-engagements
GET    /audit-engagements/{engagement_id}
GET    /audit-engagements/{engagement_id}/export/report.json
GET    /audit-ledger/operations/verify
GET    /cases
GET    /cases/export/full.json
GET    /cases/stats
GET    /cases/{case_id}
GET    /cases/{case_id}/audit-ledger/verify
GET    /cases/{case_id}/compliance/evidence-checklist
GET    /cases/{case_id}/compliance/remediations/recheck-readiness/history
GET    /cases/{case_id}/export.pdf
GET    /cases/{case_id}/export/gossopka-official-transport.json
GET    /cases/{case_id}/export/gossopka-official.json
GET    /cases/{case_id}/export/gossopka-transport.json
GET    /cases/{case_id}/export/gossopka.json
GET    /cases/{case_id}/export/siem.json
GET    /cases/{case_id}/forensic-bundle.zip
GET    /cases/{case_id}/forensic-bundle/manifest
GET    /cases/{case_id}/formal-verdict/history
GET    /cases/{case_id}/operator-actions/history
GET    /catalog/event-sources
GET    /compliance/data-quality-report
GET    /compliance/forensic-readiness
GET    /compliance/mode
GET    /compliance/remediation-kinds
GET    /compliance/remediations
GET    /data-quality
GET    /health
GET    /invariants
GET    /live
GET    /ready
GET    /topology/demo-graph
HEAD   /health
HEAD   /live
HEAD   /ready
POST   /assess
POST   /assess/demo
POST   /audit-engagements
POST   /audit-engagements/{engagement_id}/advance-stage
POST   /audit-engagements/{engagement_id}/final-report
POST   /audit-engagements/{engagement_id}/findings
POST   /backtest/fixture
POST   /cases/import/full.json
POST   /cases/{case_id}/compliance/remediations
POST   /cases/{case_id}/compliance/remediations/recheck-readiness
POST   /cases/{case_id}/decision
POST   /cases/{case_id}/formal-verdict/confirmation
POST   /cases/{case_id}/manual-permits
POST   /cases/{case_id}/operator-actions/additional-review
POST   /cases/{case_id}/operator-actions/viewed
POST   /events
POST   /events/batch
POST   /forensic-bundle/verify
POST   /integrations/ingest/ipfix
POST   /integrations/ingest/netflow
POST   /integrations/ingest/snmp/trap
POST   /integrations/ingest/syslog/rfc5424
POST   /integrations/siem/forward
POST   /integrations/siem/forward/async
```

## Приложение Б. Использование backend API во фронте

| Эндпоинт | Файл фронта | Метод вызова |
|----------|-------------|--------------|
| `GET /cases/{id}` | `app/taktApi.ts::fetchCaseDetail` | `fetch` |
| `POST /cases/{id}/formal-verdict/confirmation` | `app/taktApi.ts::sendFormalVerdictConfirmation` | `fetch` |
| `GET /cases/{id}/forensic-bundle/manifest` | `app/taktApi.ts::fetchForensicBundleManifest` | `fetch` |
| `GET /cases/{id}/forensic-bundle.zip` | `app/taktApi.ts::downloadForensicBundle` | `fetch` blob |

**Всего: 4 эндпоинта из 60** интегрированы во фронт.

---

## Приложение В. Замеры

```
backend python   : 12 404 LOC
tests python     : 12 827 LOC
frontend src     : ~2 870 LOC (.ts/.tsx без stories)

main.py          : 3 600 строк (152 KB)  <-- кандидат на дробление
sqlite_store.py  :   ~1 200 строк (48 KB)
forensic_bundle  :     ~800 строк (31 KB)

Зарегистрированных HTTP-эндпоинтов: 60
Интегрированных во фронт: 4
Покрытие фронта API: 6.7%
```

---

**Конец отчёта.**

Этот файл предлагается зафиксировать в репозитории
`takt-industrial-risk-layer/` под именем `AUDIT_REPORT.md`
и использовать как DoR для следующего release-окна.
