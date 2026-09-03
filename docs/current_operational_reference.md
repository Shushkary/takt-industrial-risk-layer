# Current Operational Reference

Актуальный reference по текущему состоянию API/CI/эксплуатации.
Если есть расхождение с историческими планами по спринтам, приоритет у этого файла, `README.md` и `.github/workflows/ci.yml`.

---

## Числа-факты (единственное место хранения)

Эти значения нельзя дублировать в других документах и во внешних инструкциях — только ссылаться на этот раздел. Дублирование уже приводило к расхождению (документация утверждала «25 инвариантов» при 26 в коде).

| Факт | Значение | Где проверяется |
|---|---|---|
| Версия пакета | `0.6.23` | `pyproject.toml`, `tests/test_package_version.py` |
| Поддерживаемый Python | `>=3.11`, матрица CI 3.11–3.14 | `pyproject.toml`, `.github/workflows/ci.yml` |
| Python в Docker-образе | 3.13 | `Dockerfile` |
| Доменных инвариантов | 26 (enum `InvariantId`, 26 файлов `config/invariants/*.yaml`) | `tests/test_invariant_catalog.py`, `tests/test_invariant_catalog_yaml.py`, `tests/test_docs_invariant_count_consistency.py` |
| Инвариантов с baseline-протоколом детектирования | 11 из 26, синтетический корпус | `docs/detection_quality.md` |
| Инвариантов отключено в проде (`builtin:noop`) | 6 из 26, известный разрыв | `docs/invariant_matrix.md` |
| Версия схемы SQLite | `LATEST_SCHEMA_VERSION = 8` | `scripts/db_migrate.py`, `sqlite_schema_version` в `GET /health` |
| Объём backend-прогона | порядка 840 тестов, ~1,5–4 мин | точное значение — вывод `python -m pytest` |

Число тестов намеренно не фиксируется точно: оно меняется каждым коммитом, а устаревшая цифра в документации хуже её отсутствия.

---

## API блоки (production-ready в текущем коде)

- `POST /cases/{id}/compliance/remediations`
- `POST /cases/{id}/compliance/remediations/recheck-readiness`
- `GET /cases/{id}/compliance/remediations/recheck-readiness/history`
- `GET /cases/{id}/forensic-bundle/manifest`
- `GET /cases/{id}/forensic-bundle.zip`
- `POST /forensic-bundle/verify`
- `POST /audit-engagements`
- `GET /audit-engagements`
- `GET /audit-engagements/{id}`
- `POST /audit-engagements/{id}/advance-stage`
- `POST /audit-engagements/{id}/findings`
- `POST /audit-engagements/{id}/final-report`
- `GET /audit-engagements/{id}/export/report.json`
- `GET /cases/{id}/export/gossopka.json`
- `GET /cases/{id}/export/gossopka-transport.json`
- `GET /cases/{id}/export/gossopka-official.json`
- `GET /cases/{id}/export/gossopka-official-transport.json` (smoke gate для `gossopka_official_ok`)
- `POST /cases/assemble/auto` (повтор сборки ядра инцидентов с другим порогом отличительности; при
  приёме тот же шаг выполняется сам — `incident_assembly.on_ingest`; SQLite backend)
- `GET /cases/{id}/audit-ledger/verify` (SQLite backend)
- `GET /audit-ledger/operations/verify` (SQLite backend)

---

## Подпись forensic root hash

- Режимы:
  - `unsigned_mvp`
  - `hmac_sha256_mvp` (при `TAKT_FORENSIC_HMAC_SECRET`)
  - `external_qualified_detached` (через внешний HTTP signer/verifier)
  - `external_gost2012_detached` (strict crypto-контур при `TAKT_FORENSIC_CRYPTO_MODE=gost_strict`)
- Для `gost_strict`: HMAC не считается допустимым fallback для `signature_status`; требуется внешний signer/verifier.
- При недоступном signer в `gost_strict` export endpoints (`/cases/{id}/forensic-bundle/manifest`, `/cases/{id}/forensic-bundle.zip`) возвращают `503` с `detail=forensic_signing_unavailable: ...`.
- Внешний адаптер:
  - `TAKT_FORENSIC_SIGN_URL`
  - `TAKT_FORENSIC_VERIFY_URL`
  - `TAKT_FORENSIC_SIGNATURE_TIMEOUT_SEC`

---

## Ledger immutability (SQLite)

- Append-only таблицы:
  - `case_audit_ledger`
  - `operation_audit_ledger`
- CLI verify:
  - `scripts/verify_audit_ledger.py`
  - `scripts/verify_operation_ledger.py`

---

## SBOM / Release gates

- SBOM файл: `dist/sbom.cyclonedx.json`
- Генерация: `python scripts/generate_sbom.py`
- Frontend SBOM: `frontend/takt-arm/dist/frontend-sbom.cyclonedx.json`, generation via `cd frontend/takt-arm && npm run sbom:frontend`.
- Frontend static delivery CSP: `frontend/takt-arm/nginx/csp.conf`.
- Frontend local release gate: `cd frontend/takt-arm && npm run test:frontend`.
- Frontend test stack includes contract checks plus 44 Vitest/MSW/Testing Library unit tests and Playwright e2e smoke against the production `dist` bundle; Playwright covers shell boundary, queue-to-case decision, manual permit to formal verdict, and local forensic export/verify boundary scenarios.
- Frontend Node runtime is pinned by `frontend/takt-arm/.nvmrc` (`22`) and `package.json` engines (`node >=20.10`); dependency audit command is `npm run audit:frontend`.
- CI job **`frontend-ci`** (`.github/workflows/ci.yml`): `npm ci`, lint, `test:frontend`, `audit:frontend`, Storybook build.
- Frontend API client uses `zod` runtime validation for base response guards and explicit DTO schemas for cases, manual permits, forensic manifests, invariants, topology demo graph, and event batch ingest responses; validation errors are normalized as Russian API errors.
- Backend API-key enforcement stays centralized in `OptionalApiKeyMiddleware` plus OpenAPI security wiring; routers do not read `TAKT_API_KEY`, `X-TAKT-API-Key`, or `Authorization` directly, and an architecture guard enforces this boundary.
- Frontend shell shows `/compliance/mode` and `/ready` badges in API mode, shows an explicit `Локальный демонстрационный режим` badge when no backend API is configured, and disables local scenario/segment demo controls whenever a backend API is configured; those controls remain available only in explicit local demo mode.
- Frontend invariant library reads `/invariants`, `/catalog/event-sources`, and `/compliance/mode`; in API mode it does not invent local weights, thresholds, or trigger counters when the server does not provide them, and local invariant reports are blocked in compliance mode.
- If `/invariants` is unavailable in API mode, the invariant library shows an API error state instead of claiming a local fallback catalog as working data.
- Frontend topology map renders the main graph from `/topology/demo-graph` when the backend graph is loaded; the local visual topology remains only a fallback for local demo mode or unavailable API. In API mode, local scenario buttons, period/object filters, and risk sliders are disabled and do not affect backend graph risk display.
- Frontend segment overview uses `/cases/stats`, `/health`, and `/compliance/data-quality-report` in API mode, and the incident queue exposes `/cases` pagination evidence from `X-Total-Count` and `Link`.
- Incident queue status chips map to `/cases?status=...` query values in API mode, keep API filters available regardless of the current page contents, and reset pagination offset when the status filter changes.
- Incident queue selectable rows expose keyboard selection plus accessible row names, and API loading/pagination changes are announced through `aria-live`.
- Local queue reports are explicitly non-evidence and are blocked in compliance mode unless the backend API is configured.
- Local settings/audit reports are explicitly non-evidence and are blocked in compliance mode; evidence must come from backend ledger verification, forensic readiness, and audit engagement APIs.
- Operator-facing frontend status strings are Russian in the shell, case detail, incident queue, invariant library, topology map, segment overview, and settings/audit; technical API field names and endpoint labels remain unchanged where they identify backend contracts.
- Frontend numeric formatting for risk and percentage values is centralized through `Intl.NumberFormat('ru-RU')`; source guards reject hand-rolled `toFixed(...).replace('.', ',')` formatting in operator views.
- Frontend demo-to-real ingest fixture: `frontend/takt-arm/src/demo/apiEvents.ts`; it posts Moscow heat-energy observations through `/events/batch` via `ingestEventBatch`.
- The demo ingest fixture is telemetry input only: no equipment commands, no active control, and all operator decisions remain human-in-loop.
- Backend `/events` and `/events/batch` share `IngestAssessmentFacade.prepared_event_ingest_body(...)` for normalization metadata and raw evidence preparation; API code only orchestrates source coercion, HTTP errors, and response mapping.
- Case DTO import/export mapping lives in `src/takt/interface_adapters/api/mappers/cases.py`; `app.py` wires the mapper callables but does not own case-detail conversion logic.
- Offset/limit `Link` header construction lives in `src/takt/interface_adapters/api/pagination.py` and is wired into case/compliance routers through `ApiContext`.
- OpenAPI server and API-key security patching lives in `src/takt/interface_adapters/api/openapi.py`; `app.py` keeps compatibility wrappers for legacy tests/imports only.
- API config path resolution and invariant-catalog path selection live in `src/takt/interface_adapters/api/config_paths.py`; `app.py` keeps compatibility wrappers while enforcing `TAKT_CONFIG` stays under the project root.
- FastAPI lifespan startup/shutdown handling lives in `src/takt/interface_adapters/api/lifecycle.py`; `app.py` injects auth validation, security startup snapshot, version, and logger.
- API event-source string coercion lives in `src/takt/interface_adapters/api/event_sources.py`; `app.py` keeps a compatibility wrapper for legacy imports.
- Prometheus registration helpers live in `src/takt/interface_adapters/api/metrics.py`; the API layer keeps metrics optional and gated by `TAKT_METRICS`.
- Frontend case detail now reads API compliance context: `/cases/{id}/operator-actions/history`, `/cases/{id}/compliance/evidence-checklist`, `/compliance/remediations`, remediation readiness recheck history, forensic manifest/ZIP/verify, and local notes are marked non-evidence.
- Case detail local print/PDF and local note exports are visibly marked non-evidence; machine-verifiable case evidence is the server forensic ZIP plus `/forensic-bundle/verify`.
- `/forensic-bundle/verify` rejects oversized archives before ZIP parsing and validates ZIP structure without extracting to disk: file count, unsafe paths/path traversal, total uncompressed size, and compression ratio are guarded.
- Forensic ZIP supplemental audit-engagement files are prepared inside `ForensicExportFacade`; missing engagement IDs return 404 and engagements not linked to the requested case return 400.
- Frontend settings/audit now verifies `/audit-ledger/operations/verify`, optional `/cases/{id}/audit-ledger/verify`, and lists `/audit-engagements`.
- Settings/audit local air-gap confirmation is visibly marked non-evidence; machine-verifiable audit status comes from backend ledger verification APIs.
- Compliance audit-engagement totals in `/compliance/mode` and `/compliance/data-quality-report` are computed inside `ComplianceFacade` from `ManageAuditEngagementUseCase`; app factory no longer owns this aggregation.
- CI job **`release-gates`** (`.github/workflows/ci.yml`):
  - CycloneDX SBOM generation + artifact check
  - Monitoring artifacts gate
  - Ledger verifier smoke gate (SQLite fixture + CLI `verify_*_ledger`)
  - `pip-audit`
  - Schemathesis (ограниченный прогон)
  - Mutation gate (`weights_loader.py`)
- CI job **`release-evidence-dry-run`**: выполняет `scripts/release_finalize.py` (локальный API smoke через `close_operational_tails.py`), автозаполнение prod-ready, `validate_prod_ready`, frontend evidence dry run (`npm run test:frontend`, включая frontend SBOM), затем `build_release_package.py` + `verify_release_package.py`. Strict package build fails if backend SBOM, frontend SBOM, or frontend CSP artifact is missing.
- `release_finalize.py` после smoke в evidence проверяет флаги **в указанном порядке** (первая несработка попадает в `release_reason`):
  - `gossopka_official_ok=true`
  - `forensic_signing_unavailable=false` (при `true` — блокирующее условие)
  - `forensic_verify_ok=true`
  - `audit_engagement_api_ok=true`

---

## Monitoring artifacts

- Grafana dashboard:
  - `deploy/monitoring/grafana/takt-business-observability-dashboard.json`
- Prometheus alerts:
  - `deploy/monitoring/prometheus/alerts.business-observability.rules.yml`
- Проверка артефактов:
  - `tests/test_monitoring_artifacts.py`

---

## Release docs map

- Minimal gate checklist: `docs/release_checklist.md`
- Readiness status snapshot: `docs/release_readiness_status.md`
- Per-release template: `docs/release_readiness_template.md`
- Folder for filled cards: `docs/releases/`
- Audit closure note (локально закрыто / остаток среды): `docs/releases/2026-05-08_audit_closure_note.md`
- Ops handover checklist (формальное закрытие в среде): `docs/releases/2026-05-08_ops_handover.md`
