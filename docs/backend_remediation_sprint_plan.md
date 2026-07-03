# Backend Remediation Status

Date: 2026-05-28

This document is now a status snapshot for the audit remediation work that was originally planned on 2026-05-20. The backend remediation scope S0-S8 is complete. It is kept here as release evidence and as a guardrail for future cleanup.

## Product Boundary

The backend remains inside the TAKT product boundary:

- TAKT is not an active control system.
- TAKT is not a SKZI.
- A human operator remains in the loop.
- The API must not add endpoints, buttons, scripts, or scenarios for stopping PLCs, sending commands to equipment, blocking accounts, disabling nodes, or otherwise actively controlling industrial assets.

## Completed Scope

- S0 public backend contracts are covered by OpenAPI snapshot and contract smoke tests.
- S1 split the former `src/takt/interface_adapters/api/main.py` god-object into `app.py`, `routers/`, `schemas/`, `dependencies.py`, and helper modules. `main.py` is a thin compatibility entrypoint.
- S2 moved repeated API business glue into application facades and query services for ingest, cases, compliance, forensic/export, case actions, and audit ledger workflows.
- S3 split the SQLite store into connection, schema, mappers, stores, recent events, and migration helpers. `sqlite_store.py` remains a facade over the split modules.
- S4 unified `/events` and `/events/batch` through `IngestFacade` and persistent recent event/idempotency support.
- S5 hardened forensic/export behavior, including shared strict signing handling, supplemental audit engagement files, and engagement error handling.
- S6 completed HITL/compliance flows for operator decisions, manual permits, evidence readiness, and audit engagement summaries.
- S7 kept HTTP perimeter checks, authentication wiring, body limits, and observability in dedicated infrastructure/API helpers.
- S8 added backend architecture guards, OpenAPI snapshot coverage, and release readiness evidence in `docs/backend_release_readiness.md`.

## Current Cleanup State

- `src/takt/interface_adapters/api/main.py` is bounded as a compatibility entrypoint by `tests/test_backend_architecture_guard.py`.
- `src/takt/interface_adapters/api/app.py` owns FastAPI assembly only; Prometheus registration delegates to `src/takt/interface_adapters/api/metrics.py`.
- `src/takt/interface_adapters/api/mappers/cases.py`, `pagination.py`, `openapi.py`, `config_paths.py`, `lifecycle.py`, `event_sources.py`, and `metrics.py` hold helper responsibilities that were previously embedded in the app factory.
- `src/takt/infrastructure/stores/sqlite_store.py` remains under the architecture guard limit and delegates to split SQLite modules.

## Latest Local Verification

The backend remediation itself has no open S0-S8 items. The latest local verification after cleanup completed:

- Targeted Prometheus and architecture tests: `25 passed, 1 skipped`.
- Full backend regression: `720 passed, 1 skipped`.
- Frontend release gate from `frontend/takt-arm`: passed, including workspace boundary, API client contract, unit tests, production build, frontend SBOM, Playwright smoke, and release artifact checks.
- Boundary scans for external workspace references and active-control language: no matches.
- Backend SBOM was regenerated in `dist/`.
- Strict release package was built and verified with `scripts/verify_release_package.py`; both package directory and zip archive verification are covered, including manifest completeness and path-escape checks.

## Remaining Work

No code remediation items remain in S0-S8. The remaining items are operational and environment-specific:

- Confirm production/preproduction environment variables, secrets, storage paths, and signer/verifier endpoints.
- Run deployment smoke checks in the target environment.
- Import Grafana dashboard and Prometheus alert rules into the target observability stack.
- Keep future changes within the product boundary and re-run the gates above before release.

## Verification Commands

```powershell
python -m pytest -q tests/test_prometheus_metrics.py tests/test_backend_architecture_guard.py
python -m pytest -q
rg -n "<external-workspace-markers>" .github docs scripts tests frontend\takt-arm src
rg -n "Демо-управление|управление вне интерфейса|отправить команду|остановить ПЛК|shutdown plc|stop plc|disable node|block account" frontend\takt-arm\src src\takt\interface_adapters\api
```
