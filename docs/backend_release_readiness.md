# Backend Release Readiness

Date: 2026-05-28

Backend status: ready for frontend integration against the real API.

This document records the S0-S8 backend remediation gate before frontend work starts. It is intentionally scoped to backend behavior, CI evidence, and product-boundary controls.

## S0-S8 backend remediation gate

| Gate | Evidence | Status |
| --- | --- | --- |
| S0 public API baseline | `tests/test_openapi_contract_snapshot.py`, `docs/backend_public_contracts_sprint0.md` | Complete |
| S1 API split | `src/takt/interface_adapters/api/main.py` is a thin compatibility entry point; routers, schemas, dependencies, and app factory are split out | Complete |
| S2 application facades | ingest, cases, compliance, forensic/export, case actions, and audit ledger facades keep API routers thin | Complete |
| S3 SQLite storage split | SQLite connection, schema, case mapping, audit engagement, ledger, recent events, and migration runner are separated | Complete |
| S4 ingest reliability | idempotency and SQLite-backed recent context are covered by tests | Complete |
| S5 forensic/export hardening | bundle verification rejects unsafe zip structure, excessive files, oversized archives, and compression-ratio abuse | Complete |
| S6 HITL and compliance | decisions, operator actions, manual permits, and formal verdicts write audit evidence | Complete |
| S7 HTTP perimeter | unsafe auth/CORS startup config fails fast; async SIEM forwarding is bounded | Complete |
| S8 release gate | CI, OpenAPI snapshot, Schemathesis, backtest regression, domain policy, SBOM, and release evidence are tracked | Complete |

## Release gate checks

- Full backend regression: `python -m pytest -q`.
- architecture guard: `tests/test_backend_architecture_guard.py` keeps `main.py` thin, router modules bounded, SQLite split modules present, and application facades independent from delivery frameworks.
- OpenAPI snapshot: `tests/test_openapi_contract_snapshot.py` fixes public route methods, paths, tags, and response contract names.
- Schemathesis: CI runs `/openapi.json` with all checks and bounded examples.
- Error contract: HTTP middleware tests require structured error JSON with `request_id`.
- Backtest regression: `tests/test_backtest_legacy_regression.py` covers the `plc_polling_demo.csv` fixture.
- domain purity policy: `tests/test_domain_pure.py`, `tests/test_domain_ast_policy.py`, and import-linter contracts keep L1 free from FastAPI, ORM, network, filesystem, and cryptography dependencies.
- Product boundary: API remains advisory and evidence-oriented, with no active equipment control, no SCZI scope expansion, and human remains in the loop.
- Release evidence: CI runs ledger verifier smoke, release finalize dry run, frontend evidence dry run, release package build, and package verification. Strict package build fails when backend SBOM, frontend SBOM, or frontend CSP evidence is missing.
- SBOM: CI generates and verifies a CycloneDX SBOM artifact.

## Latest local evidence

- Backend targeted Prometheus/architecture tests: `25 passed, 1 skipped`.
- Full backend regression: `720 passed, 1 skipped`.
- Frontend local gate `npm run test:frontend`: passed, including build, frontend SBOM, Playwright smoke, and release artifact checks.
- Backend SBOM: regenerated in `dist/`.
- Strict release package: built under `dist/release-package-20260528T022439Z`; both the package directory and `dist/release-package-20260528T022439Z.zip` verify with `scripts/verify_release_package.py`.
- Release package verifier hardening: zip verification rejects invalid zip files, path traversal, duplicate zip entries, symlink entries, archives without a root `manifest.json`, excessive file counts, excessive uncompressed size, and excessive compression ratio; package directories reject symlinks; invalid manifest JSON is reported as a controlled verification failure; manifest file lists cannot escape the package root; nested manifests, duplicate manifest entries, and extra unmanifested files are rejected; checksum keys must exactly match `included_files`; checksum values must be SHA-256 hex digests; tampering is detected by checksum; and `manifest.status` must be `READY`.
- Release package verifier UX: `verify_release_package.py` accepts a positional package directory or zip archive, plus explicit `--package-dir` / `--package-zip` forms for CI.
- Release package verifier limits: zip file count, total uncompressed size, and compression ratio limits can be tightened through CLI flags or `TAKT_RELEASE_VERIFY_*` env defaults while keeping conservative defaults for release gates.
- Release package manifest metadata: verifier requires valid `generated_at_utc`, relative timestamped `package_dir` with a matching timestamp, `evidence_file`, and `prod_ready_file`; evidence/prod-ready metadata must name different package-root files and those files must be included in the manifest; `included_files` entries must be package-root filenames.
- Product boundary scans: no external workspace references or active-control phrases found in the checked source/API/UI paths.

## Frontend integration note

Frontend work may connect to the real backend API after this backend gate remains green. Frontend must not emulate backend decisions locally, must not introduce active equipment control flows, and must continue to present operator actions as human-confirmed audit events.
