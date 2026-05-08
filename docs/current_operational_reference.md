# Current Operational Reference

Актуальный reference по текущему состоянию API/CI/эксплуатации.
Если есть расхождение с историческими планами по спринтам, приоритет у этого файла, `README.md` и `.github/workflows/ci.yml`.

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
- CI job **`release-gates`** (`.github/workflows/ci.yml`):
  - CycloneDX SBOM generation + artifact check
  - Monitoring artifacts gate
  - Ledger verifier smoke gate (SQLite fixture + CLI `verify_*_ledger`)
  - `pip-audit`
  - Schemathesis (ограниченный прогон)
  - Mutation gate (`weights_loader.py`)
- CI job **`release-evidence-dry-run`**: выполняет `scripts/release_finalize.py` (локальный API smoke через `close_operational_tails.py`), автозаполнение prod-ready, `validate_prod_ready`, затем `build_release_package.py` + `verify_release_package.py`.
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
