# Release checklist

Продукт: **TAKT Industrial Risk Layer**.

Этот файл фиксирует минимальный gate перед тегом/образом. Для конкретной выкладки копируйте `docs/release_readiness_template.md` в `docs/releases/` и заполняйте карточку окружения.

## Автоматические проверки

- [ ] `python -m pytest -q` зелёный.
- [ ] `lint-imports --config pyproject.toml` зелёный.
- [ ] GitHub Actions jobs `release-gates` и **`release-evidence-dry-run`** зелёные.
- [ ] `scripts/generate_sbom.py` сформировал `dist/sbom.cyclonedx.json`.
- [ ] `pip-audit` не нашёл уязвимостей в зависимостях проекта.
- [ ] Schemathesis gate прошёл без 500-ответов без `request_id`.
- [ ] Mutation gate прошёл в согласованном scope.
- [ ] Monitoring artifacts gate прошёл (наличие dashboard/rules + `tests/test_monitoring_artifacts.py`).
- [ ] Ledger verifier smoke gate прошёл (`scripts/verify_audit_ledger.py` и `scripts/verify_operation_ledger.py`).
- [ ] Предрелизный smoke через `release-evidence-dry-run` (в т.ч. `gossopka_official_ok`, forensic verify, `/audit-engagements` + `/export/report.json`) или эквивалентный локальный `release_finalize` / `runbook_smoke_checks.md` после выкладки.

## Данные и миграции

- [ ] `scripts/db_migrate.py --db <target.db>` выполнен на целевой БД или подтверждено, что миграция не требуется.
- [ ] `sqlite_schema_version` в `/health` совпадает с поддерживаемой версией приложения.
- [ ] Перед выкладкой сделан backup через `scripts/db_backup.py`.
- [ ] Rollback-план согласован с учетом версии схемы SQLite.

## Конфигурация

- [ ] `TAKT_AUTH_REQUIRED=true` в prod/preprod и задан непустой `TAKT_API_KEY`.
- [ ] `TAKT_CONFIG` указывает на утвержденный `risk_weights.yaml`.
- [ ] `TAKT_STORAGE` / `TAKT_SQLITE_PATH` заданы для сред, где нужна персистентность; пути остаются внутри корня репозитория.
- [ ] SIEM allowlist и `TAKT_SECURITY_PROFILE` соответствуют среде.
- [ ] `TAKT_FORENSIC_CRYPTO_MODE` согласован с контуром: `mvp` или `gost_strict`.
- [ ] Для `mvp`: настроен `TAKT_FORENSIC_HMAC_SECRET` или внешний signer/verifier (либо явно зафиксирован unsigned режим).
- [ ] Для `gost_strict`: заданы `TAKT_FORENSIC_SIGN_URL` и `TAKT_FORENSIC_VERIFY_URL`; HMAC как fallback не используется.
- [ ] Smoke подтверждает `forensic_verify_ok=true` для проверочного forensic bundle.
- [ ] Для `gost_strict`: smoke не возвращает `503 forensic_signing_unavailable` на `/cases/{id}/forensic-bundle/manifest` и `/cases/{id}/forensic-bundle.zip`.
- [ ] Smoke подтверждает `gossopka_official_ok=true` (`/cases/{id}/export/gossopka-official-transport.json`).

## Наблюдаемость

- [ ] `/metrics` доступен в нужной среде при `TAKT_METRICS=1`.
- [ ] Grafana dashboard импортирован из `deploy/monitoring/grafana/`.
- [ ] Prometheus alert rules импортированы из `deploy/monitoring/prometheus/`.
- [ ] OpenTelemetry явно помечен как N/A или проверен отдельным приемочным сценарием.

## Ревью

- [ ] Изменения `config/risk_weights.yaml` просмотрены ответственным инженером.
- [ ] Изменения `config/invariants/*.yaml` просмотрены ответственным инженером.
- [ ] Release readiness card заполнена в `docs/releases/`.
- [ ] Тег/образ собран из зафиксированного SHA.

## Подпись

| Роль | Имя | Дата | Комментарий |
|------|-----|------|-------------|
| Tech lead | | | |
| Operations | | | |
| Product / заказчик | | | |
