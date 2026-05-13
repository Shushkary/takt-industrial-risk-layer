# Ops Handover — Audit Closure (2026-05-08)

Проект: `takt-industrial-risk-layer`  
Базовый коммит: `1a1c5f4`  
Связанный документ: `2026-05-08_audit_closure_note.md`

## Цель

Закрыть оставшиеся пункты аудита, которые требуют целевой среды и операционной приёмки.

## 1) Production configuration freeze

- [ ] Зафиксировать `TAKT_AUTH_REQUIRED=true` и непустой `TAKT_API_KEY`.
- [ ] Утвердить `TAKT_CONFIG` (путь внутри project root).
- [ ] Зафиксировать storage-параметры: `TAKT_STORAGE`, `TAKT_SQLITE_PATH`.
- [ ] Для `gost_strict`: задать `TAKT_FORENSIC_SIGN_URL` и `TAKT_FORENSIC_VERIFY_URL`.
- [ ] Утвердить SIEM-параметры (`allowlist`, профиль, retries/backoff).

Артефакт: ссылка на change request / ops ticket с финальными значениями.

## 2) Database pre-deploy

- [ ] Выполнить backup целевой БД (`scripts/db_backup.py`).
- [ ] Выполнить migrate (`scripts/db_migrate.py`) или задокументировать, что не требуется.
- [ ] Проверить `sqlite_schema_version` через `/health`.
- [ ] Обновить rollback-план с учётом версии схемы.

Артефакт: логи backup/migrate + скрин/вывод `/health`.

## 3) Post-deploy smoke (blocking)

- [ ] `GET /ready` возвращает ready state для целевого режима.
- [ ] `POST /assess` создаёт кейс и возвращает `case_id`.
- [ ] `GET /cases/<CASE_ID>/export/gossopka-official-transport.json` -> `200`.
- [ ] `GET /cases/<CASE_ID>/forensic-bundle.zip` + `POST /forensic-bundle/verify` -> `ok=true`.
- [ ] В strict-среде нет `forensic_signing_unavailable`.
- [ ] `POST /audit-engagements` + `GET /audit-engagements/<ENGAGEMENT_ID>/export/report.json` успешны.

Артефакт: smoke-лог и/или operational evidence markdown.

## 4) Observability onboarding

- [ ] Импортировать dashboard: `deploy/monitoring/grafana/takt-business-observability-dashboard.json`.
- [ ] Импортировать правила: `deploy/monitoring/prometheus/alerts.business-observability.rules.yml`.
- [ ] Проверить доступность `/metrics` в целевой среде.
- [ ] OpenTelemetry: пометить `N/A` или приложить отдельный приёмочный отчёт.

Артефакт: ссылки на Grafana/Alertmanager + скрин/экспорт правил.

## 5) Formal sign-off

- [ ] Обновить `2026-05-07_v0.6.23_readiness.md` фактическими полями среды.
- [ ] Проставить подписи ролей: Dev / Security / Ops / Product.
- [ ] Закрыть релизный/аудитный тикет с ссылками на evidence.

## Минимальный критерий «аудит закрыт»

Все чекбоксы выше отмечены, а evidence хранится в `docs/releases/` или в релизном тикете с постоянными ссылками.
