# Release readiness status (TAKT Industrial Risk Layer)

**Шаблон для новых релизов:** см. [`release_readiness_template.md`](release_readiness_template.md) — скопируйте в `docs/releases/` (или свой каталог), заполните и приложите к тегу/образу.
**Операционный reference:** см. [`current_operational_reference.md`](current_operational_reference.md) — актуальные API/CI/env точки контроля.

Ниже — **живая сводка по коду** без привязки к конкретной версии или дате релиза.

Краткий чеклист: что уже закрыто в коде и что остаётся для формального прод-релиза под конкретную среду эксплуатации. Целевой репозиторий: `takt-industrial-risk-layer`.

---

## Готово в продукте (код и тесты)

| Область | Статус | Примечание |
|--------|--------|------------|
| Sprint 7 remediation | Готово | Журнал попыток, поля action/result/readiness, речек readiness, история/пагинация, forensic/SIEM/GosSOPKA маппинги |
| PDF evidence | Готово | SHA-256 экспорта в кейсе, заголовок ответа, SIEM/forensic payload |
| Конфигурация | Готово | Pydantic-схема для `risk_weights.yaml` |
| Forensic bundle подпись root hash | Готово MVP + strict-gate | HMAC MVP; внешний HTTP sign/verify (`TAKT_FORENSIC_SIGN_URL`, `TAKT_FORENSIC_VERIFY_URL`), режим `gost_strict` с readiness gate и без HMAC fallback |
| Forensic strict readiness | Готово | `/health` и `/ready` отдают `forensic_crypto_mode`, `forensic_strict_ready`, `forensic_strict_missing`; при misconfig strict режим возвращает `503` на `/ready`, при недоступном signer forensic export endpoints возвращают `503 forensic_signing_unavailable` |
| GosSOPKA | Готово MVP + транспорт | Карточка + строгая валидация; envelope `GET .../export/gossopka-transport.json`; official-format для smoke/release gate `GET .../export/gossopka-official-transport.json` |
| Audit engagement workflow | Готово | API `/audit-engagements*`, экспорт `.../export/report.json`, SQLite persistence |
| Observability (Prometheus) | Готово | Бизнес-метрики: risk score, invariant hits, DQ ratio, event-to-case latency, merges |
| Grafana / alerts (артефакты) | Готово | `deploy/monitoring/grafana/`, `deploy/monitoring/prometheus/`; тесты `tests/test_monitoring_artifacts.py` |
| Release gate (CI) | Готово | `release-gates`: SBOM, monitoring, ledger CLI fixture, pip-audit, Schemathesis, mutmut; `release-evidence-dry-run`: полный локальный smoke (`close_operational_tails` → флаги `gossopka_official_ok` / forensic / audit) + упаковка и verify манифеста |
| SQLite migrations / backup | Готово | `scripts/db_migrate.py`, `scripts/db_backup.py`; тесты |
| Audit immutability | Готово (SQLite) | Append-only `case_audit_ledger`, `operation_audit_ledger`; API verify; CLI `scripts/verify_audit_ledger.py`, `scripts/verify_operation_ledger.py` |

---

## Частично / зависит от эксплуатации

| Область | Что сделано | Что нужно среде |
|--------|-------------|-----------------|
| КЭП / ГОСТ / СКЗИ | Контракт HTTP + верификация; не встроен криптопровайдер | Реальный сертифицированный сервис подписи/проверки, согласование формата `signature` и ответа verify |
| GosSOPKA production | Внутренний контракт + transport envelope | Официальная схема и транспорт оператора (СМЭВ/шлюз и т.д.), приёмка по их ТЗ |
| Audit ledger | Полная цепочка на SQLite; in-memory без ledger | Для non-SQLite: либо документировать ограничение, либо вынести ledger в отдельное хранилище |

---

## Рекомендуемые шаги до «закрытого» прод-релиза

1. **Подпись**: задеплоить внешний signer/verifier по ГОСТ/КЭП; прогнать приёмочные сценарии verify на реальных архивах.
2. **GosSOPKA**: заменить/расширить `TAKT-GosSOPKA-MVP` под утверждённый оператором формат; добавить валидатор под их JSON Schema/XSD.
3. **OpenTelemetry**: при необходимости требований — spans вокруг assess/export/critical use cases (сейчас фокус на Prometheus).
4. **Операционка**: импорт правил Prometheus в реальный Alertmanager; импорт dashboard в Grafana; datasource variable `DS_PROMETHEUS`.
5. **Резервное копирование**: внедрить расписание `scripts/db_backup.py` и политику хранения.
6. **Документация эксплуатации**: переменные окружения для подписи, path БД, version схемы после `db_migrate`, и smoke gates `gossopka_official_ok=true` + `forensic_signing_unavailable=false` + `forensic_verify_ok=true` + `audit_engagement_api_ok=true`.

---

## Быстрые ссылки на артефакты

- Forensic / подпись: `src/takt/infrastructure/export/forensic_bundle.py`, `src/takt/infrastructure/security/root_hash_signature.py`
- Audit engagement: `src/takt/application/use_cases/audit_engagement.py`, `src/takt/infrastructure/stores/sqlite_store.py`, `src/takt/interface_adapters/api/main.py`
- GosSOPKA: `src/takt/infrastructure/export/gossopka.py`
- Метрики: `src/takt/infrastructure/http/prometheus_metrics.py`
- Monitoring: `deploy/monitoring/grafana/`, `deploy/monitoring/prometheus/`
- Миграции и проверка ledger: `scripts/db_migrate.py`, `scripts/verify_audit_ledger.py`, `scripts/verify_operation_ledger.py`
- CI: `.github/workflows/ci.yml` (jobs `release-gates`, `release-evidence-dry-run`)

---

*Документ отражает состояние на момент последнего обновления ветки; после крупных изменений схемы БД или контрактов экспорта обновите таблицы выше.*
