# Releases Bundle Index

Единая точка входа по релизным артефактам в `docs/releases/`.

## Текущий пакет (2026-05-07 / v0.6.23)

| Файл | Назначение | Статус |
|------|------------|--------|
| `2026-05-07_done_log.md` | Сводка выполненных работ | готово |
| `2026-05-07_v0.6.23_readiness.md` | Заполненная release readiness-card | готово (требуются подписи/операционные поля) |
| `2026-05-07_v0.6.23_prod_ready.md` | Компактная prod-only карточка допуска | готово (требуются подписи/операционные поля) |
| `runbook_pre_deploy.md` | Команды и проверки перед выкладкой | готово |
| `runbook_smoke_checks.md` | Smoke-проверки сразу после выкладки | готово |
| `runbook_rollback.md` | Быстрые шаги отката | готово |
| `../scripts/build_release_package.py` | One-shot сборка релизного bundle (manifest+zip) | готово |

## Базовые шаблоны и reference

| Файл | Назначение |
|------|------------|
| `../release_readiness_template.md` | Шаблон карточки релизной готовности |
| `../release_checklist.md` | Минимальный release gate checklist |
| `../release_readiness_status.md` | Текущий статус закрытых/частично закрытых блоков |
| `../current_operational_reference.md` | Актуальный source of truth по API/CI/env |

## Как использовать

Перед тегом/образом в CI должны быть зелёными джобы **`release-gates`** и **`release-evidence-dry-run`** (см. [`../current_operational_reference.md`](../current_operational_reference.md)).

1. Обновить `*_readiness.md` под целевую среду и SHA.
2. Выполнить `runbook_pre_deploy.md`.
3. После выкладки выполнить `runbook_smoke_checks.md` (включая `gossopka_official_ok`, forensic verify, контроль `forensic_signing_unavailable=false` и `audit_engagement_api_ok` smoke).
4. При необходимости использовать `runbook_rollback.md`.
5. Зафиксировать финальные подписи и закрыть релизный тикет.
