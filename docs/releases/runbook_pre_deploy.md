# Runbook — Pre-Deploy

Краткий pre-deploy чек для окружений с SQLite storage.

## 1) Подготовка окружения

```powershell
# Пример: перейти в корень проекта
cd <repo-root>

# Проверить Python / зависимости
python -V
python -m pip install -e ".[dev]"
```

## 2) Локальный gate перед выкладкой

```powershell
python -m pytest -q
python scripts/generate_sbom.py
python -m pip_audit
```

Ожидаемо:

- тесты зелёные;
- есть `dist/sbom.cyclonedx.json`;
- `pip-audit` без критичных находок для релизного решения;
- в GitHub Actions для целевого коммита/PR зелёные джобы **`release-gates`** и **`release-evidence-dry-run`** (детально: **`docs/current_operational_reference.md`** от корня репозитория).

## 3) Backup и миграция SQLite

```powershell
# Переменная/путь к боевой БД задаётся в вашей среде
python scripts/db_backup.py --src "<PATH_TO_DB>" --dst "<BACKUP_PATH>"
python scripts/db_migrate.py --db "<PATH_TO_DB>"
```

Проверить:

- backup-файл создан;
- миграция завершилась с актуальной версией схемы.

## 4) Конфигурация безопасности и подписи

Проверить наличие и корректность:

- `TAKT_AUTH_REQUIRED=true`
- `TAKT_API_KEY` (непустой)
- `TAKT_STORAGE` / `TAKT_SQLITE_PATH`
- один из режимов подписи forensic:
  - для `TAKT_FORENSIC_CRYPTO_MODE=mvp`: `TAKT_FORENSIC_HMAC_SECRET` или внешний signer/verifier
  - для `TAKT_FORENSIC_CRYPTO_MODE=gost_strict`: только `TAKT_FORENSIC_SIGN_URL` + `TAKT_FORENSIC_VERIFY_URL` (без HMAC fallback)

## 4a) Службы на целевой ВМ: их две

При `incident_assembly.mode: worker` (значение по умолчанию) приём событий только отмечает
работу, а связанный инцидент собирает отдельный процесс. Одного `takt-api.service`
недостаточно: API будет исправно принимать события и заводить дела, а инцидентов в очереди
не появится.

Юниты и порядок установки: [`deploy/systemd/README.md`](../../deploy/systemd/README.md).

```bash
sudo systemctl enable --now takt.target      # поднимает обе службы
systemctl status takt-api.service takt-assembly-worker.service
journalctl -u takt-assembly-worker.service -n 20   # ожидается `assembly worker started`
```

Проверить:

- обе службы `active (running)`;
- `EnvironmentFile` у них один и тот же — иначе процессы могут читать разные базы;
- воркер не в `failed` с кодом 4: это расхождение его настройки с настройкой API, коды
  разобраны в README юнитов.

Если отдельный процесс не нужен, поставьте `incident_assembly.mode: on_ingest` и не включайте
`takt-assembly-worker.service` — прогон пойдёт внутри приёма, ценой времени ответа приёма.

## 5) Monitoring артефакты

Подготовить импорт:

- `deploy/monitoring/grafana/takt-business-observability-dashboard.json`
- `deploy/monitoring/prometheus/alerts.business-observability.rules.yml`

## 6) Быстрый handoff для `gost_strict` (если используется)

Проверить env:

- `TAKT_FORENSIC_CRYPTO_MODE=gost_strict`
- `TAKT_FORENSIC_SIGN_URL` задан и доступен из runtime
- `TAKT_FORENSIC_VERIFY_URL` задан и доступен из runtime

Быстрая валидация readiness:

```powershell
curl -sS http://127.0.0.1:8090/ready
```

Ожидаемо:

- `ready=true`
- `forensic_crypto_mode="gost_strict"`
- `forensic_strict_ready=true`
- `forensic_strict_missing=[]`

Примечание: в strict-контуре HMAC не используется как fallback статуса подписи.

## 7) Автоматический evidence-отчёт (рекомендуется)

```powershell
python scripts/close_operational_tails.py --db "<PATH_TO_DB>" --apply-migrate --output "docs/releases/operational_tails_evidence.md"
```

Скрипт создаёт backup, применяет миграцию (если указан `--apply-migrate`), выполняет ledger verify и локальный API smoke на копии БД, затем формирует markdown-отчёт для заполнения `prod_ready` полей.

## 8) Автозаполнение `prod_ready` из evidence

```powershell
python scripts/fill_prod_ready_from_evidence.py --evidence "docs/releases/operational_tails_evidence.md" --prod-ready "docs/releases/2026-05-07_v0.6.23_prod_ready.md"
```

Обновляются поля 5/6/7/8 в compact prod-ready карточке:

- backup path
- факт миграции
- forensic mode (из `TAKT_FORENSIC_*` env или через `--forensic-mode`; при `TAKT_FORENSIC_CRYPTO_MODE=gost_strict` без sign/verify будет помечен как `misconfigured`)
- smoke summary (`case_id` + `gossopka_official_ok` + `forensic_signing_unavailable` + `forensic_verify_ok` + `audit_engagement_api_ok`, как в `fill_prod_ready_from_evidence.py`)

## 9) One-shot finalize (рекомендуется)

```powershell
python scripts/release_finalize.py --db "<PATH_TO_DB>" --apply-migrate --evidence "docs/releases/operational_tails_evidence.md" --prod-ready "docs/releases/2026-05-07_v0.6.23_prod_ready.md"
```

Команда делает evidence + автозаполнение карточки в один проход и печатает итог:

- `release_status=READY` если заполнены auto-поля и пройдена placeholder policy
- `release_status=NOT_READY` если не пройдена policy, отсутствуют обязательные release-артефакты или smoke выявил (в порядке проверки `release_finalize`): `gossopka_official_ok!=true`, затем `forensic_signing_unavailable=true`, затем `forensic_verify_ok!=true`, затем `audit_engagement_api_ok!=true`

Строгий режим (добавляет проверку SBOM):

```powershell
python scripts/release_finalize.py --db "<PATH_TO_DB>" --apply-migrate --strict --strict-generate-sbom
```

Дополнительная локальная валидация карточки:

```powershell
python scripts/validate_prod_ready.py --prod-ready "docs/releases/2026-05-07_v0.6.23_prod_ready.md"
```

## 10) Полный release package bundle

```powershell
python scripts/build_release_package.py --db "<PATH_TO_DB>" --apply-migrate --strict --strict-generate-sbom --package-root "dist"
```

Результат:

- папка `dist/release-package-<UTCSTAMP>/`
- архив `dist/release-package-<UTCSTAMP>.zip`
- `manifest.json` с составом пакета, статусом и SHA-256 контрольными суммами; поле **`package_dir`** записывается **относительно корня репозитория** (POSIX-путь), если сборка идёт под `--package-root` внутри репозитория — так проще переносить архив без привязки к букве диска

Проверка целостности пакета:

```powershell
python scripts/verify_release_package.py "dist/release-package-<UTCSTAMP>.zip"
python scripts/verify_release_package.py --package-dir "dist/release-package-<UTCSTAMP>"
python scripts/verify_release_package.py --package-zip "dist/release-package-<UTCSTAMP>.zip"
```

РџСЂРё РЅРµРѕР±С…РѕРґРёРјРѕСЃС‚Рё СѓР¶РµСЃС‚РѕС‡РёС‚Рµ zip-Р»РёРјРёС‚С‹ РЅР° РїСЂРёС‘РјРєРµ:

```powershell
python scripts/verify_release_package.py --package-zip "dist/release-package-<UTCSTAMP>.zip" --max-zip-files 1000 --max-zip-uncompressed-bytes 262144000 --max-zip-compression-ratio 100
```

РўРµ Р¶Рµ Р»РёРјРёС‚С‹ РјРѕР¶РЅРѕ Р·Р°РґР°С‚СЊ РєР°Рє env-defaults РґР»СЏ CI/ops; CLI-С„Р»Р°РіРё РёРјРµСЋС‚ РїСЂРёРѕСЂРёС‚РµС‚:

```powershell
$env:TAKT_RELEASE_VERIFY_MAX_ZIP_FILES="1000"
$env:TAKT_RELEASE_VERIFY_MAX_ZIP_UNCOMPRESSED_BYTES="262144000"
$env:TAKT_RELEASE_VERIFY_MAX_ZIP_COMPRESSION_RATIO="100"
python scripts/verify_release_package.py "dist/release-package-<UTCSTAMP>.zip"
```
