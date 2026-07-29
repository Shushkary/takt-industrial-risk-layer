# CLAUDE.md — рабочая память проекта ТАКТ

## Что это

ТАКТ Industrial Risk Layer — второй аналитический эшелон для КИИ/АСУ ТП. Слои:
`src/takt/domain` (L1, чистый, без инфраструктуры) → `src/takt/application` (L2, use cases) →
`src/takt/interface_adapters/api` (L3, FastAPI) → `src/takt/infrastructure` (L4, YAML/CSV/SQLite/экспорт).
Границы слоёв держит import-linter (`pyproject.toml`) и `tests/test_backend_architecture_guard.py`.

## Команды

```bash
python -m pip install -e ".[dev,metrics]"     # если PyYAML от системы: добавить --ignore-installed PyYAML
python -m pytest
uvicorn takt.interface_adapters.api.main:app --host 127.0.0.1 --port 8090
```

## Классы источников SOC

Четыре класса (`docs/pt_techlab/adr_source_classes.md`, контракт — `docs/pt_techlab/data_contract.md`):
`edr`, `siem`, `ndr`, `ot`. Мапперы CSV → `NormalizedEvent`: `src/takt/infrastructure/importers/soc_csv.py`.
Потоковая загрузка одного источника: `python -m takt.tools.load_dataset --source edr --path <csv>`.

Корреляция задаётся в `config/risk_weights.yaml` → `correlation`. **В боевом конфиге `mode: legacy`,
и это полностью отключает обобщённый коррелятор** (`AssessRisk._correlation_candidates` возвращает `[]`).
Кросс-источниковая корреляция работает только при `mode: generalized`.

## Стенд двух источников

Отладочный стенд «два источника → один кейс»: `deploy/stand/README.md`.

```bash
python scripts/stand_dataset.py --pair edr,ot --incidents 6 --noise 300
python scripts/stand_run.py --reset
```

Отчёт: `data/stand/report/report.md` + `report.json`. Живой API на данных стенда:
`docker compose -f deploy/stand/docker-compose.stand.yml up`.

## Инфраструктура

Доступ к ВМ SpaceWeb (панель, SSH, диагностика): `docs/ops/vm_spaceweb_access.md`.
Кратко: `ssh -i ~/.ssh/id_rsa_spaceweb torionadmin@89.111.142.231`, панель <https://mcp.sweb.ru/main/auth/>
(логин `grflmailru`, 2FA по SMS на каждый вход). Секреты в репозитории не хранятся.

## Правила репозитория

- Секреты, пароли, приватные ключи — никогда в git. `.env` в `.gitignore`, трекается только `.env.example`.
- `tests/test_release_artifacts.py` запрещает следы машины разработчика в текстах репозитория
  (профили пользователей Windows, пути venv, `file:///`). Не вставлять такие пути в доки.
- `TAKT_CONFIG` и `TAKT_SQLITE_PATH` обязаны указывать внутрь корня репозитория
  (`settings_helpers._project_local_path`).
- Данные стенда и БД лежат в `data/` — каталог в `.gitignore`.
