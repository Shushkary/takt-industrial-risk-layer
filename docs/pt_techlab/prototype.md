# Прототип: запуск и демо-сценарий

Полнофункциональный прототип состоит из **backend** (FastAPI, ядро TAKT) и **АРМ аналитика** (React + TypeScript). Ниже — воспроизводимый запуск на предоставленных fixture-данных четырёх классов источников.

## 1. Backend

```powershell
# из корня репозитория
python -m pip install -e ".[dev]"
python -m pytest                 # прогон тестов, включая tests/test_pt_techlab_*
uvicorn takt.interface_adapters.api.main:app --reload --host 127.0.0.1 --port 8090
```

Swagger с полным контуром API — `http://127.0.0.1:8090/docs`.

## 2. Загрузка датасета (4 класса источников)

Потоковая загрузка demo-фикстур из `tests/fixtures/pt_techlab/` в конвейер оценки:

```powershell
python -m takt.tools.load_dataset --source edr  --path tests/fixtures/pt_techlab/edr.csv
python -m takt.tools.load_dataset --source siem --path tests/fixtures/pt_techlab/siem.csv
python -m takt.tools.load_dataset --source ndr  --path tests/fixtures/pt_techlab/ndr.csv
python -m takt.tools.load_dataset --source ot   --path tests/fixtures/pt_techlab/ot.csv
```

После загрузки:

- `GET /cases` — сформированные инциденты с корреляцией событий из разных источников;
- `GET /events/search?host_id=...` — единый поиск по событиям всех источников;
- `GET /cases/{id}/attack-chain` — реконструкция цепочки атаки;
- `GET /entities/{type}/{id}/card` — карточка сущности (историчность + окружение).

## 3. АРМ аналитика (frontend)

```powershell
cd frontend/takt-arm
npm install
# API-режим: указать адрес backend
$env:VITE_TAKT_API_BASE_URL = "http://127.0.0.1:8090"
npm run dev
```

АРМ откроется на `http://127.0.0.1:5173`. В API-режиме рабочие экраны читают backend: очередь инцидентов, рабочий стол кейса, граф/таймлайн, карточки сущностей, журнал находок, единый поиск.

> АРМ не выполняет активное управление оборудованием, не отправляет команды на ПЛК, не блокирует учётные записи и не закрывает кейсы автоматически. Итоговое решение остаётся за оператором.

## 4. Основной демо-сценарий: INC-002

Профильный для Positive Technologies кейс — **компрометация конвейера сборки
через фишинг**. Данные: [`tests/fixtures/pt_techlab/inc_002/`](../../tests/fixtures/pt_techlab/inc_002/),
описание — [`README_INC-002.md`](../../tests/fixtures/pt_techlab/inc_002/README_INC-002.md).

```powershell
python -m takt.tools.load_dataset --source edr  --path tests/fixtures/pt_techlab/inc_002/edr.csv
python -m takt.tools.load_dataset --source siem --path tests/fixtures/pt_techlab/inc_002/siem.csv
python -m takt.tools.load_dataset --source ndr  --path tests/fixtures/pt_techlab/inc_002/ndr.csv
python -m takt.tools.load_dataset --source ot   --path tests/fixtures/pt_techlab/inc_002/ot.csv
```

Цепочка атаки (2026-08-17, UTC): фишинг на `ws-17` под `smirnov` →
канал C2 по DoH к `185.220.101.34` → kerberoasting и захват `svc_build` →
перемещение на `build-srv-01` → неподписанный артефакт в конвейере `release-prod`.

Из 1030 событий цепочку составляют 27. Сборка инцидента идёт в два шага
(`takt.domain.engines.incident_pivot`):

1. **Ядро по отличительным сущностям** — 25 событий, **без единого фонового**.
   Скомпрометированные учётные записи, адрес C2 и объекты релизного конвейера
   в фоне не встречаются, поэтому шаг точен.
2. **Переход на уровень узла** — добирает два сетевых потока
   (SMB `ws-17` → `build-srv-01` и HTTPS к `git-srv-01`), у которых нет
   отличительных признаков: те же узлы и внутренние адреса есть в фоновом
   трафике. Вместе с ними приходит легитимная активность этих узлов — её
   отсеивает аналитик.

Ключевая проверка на ложные срабатывания: три отвлекающие аномалии —
`BG-ADMIN` (админ вне рабочего окна), `BG-SCAN` (санкционированный сканер),
`BG-BACKUP` (ночной бэкап) — **ни на одном шаге не попадают в инцидент**,
хотя внешне похожи на атаку. В АРМ они отображаются отдельными кейсами с
вердиктом «требует проверки», а не «подтверждённый инцидент».

Регрессия: [`tests/test_pt_techlab_inc_002.py`](../../tests/test_pt_techlab_inc_002.py).

## 5. Сквозной демо-сценарий

1. **Загрузка датасета** — 4 класса источников (шаг 2).
2. **Алерт → кейс** — корреляция сама подтягивает связанные события SIEM, NDR и промышленной телеметрии к триггеру EDR.
3. **Контекст сущностей** — карточки узла и пользователя: историчность (типичность по базовой линии) + окружение.
4. **Находки** — артефакты фиксируются в кейсе в один клик, без ручного копирования идентификаторов.
5. **Реконструкция цепочки** — точка входа → цепочка процессов → перемещение по сети.
6. **Оценка распространения** — IOC-sweep: перечень затронутых узлов с доказательствами.
7. **Пакет реагирования и отчёт** — после подтверждения аналитика формируется пакет для EDR и связный отчёт по инциденту (PDF/JSON).

Методика измерения ускорения расследования (критерий ТЗ §12.4) — [baseline_methodology.md](baseline_methodology.md).

## Структура прототипа в репозитории

| Часть | Путь |
|---|---|
| Коннекторы источников (EDR/SIEM/NDR/OT) | `src/takt/infrastructure/importers/*_events.py` |
| Порт чтения источников | `src/takt/domain/ports/event_source_reader.py` |
| Корреляция и качество группировки | `src/takt/domain/engines/correlation_quality.py`, `scripts/eval_correlation.py` |
| Реконструкция цепочки | `src/takt/application/use_cases/reconstruct_chain.py` |
| Находки и обогащение | `src/takt/application/use_cases/case_findings.py`, `enrichment.py` |
| API-роутеры SOC-слоя | `src/takt/interface_adapters/api/routers/` (events, correlation, entities, findings, attack_chain, enrichment, workspace) |
| АРМ аналитика | `frontend/takt-arm/` |
| CLI загрузки датасета | `src/takt/tools/load_dataset.py` |
| Тесты SOC-слоя | `tests/test_pt_techlab_*.py` |
