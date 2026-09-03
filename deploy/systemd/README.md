# Службы ТАКТ на боевой ВМ

Два процесса, а не один. При `incident_assembly.mode: worker` (значение по умолчанию в
[`config/risk_weights.yaml`](../../config/risk_weights.yaml)) приём событий только отмечает
работу в очереди, а связанный инцидент собирает отдельный процесс. Без него API исправно
принимает события и заводит дела, но инцидентов в очереди не появляется — разбор режимов и
замеры в [`docs/pt_techlab/correlation_quality.md`](../../docs/pt_techlab/correlation_quality.md).

Поэтому службы поставляются парой и включаются одной целью: забыть второй процесс не должно
быть возможно.

| Файл | Что запускает |
|---|---|
| `takt-api.service` | uvicorn с API (приём, кейсы, экспорт) |
| `takt-assembly-worker.service` | `python -m takt.tools.assembly_worker` — сборку инцидентов |
| `takt.target` | обе службы одной командой |

Юниты объявляют `Type=exec` — он требует systemd 240 и новее (Debian 11+, Ubuntu 20.04+,
RHEL 9+). На более старой системе замените его на `Type=simple`: разница в том, что `exec`
считает запуск неудачным, если процесс не смог стартовать, а `simple` — сразу после `fork`.

## Установка

Пути в юнитах: проект — `/opt/takt`, виртуальное окружение — `/opt/takt/.venv`,
данные — `/opt/takt/data`, переменные — `/etc/takt/takt.env`. Если они другие, поправьте
`WorkingDirectory`, `ExecStart`, `ReadWritePaths` и `EnvironmentFile` в обоих юнитах
одинаково.

```bash
sudo useradd --system --home /opt/takt --shell /usr/sbin/nologin takt
sudo install -d -o takt -g takt /opt/takt/data /etc/takt
sudo install -m 0640 -o root -g takt takt.env.example /etc/takt/takt.env   # затем заполнить
sudo install -m 0644 takt-api.service takt-assembly-worker.service takt.target /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now takt.target
```

Проверка:

```bash
systemctl status takt-api.service takt-assembly-worker.service
journalctl -u takt-assembly-worker.service -n 20
curl -sS http://127.0.0.1:8090/health | head -c 200
```

В журнале воркера при исправной настройке видно строку `assembly worker started` с владельцем
аренды, порогом отличительности и путём к базе.

## Один файл переменных на оба процесса

`EnvironmentFile=/etc/takt/takt.env` одинаков в обоих юнитах намеренно. Разные файлы означают
разные `TAKT_CONFIG` или `TAKT_SQLITE_PATH`: приём копит сигналы в одной базе, а сборка ждёт
их в другой, и выглядит это как «инциденты не появляются» без единой ошибки в журналах.
Воркер сверяет свою настройку с настройкой API при старте и в таком случае откажется
запускаться, но общий файл снимает вопрос заранее.

## Коды выхода воркера и перезапуск

`Restart=on-failure` с `RestartPreventExitStatus=3 4`: две ситуации требуют человека, и
перезапуск их только спрячет — служба крутилась бы в цикле, выглядя работающей.

| Код | Что произошло | Что делать |
|---:|---|---|
| 0 | штатная остановка (`systemctl stop`, SIGTERM) | — |
| 2 | нет постоянного хранилища (`TAKT_STORAGE` не `sqlite`) | поправить переменные |
| 3 | аренду держит другой воркер | оставить один процесс на базу |
| 4 | настройка разошлась с настройкой API | привести конфигурации к одному виду; осознанное расхождение — флаг `--allow-config-mismatch` |

## Остановка и обновление

```bash
sudo systemctl stop takt.target          # сначала обе службы
# обновление кода, миграция БД: scripts/db_migrate.py
sudo systemctl start takt.target
```

Воркер обрабатывает SIGTERM: дорабатывает цикл и освобождает аренду, поэтому сменщик после
перезапуска не ждёт её истечения. Останавливать службы порознь не нужно — сборка не портит
данные, если её прервать: прогон идемпотентен, а незабранные сигналы остаются в очереди.

## Если сборка вынесена не нужна

Поставьте `incident_assembly.mode: on_ingest` в конфигурации и не включайте
`takt-assembly-worker.service` — прогон пойдёт внутри приёма. Тогда приём платит за прогон
временем ответа: на хранилище в 8000 дел это 1,8 с на каждое срабатывание инварианта.
