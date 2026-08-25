# Контракт данных SOC «Техлаб 2026»

Статус: **v0.2 — класс NDR подтверждён схемой заказчика, остальные три ожидают согласования**. Дата: 2026-08-03.

Контракт задаёт минимальный профиль для четырёх классов источников.

| Класс | Состояние маппинга | Прогон на живых данных |
|---|---|---|
| **NDR / PT NAD** | ✅ По фактической схеме заказчика (mapping индекса, 1786 полей) — [`source_schema_nad.md`](source_schema_nad.md) | ❌ нет |
| EDR | ⏳ Предположительный — ожидает схему заказчика | ❌ нет |
| SIEM | ⏳ Предположительный — ожидает схему заказчика | ❌ нет |
| OT / PT ISIM | ⏳ Предположительный — ожидает схему заказчика | ❌ нет |

Примеры для классов со статусом ⏳ взяты из обезличенного воспроизводимого среза `tests/fixtures/pt_techlab`; до приёмки они должны быть заменены или подтверждены на выгрузке заказчика.

**Проверка на живых данных: не проводилась (на 2026-08-25).** Ни один класс не принимался с
работающего стенда: маппинг NDR построен по схеме индекса, три остальных — по предполагаемым
именам полей, все примеры синтетические. Доступ к стендам PT EdTechLab требует VPN, который на
машине разработки не поднимается. Формулировка «коннектор проверен на реальных данных» до
такого прогона в материалы не идёт — это утверждение без измерения, запрещённое
[границами продукта](../product_boundary.md).

Что закрывает пункт: **выгрузка файлом, а не подключение**. Конвейер приёма файловый — NDJSON
от NTA (`python -m takt.tools.load_dataset --source nad --path <файл>.ndjson`) и CSV от SIEM
(`--source siem`), поэтому экспорт может сделать любой, у кого есть доступ к стенду. Хватает
200–500 строк на класс: этого достаточно, чтобы проверить непустоту ключей корреляции, форму
выгрузки, фактическое маскирование `credentials.password` и наличие разметки фазы атаки.

Риски, которые остаются незакрытыми до такого прогона: поле объявлено в схеме, но пустое в
документах; форма экспорта отличается от `_source`-обёртки; события без `attack_phase` не
становятся шагами цепочки; кардинальность и объём реального потока не измерены.

## Каноническое событие TAKT

Обязательное ядро: `event_id: string`, `observed_at: datetime (UTC)`, `source: enum`, `protocol: string`, `operation: string`, `payload_size: integer >= 0`, `payload: object`. SOC-профиль: `entities.host_id`, `entities.user_id`, `entities.process_id`, `entities.parent_process_id`, `entities.src_address`, `entities.dst_address` — nullable strings; `artifacts` — список объектов `{type, value}`. Допустимые типы артефакта: `host`, `file`, `hash`, `process`, `account`, `address`, `url`, `domain`.

Исходная запись всегда сохраняется в `payload`. Время без зоны отклоняется; строковые значения обрезаются по краям; пустая строка нормализуется в `null`; IP-адреса и хеши не изменяются кроме приведения SHA-256 к нижнему регистру.

## Маппинг классов источников

| Класс / `source` | Поле источника → TAKT | Тип и семантика | Пример |
|---|---|---|---|
| EDR / `edr` | `timestamp` → `observed_at`; `event_id` → `event_id`; `hostname` → `entities.host_id`; `username` → `entities.user_id`; `process_guid` → `entities.process_id`; `parent_process_guid` → `entities.parent_process_id`; `remote_ip` → `entities.dst_address`; `sha256` → `artifacts[hash]`; `image_path` → `artifacts[file]`; `event_type` → `operation` | ISO-8601 UTC; строки. Процессная телеметрия конечной точки | `2026-06-01T09:00:00Z,edr-001,ws-17,ivanov,p-900,p-100,10.20.30.40,9f86…0a08,C:\\Temp\\update.exe,PROCESS_START` |
| SIEM / `siem` | `event_time` → `observed_at`; `record_id` → `event_id`; `device_host` → `entities.host_id`; `subject_user` → `entities.user_id`; `src_ip`/`dst_ip` → адреса; `rule_name` → `operation`; `indicator` → типизированный артефакт | ISO-8601 UTC; строки. Нормализованное событие/алерт SIEM | `2026-06-01T09:00:15Z,siem-001,ws-17,ivanov,10.10.1.17,10.20.30.40,SUSPICIOUS_OUTBOUND,evil.example` |
| **NDR / PT NAD** / `ndr` ✅ | `ts` → `observed_at`; `_ndx` → `event_id`; `src.host_id` → `entities.host_id`; `src.ip`/`dst.ip` → адреса; `user`/`credentials.login` → `entities.user_id`; `app_proto` → `protocol`; `s_msg` → `operation`; `sha256`/`md5`/`ja3_md5`/`ja4` → `artifacts[hash]`; `query.rrname`/`server_name` → `artifacts[domain]`; `att_ck` → `payload.mitre_technique`. Полный каскад приоритетов — в [`source_schema_nad.md`](source_schema_nad.md) | Документы NDJSON; `ts` — `date_optional_time`; `src.ip`/`dst.ip` — тип `ip`; `bytes.sent`/`bytes.recv` — long. **`credentials.password` маскируется** и в хранилище не попадает | `tests/fixtures/pt_techlab/nad_sample.ndjson` |
| OT/PT ISIM / `ot` | `timestamp` → `observed_at`; `event_id` → `event_id`; `asset_id` → `entities.host_id` и сохраняется в `payload.asset_id`; `src_address`/`dst_address` → адреса; `protocol` → `protocol`; `operation` → `operation`; `tag` → `artifacts[process]` | ISO-8601 UTC; строки; `payload_size` — integer. Промышленная телеметрия и OT-инварианты | `2026-06-01T09:01:00Z,ot-001,plc-01,10.10.2.5,10.10.2.20,IEC104,WRITE_SETPOINT,boiler.pressure,64` |

Полная машиночитаемая форма примеров — CSV-файлы в `tests/fixtures/pt_techlab/`.

## Обязательные признаки корреляции

| Признак | EDR ⏳ | SIEM ⏳ | **NDR / PT NAD ✅** | OT/PT ISIM ⏳ |
|---|---|---|---|---|
| Узел | `hostname` | `device_host` | `src.host_id`, `dst.host_id`, `host.host_id`, `attacker.host_id`, `victim.host_id` | `asset_id` |
| Пользователь | `username` | `subject_user` | `user`, `credentials.login`, `subject` | — (если доступно: `operator_id`) |
| Процесс | `process_guid`, `parent_process_guid` | — (если обогащено: `process_id`) | — (в схеме отсутствует: сетевой сенсор процессов не видит) | `tag` как технологический процесс/точка |
| Адрес | `remote_ip` | `src_ip`, `dst_ip` | `src.ip`, `dst.ip`, `attacker.ip`, `victim.ip` (+ порты) | `src_address`, `dst_address` |
| Хеш/артефакт | `sha256`, `image_path` | `indicator`, `indicator_type` | `sha256`, `md5`, `fuzzy_hash`, `ja3_md5`, `ja4`, `filename`, `filepath`, `query.rrname`, `server_name` | `tag` |
| Техника атаки | — | — | `att_ck` (MITRE ATT&CK) | — |

Схема NAD даёт сквозной `host_id` во всех ролевых группах — это основной ключ склейки по узлу, не требующий нормализации. Дополнительно сенсор уже размечает роли `attacker.*` / `victim.*`, что снимает часть работы по определению направления атаки.

Отсутствие признака не блокирует ingest: поле остаётся `null`, а корреляция использует доступные составные ключи. Нельзя подставлять вымышленные идентификаторы.

## Управление изменениями и согласование

Несовместимое переименование исходного поля требует новой версии маппинга; добавление nullable-поля обратно совместимо. Ошибочная строка изолируется, журналируется без секретов и не останавливает поток.

| Роль | Представитель | Решение | Дата/ссылка |
|---|---|---|---|
| Заказчик | ожидает назначения | ожидает подтверждения классов, полей и реальных примеров | TBD |
| Исполнитель TAKT | технический руководитель | проект принят как основание реализации | 2026-07-10 |

