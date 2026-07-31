# Контракт данных SOC «Техлаб 2026»

Статус: **проект v0.1, ожидает согласования заказчиком**. Дата: 2026-07-10.

Контракт задаёт минимальный профиль для четырёх классов источников. Примеры ниже взяты из обезличенного воспроизводимого среза `tests/fixtures/pt_techlab`; до приёмки они должны быть заменены или подтверждены на выгрузке заказчика.

## Каноническое событие TAKT

Обязательное ядро: `event_id: string`, `observed_at: datetime (UTC)`, `source: enum`, `protocol: string`, `operation: string`, `payload_size: integer >= 0`, `payload: object`. SOC-профиль: `entities.host_id`, `entities.user_id`, `entities.process_id`, `entities.parent_process_id`, `entities.src_address`, `entities.dst_address` — nullable strings; `artifacts` — список объектов `{type, value}`. Допустимые типы артефакта: `host`, `file`, `hash`, `process`, `account`, `address`, `url`, `domain`.

Исходная запись всегда сохраняется в `payload`. Время без зоны отклоняется; строковые значения обрезаются по краям; пустая строка нормализуется в `null`; IP-адреса и хеши не изменяются кроме приведения SHA-256 к нижнему регистру.

## Маппинг классов источников

| Класс / `source` | Поле источника → TAKT | Тип и семантика | Пример |
|---|---|---|---|
| EDR / `edr` | `timestamp` → `observed_at`; `event_id` → `event_id`; `hostname` → `entities.host_id`; `username` → `entities.user_id`; `process_guid` → `entities.process_id`; `parent_process_guid` → `entities.parent_process_id`; `remote_ip` → `entities.dst_address`; `sha256` → `artifacts[hash]`; `image_path` → `artifacts[file]`; `event_type` → `operation` | ISO-8601 UTC; строки. Процессная телеметрия конечной точки | `2026-06-01T09:00:00Z,edr-001,ws-17,ivanov,p-900,p-100,10.20.30.40,9f86…0a08,C:\\Temp\\update.exe,PROCESS_START` |
| SIEM / `siem` | `event_time` → `observed_at`; `record_id` → `event_id`; `device_host` → `entities.host_id`; `subject_user` → `entities.user_id`; `src_ip`/`dst_ip` → адреса; `rule_name` → `operation`; `indicator` → типизированный артефакт | ISO-8601 UTC; строки. Нормализованное событие/алерт SIEM | `2026-06-01T09:00:15Z,siem-001,ws-17,ivanov,10.10.1.17,10.20.30.40,SUSPICIOUS_OUTBOUND,evil.example` |
| NDR / `ndr` | `start_time` → `observed_at`; `flow_id` → `event_id`; `src_host` → `entities.host_id`; `src_ip`/`dst_ip` → адреса; `app_protocol` → `protocol`; `verdict` → `operation`; `dns_query` → `artifacts[domain]` | ISO-8601 UTC; строки; `bytes` — integer. Сетевой поток/сетевой детект | `2026-06-01T09:00:10Z,ndr-001,ws-17,10.10.1.17,10.20.30.40,DNS,C2_SUSPECT,evil.example,211` |
| OT/PT ISIM / `ot` | `timestamp` → `observed_at`; `event_id` → `event_id`; `asset_id` → `entities.host_id` и сохраняется в `payload.asset_id`; `operator_id` (опционально) → `entities.user_id` и `operator_id`; `src_address`/`dst_address` → адреса; `protocol` → `protocol`; `operation` → `operation`; `tag` → `artifacts[process]` | ISO-8601 UTC; строки; `payload_size` — integer. Промышленная телеметрия и OT-инварианты | `2026-06-01T09:01:00Z,ot-001,plc-01,10.10.2.5,10.10.2.20,IEC104,WRITE_SETPOINT,boiler.pressure,64` |

Полная машиночитаемая форма примеров — CSV-файлы в `tests/fixtures/pt_techlab/`.

## Обязательные признаки корреляции

| Признак | EDR | SIEM | NDR | OT/PT ISIM |
|---|---|---|---|---|
| Узел | `hostname` | `device_host` | `src_host` | `asset_id` |
| Пользователь | `username` | `subject_user` | — | `operator_id`, если присутствует в выгрузке |
| Процесс | `process_guid`, `parent_process_guid` | — (если обогащено: `process_id`) | — | `tag` как технологический процесс/точка |
| Адрес | `remote_ip` | `src_ip`, `dst_ip` | `src_ip`, `dst_ip` | `src_address`, `dst_address` |
| Хеш/артефакт | `sha256`, `image_path` | `indicator`, `indicator_type` | `dns_query` | `tag` |

Отсутствие признака не блокирует ingest: поле остаётся `null`, а корреляция использует доступные составные ключи. Нельзя подставлять вымышленные идентификаторы.

## Управление изменениями и согласование

Несовместимое переименование исходного поля требует новой версии маппинга; добавление nullable-поля обратно совместимо. Ошибочная строка изолируется, журналируется без секретов и не останавливает поток.

| Роль | Представитель | Решение | Дата/ссылка |
|---|---|---|---|
| Заказчик | ожидает назначения | ожидает подтверждения классов, полей и реальных примеров | TBD |
| Исполнитель TAKT | технический руководитель | проект принят как основание реализации | 2026-07-10 |

