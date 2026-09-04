# Матрица 26 инвариантов

Справочник по всем инвариантам каталога `InvariantId` для ФСТЭК-пакета (`docs/certification_risk_roadmap.md`)
и для разговора с Positive Technologies о том, что детектирует ТАКТ поверх их стека.

Источники данных для таблицы:

- `src/takt/domain/invariants/catalog.py` — идентификаторы, блоки, заголовки.
- `config/invariants/*.yaml` — декларативный каталог, **фактически загружаемый API** (`load_invariant_catalog_from_dir`,
  см. `src/takt/interface_adapters/api/app.py`); это то, что реально исполняется в проде, а не `default_extended_rule_specs()`
  из кода (тот путь используется только когда `AssessRiskUseCase` создаётся без `rule_specs`, как в части unit-тестов).
- `src/takt/domain/invariants/rule_predicates.py` — реализация предикатов и `PREDICATE_REGISTRY`.

## Статусы валидации, используемые в таблице

- **prod-active** — предикат исполняется через `config/invariants/<id>.yaml` в реальном API-конвейере.
- **noop (config)** — YAML-файл ссылается на `predicate_ref: builtin:noop`, поэтому правило **не** исполняется в проде,
  даже если функция-предикат реализована и работает в изоляции.
- **unit only** — есть прямой unit-тест предиката/движка, но нет датасета true positive / false positive.
- **нет прямого теста** — предикат не вызывается напрямую ни в одном тесте по имени функции (только опосредованно
  через сквозные тесты, использующие `default_extended_rule_specs()`, который не совпадает с боевым конфигом).

TPR/FPR-протокол (`docs/detection_quality.md`) на момент обновления покрывает **11 из 26** инвариантов
синтетическим baseline-корпусом (не промышленной выборкой); статус «unit only» ниже для этих 11 означает
дополнительно «есть baseline TPR/FPR на синтетическом корпусе», для оставшихся 15 — протокол пока отсутствует.
`docs/product_boundary.md` и `docs/certification_risk_roadmap.md` фиксируют расширение на промышленную
выборку и оставшиеся инварианты как открытый пункт ФСТЭК-пакета.

## ⚠ Известный разрыв: 7 инвариантов отключены в проде

Ниже отмечены `⚠ NOOP` — эти правила задекларированы в `config/invariants/*.yaml` с `predicate_ref: builtin:noop`
и **не помечены `experimental: true`**, хотя рабочая реализация предиката существует в `rule_predicates.py` и
зарегистрирована в `PREDICATE_REGISTRY` под собственным именем. Проверено эмпирически: демо-топология из
`config/risk_weights.yaml` (`eng-workstation -> plc-01` в обход `jump-01`) не даёт срабатывания `jump_server_bypass`
через `POST /events` в реальном приложении (`invariant_hits: []`), хотя тот же предикат корректно срабатывает в
изолированном unit-тесте, использующем код-дефолтные `rule_specs` вместо конфига из `config/invariants/`.

Список: `jump_server_bypass`, `context_dissonance`, `source_reputation_drift`,
`stale_data`, `telemetry_gap`, `polling_period_doubling_suspect`.

`out_of_shift_access` из списка выведен: предикат включён, а сопоставление вердиктов источников
(`params.source_operations`) поднимает его на правиле SIEM `CODE_REPO_WRITE_OFFHOURS`.

Это не проектное решение (см. отсутствие `experimental: true`), а рассогласование между декларативным конфигом
и кодом — исправление вынесено отдельной задачей, см. `spawn_task` в этой же сессии /
`docs/backend_remediation_sprint_plan.md` (следующий пункт).

## Блок 1 — Частота опроса и протоколы

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `polling_jitter` | Аномальный джиттер интервалов опроса | последние **24** события | prod-active, unit only |
| `illegal_function_code` | Недопустимый код функции / IEC 60870-5-104 ASDU type id | последние **5** событий | prod-active, unit only |
| `payload_length_drift` | Дрейф размера полезной нагрузки относительно базовой линии (`payload_drift_ratio` в `risk_weights.yaml`) | последние **24** события | prod-active, unit only |
| `request_reply_dissonance` | Расхождение запрос/ответ по протоколу | последние **24** события | prod-active, unit only |
| `polling_period_doubling_suspect` | Эвристика каскадного удвоения интервалов опроса (см. `docs/feigenbaum_rationale.md`, δ≈4.669 как референсное число, не физический закон) | последние **24** события | ⚠ NOOP (config), нет прямого теста предиката; сама эвристика `predict_polling_chaos` покрыта тестами chaos predictor'а отдельно |

## Блок 2 — Топология

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `jump_server_bypass` | Доступ к ПЛК/критузлу в обход jump-хоста (`topology.jump_host`/`plc_hosts` в `risk_weights.yaml`) | граф рёбер, последние **5** событий | ⚠ NOOP (config), нет прямого unit-теста предиката; helper `detect_jump_server_bypass` покрыт тестами в `test_domain_engines.py` изолированно |
| `new_node_airgap` | Новый узел в сегменте air-gap (`enrichment.air_gap_segments`) | последние **5** событий | prod-active, unit only |
| `lateral_movement` | Признаки lateral movement | последние **5** событий | prod-active, unit only |
| `reconnaissance` | Разведка: скан, SNMP walk, топология | последние **5** событий | prod-active, unit only |

## Блок 3 — Идентификация

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `untrusted_ip_admin` | Админ-действия с недоверенного IP | последние **5** событий | prod-active, unit only |
| `brute_force` | Серия неуспешных аутентификаций (порог `invariants.auth_fail_threshold`, окно `invariants.auth_fail_window` в `risk_weights.yaml`) | последние **20** событий | prod-active, unit only |
| `out_of_shift_access` | Администрирование вне штатной фазы/смены | последние **5** событий | включён; вердикты источников — `tests/test_source_verdict_mapping.py` |
| `protocol_escalation` | Эскалация «тяжёлого» протокола по активу | последние **5** событий | prod-active, unit only |

## Блок 4 — Физическая логика

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `conflict_logic` | Конфликт логики управления / взаимоисключающие команды | последние **5** событий | prod-active, unit only |
| `physical_invariant_breach` | Нарушение физического инварианта процесса | последние **5** событий | prod-active, unit only |
| `blind_command` | Команда записи без предшествующего чтения/опроса (только непосредственно предыдущее событие по активу) | последние **3** события | prod-active, unit only |
| `cyclic_service_crash` | Циклический отказ сервиса исполнения | последние **5** событий | prod-active, unit only |

## Блок 5 — Целостность

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `log_wiping` | Очистка журналов / аудита | последние **5** событий | prod-active, unit only |
| `runtime_config_change` | Изменение конфигурации на исполнении | последние **5** событий | prod-active, unit only |
| `c2_external_dns` | Подозрительный внешний DNS / C2-паттерн | последние **5** событий | prod-active, unit only |
| `trust_index_drop` | Просадка индекса доверия источника (`ingest_trust.by_source` в `risk_weights.yaml`) | последние **5** событий | prod-active, unit only |

## Блок 6 — Данные и HITL

| id | Детектирует | Вход / окно | Статус |
|---|---|---|---|
| `stale_data` | Устаревшие данные в конвейере | последние **5** событий | ⚠ NOOP (config), нет прямого теста предиката; параметр `stale_window_seconds=90.0` используется отдельно в `evaluate_full_pipeline` (DQ) |
| `telemetry_gap` | Разрыв телеметрии / пропуск выборок | последние **5** событий | ⚠ NOOP (config), нет прямого теста предиката; параметр `max_gap_seconds=120.0` используется отдельно в `evaluate_full_pipeline` (DQ) |
| `source_reputation_drift` | Дрейф репутации источника | последние **5** событий | ⚠ NOOP (config), нет прямого теста предиката |
| `expert_dissonance` | Расхождение с экспертной оценкой / HITL | последние **5** событий | prod-active, unit only |
| `context_dissonance` | Расхождение с контекстом ТО / заявок | последние **5** событий | ⚠ NOOP (config), нет прямого теста предиката; смежная логика `match_event_to_ticket` покрыта тестами отдельно и влияет на `context_signal` независимо от этого инварианта |

## Что нужно для перехода на следующий уровень зрелости

1. Устранить разрыв noop→prod для 7 правил (см. предупреждение выше) — самостоятельная приоритетная задача,
   не входящая в объём этого документа.
2. Расширить `docs/detection_quality.md` с 11 на оставшиеся 15 инвариантов и заменить синтетический корпус
   эталонной выборкой «без атак» + размеченными сценариями промышленного трафика
   (`docs/certification_risk_roadmap.md`, раздел «Трек ФСТЭК», пункт 3).
3. Решить судьбу `polling_period_doubling_suspect` окончательно: либо формализовать статистический критерий,
   либо оставить эвристикой с явным `experimental: true` в `config/invariants/polling_period_doubling_suspect.yaml`
   (сейчас файл не помечен experimental, при этом сама эвристика не исполняется из-за noop — см. предупреждение).
