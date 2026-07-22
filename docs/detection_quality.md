# Протоколы true positive / false positive

Документ закрывает пункт «протоколы true positive / false positive» из
`docs/product_boundary.md` (раздел «Подготовка к ФСТЭК») и
`docs/certification_risk_roadmap.md` (Трек ФСТЭК, п.3) для части каталога
26 инвариантов.

## Методология

- Инструмент: [`scripts/eval_detection.py`](../scripts/eval_detection.py).
- Корпус сценариев: [`tests/fixtures/detection_eval/scenarios.py`](../tests/fixtures/detection_eval/scenarios.py) —
  22 размеченных сценария (11 эталонных атак + 11 легитимных/пограничных случаев),
  каждый — одно нормализованное событие (+ история) с явным ожидаемым набором
  сработавших инвариантов (`expected_hits`; пустой набор — легитимный трафик).
- Оценка идёт через `collect_extended_invariants` по **код-дефолтному каталогу
  правил** (`default_extended_rule_specs()` в `src/takt/domain/invariants/rule_spec.py`),
  а не по боевому YAML из `config/invariants/`. Это осознанное решение: боевой
  каталог на момент составления протокола расходился с кодом для 7 инвариантов
  (`predicate_ref: builtin:noop`, см. `docs/invariant_matrix.md`, раздел
  «Известный разрыв» — устранение отслеживается отдельной задачей). Протокол
  оценивает **корректность предикатов**, а не то, какие из них включены в
  текущей конфигурации; после исправления noop-разрыва тот же корпус можно
  прогнать и против `catalog_rule_specs(inv_catalog)` для проверки паритета.
- Регрессия: [`tests/test_detection_quality.py`](../tests/test_detection_quality.py) — часть
  обычного прогона `pytest`, падает при регрессии TPR/FPR по любому инварианту
  из объёма.

## Объём (11 из 26 инвариантов)

Выбраны инварианты с детерминированными триггерами, не требующими графа
топологии (`jump_server_bypass`, `new_node_airgap` — вне объёма этого протокола)
и не входящие в список noop-разрыва:

`illegal_function_code`, `log_wiping`, `brute_force`, `payload_length_drift`,
`protocol_escalation`, `blind_command`, `reconnaissance`,
`physical_invariant_breach`, `cyclic_service_crash`, `untrusted_ip_admin`,
`lateral_movement`.

## Результат (baseline)

По состоянию на момент записи все 11 инвариантов в объёме показывают
**TPR = 1.0, FPR = 0.0** на синтетическом корпусе (см. вывод
`python scripts/eval_detection.py`). Это ожидаемо: корпус построен по тем же
условиям, что и сами предикаты (аналогично `tests/test_invariants_evaluator.py`),
и **не является** независимой проверкой на промышленном трафике.

## Ограничения этого протокола (важно для лаборатории)

- Синтетический, не промышленный корпус: 22 сценария, не тысячи событий из
  реального трафика КИИ. Совпадение условий генерации сценария и условия
  срабатывания предиката завышает TPR/FPR относительно реальных данных.
- Не покрыты: 7 инвариантов из «Известного разрыва» (`docs/invariant_matrix.md`),
  `jump_server_bypass`/`new_node_airgap` (нужен граф топологии, не входят в
  `collect_extended_invariants` без дополнительного контекста), остальные
  8 инвариантов Блоков 4-6, требующие более сложного контекста (наряды,
  тикеты, DQ pipeline) — `conflict_logic`, `runtime_config_change`,
  `c2_external_dns`, `trust_index_drop`, `request_reply_dissonance`,
  `expert_dissonance`, `polling_jitter` (частично покрыт в
  `tests/test_invariants_evaluator.py`, не в этом корпусе).
- Не оценивает совокупный `risk_score`/`risk_class` — только срабатывание
  отдельных инвариантов на уровне `collect_extended_invariants`.

## Дальнейшие шаги

1. Расширить корпус на оставшиеся инварианты (Блоки 4-6 с контекстом ТО/DQ,
   `jump_server_bypass`/`new_node_airgap` через `AssessRiskUseCase.execute`
   целиком, а не только `collect_extended_invariants`).
2. Заменить/дополнить синтетический корпус эталонной выборкой промышленного
   трафика «без атак» + размеченными сценариями атак от эксплуатанта или
   аккредитованной лаборатории — независимая проверка, не на тех же условиях,
   что предикат.
3. Прогнать корпус против боевого `config/invariants/` (после устранения
   noop-разрыва) для проверки паритета код-дефолт vs prod-конфиг.
4. Долгосрочно: перейти от TPR/FPR по отдельным инвариантам к end-to-end
   метрикам по `risk_class` на размеченных инцидентах.
