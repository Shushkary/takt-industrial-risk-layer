"""Сборка боевого конвейера оценки из конфигурации.

Одно место, где веса, каталог инвариантов и топология превращаются в
``AssessRiskUseCase`` и ``ProcessEventUseCase``. Им пользуются и запуск API
(``create_app``), и прогон накопленных сценариев регресса
(``tests/test_case_scenarios.py``).

Зачем вынесено. Прогон на кодовых умолчаниях проверяет не то, что работает у заказчика:
боевой каталог правил лежит в ``config/invariants/*.yaml`` и с кодовыми умолчаниями расходится
(предупреждение в ``docs/invariant_matrix.md``). Пока сборка была только внутри ``create_app``,
любой воспроизводящий прогон приходилось собирать заново — и он тихо расходился с боевым.
Здесь же живут значения окружения оценки (рёбра графа, интервалы опроса), чтобы повторный
прогон давал тот же результат, что и приём события через API.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.invariants.evaluator import invariant_context_from_config
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.infrastructure.config.invariant_catalog_yaml import (
    catalog_experimental_invariant_ids,
    catalog_rule_overrides,
    catalog_rule_specs,
    load_invariant_catalog_from_dir,
)
from takt.infrastructure.config.settings_helpers import (
    enrichment_from_weights,
    graph_edges_from_weights,
    topology_from_weights,
    trust_by_source_from_weights,
)

DEFAULT_POLLING_INTERVALS_US: tuple[float, ...] = (1000.0, 1000.0, 4670.0, 21_800.0)
"""Профиль опроса демо-стенда. Один и тот же у приёма событий и у прогона сценариев."""


@dataclass(frozen=True, slots=True)
class AssessmentPipeline:
    """Собранный конвейер и окружение оценки, в котором он даёт воспроизводимый результат."""

    assess: AssessRiskUseCase
    process: ProcessEventUseCase
    invariant_catalog: Any
    graph_edges: Sequence[GraphEdge]
    polling_intervals_us: Sequence[float]
    trust_by_source: Mapping[str, float] | None
    jump_host: str
    plc_hosts: frozenset[str]


def build_assessment_pipeline(
    weights: Mapping[str, Any],
    *,
    repo: CaseRepositoryPort,
    invariant_catalog_dir: Path,
    expected_behavior: ExpectedBehaviorPort | None = None,
) -> AssessmentPipeline:
    """Собрать конвейер так же, как это делает запуск API."""
    jump_host, plc_hosts = topology_from_weights(weights)
    catalog = load_invariant_catalog_from_dir(invariant_catalog_dir)
    assess = AssessRiskUseCase(
        weights,
        jump_host=jump_host,
        plc_hosts=plc_hosts,
        expected_behavior=expected_behavior,
        invariant_profile=invariant_context_from_config(weights),
        rule_overrides=catalog_rule_overrides(catalog),
        experimental_invariant_ids=catalog_experimental_invariant_ids(catalog),
        rule_specs=catalog_rule_specs(catalog),
    )
    return AssessmentPipeline(
        assess=assess,
        process=ProcessEventUseCase(assess, repo, enrichment=enrichment_from_weights(weights)),
        invariant_catalog=catalog,
        graph_edges=graph_edges_from_weights(weights, plc_hosts=plc_hosts),
        polling_intervals_us=list(DEFAULT_POLLING_INTERVALS_US),
        trust_by_source=trust_by_source_from_weights(weights),
        jump_host=jump_host,
        plc_hosts=plc_hosts,
    )
