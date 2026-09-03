"""Автоматическая сборка инцидента после приёма — замер на эталоне INC-002.

Замечание, с которого начата работа: 27 связанных событий атаки, принятые штатным
механизмом, давали 21 отдельное дело вместо одного связанного инцидента. Фикстура INC-002
воспроизводит ровно это — 1030 событий, из них 27 размечены как цепочка `INC-002`,
остальное фон и отвлекающие аномалии (`BG-ADMIN`, `BG-SCAN`, `BG-BACKUP`).

Числа здесь закреплены точными значениями, а не границами вида «не хуже, чем». Замер, у
которого нет точного значения, перестаёт быть замером: сдвиг с 23 событий на 19 прошёл бы
мимо проверки «не меньше 20», а это и есть та регрессия, ради которой тест написан. Если
число изменилось осознанно — оно меняется здесь вместе с разбором в
`docs/pt_techlab/correlation_quality.md`.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.auto_assemble_incidents import AutoAssembleIncidentsUseCase
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.config.pipeline import build_assessment_pipeline
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.importers.soc_csv import (
    CsvEventSourceReader,
    map_edr,
    map_ndr,
    map_ot,
    map_siem,
)
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "pt_techlab" / "inc_002"
MAPPERS = {"edr": map_edr, "siem": map_siem, "ndr": map_ndr, "ot": map_ot}

CHAIN_ID = "INC-002"
CHAIN_SIZE = 27

# Столько дел конвейера получала цепочка до работы: замечание, воспроизведённое на этой же
# фикстуре. Число зафиксировано, чтобы регрессия читалась как число, а не как ощущение.
CASES_BEFORE = 21

# Замер на боевом конфиге (`config/risk_weights.yaml`), порог отличительности 12.
EXPECTED_INCIDENTS = 1
EXPECTED_INCIDENT_EVENTS = 23
EXPECTED_CONSIDERED_CASES = 7
EXPECTED_SKIPPED_CASES = 3

# Сущности, которые сборка выбирает сама. Совпадают с набором, отобранным для этого корпуса
# человеком (`CHAIN_PIVOTS` в tests/test_pt_techlab_inc_002.py), кроме объектов уровня узла:
# узел сидом не бывает.
EXPECTED_SEEDS = (
    "address:185.220.101.34",
    "artifact:domain:cdn-metrics.example-analytics.com",
    "artifact:repo:release-prod",
    "user:smirnov",
    "user:svc_build",
)


def _label(event) -> str:
    return str(event.payload.get("incident_id") or "")


class _CountingCaseStore(SqliteCaseStore):
    """Хранилище, считающее полные обходы.

    Полный обход стоит O(дел), и раньше сборка делала его трижды плюс ещё по разу на каждый
    собранный инцидент. Замер: 8000 дел и 40 инцидентов — 20 с только на обходы. Счётчик
    держит границу: обход должен остаться одним на прогон.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.list_all_calls = 0

    def list_all(self) -> list[Case]:
        self.list_all_calls += 1
        return super().list_all()


@pytest.fixture(scope="module")
def assembled(tmp_path_factory):
    """Полный прогон: приём 1030 событий штатным конвейером, затем сборка инцидентов."""
    directory = tmp_path_factory.mktemp("auto-assembly")
    weights = load_risk_weights(ROOT / "config" / "risk_weights.yaml")
    repo = _CountingCaseStore(directory / "cases.sqlite3")
    events_store = SqliteRecentEventStore(directory / "cases.sqlite3")
    try:
        pipeline = build_assessment_pipeline(
            weights, repo=repo, invariant_catalog_dir=ROOT / "config" / "invariants"
        )
        events = [
            event
            for name, mapper in MAPPERS.items()
            for event in CsvEventSourceReader(FIXTURES / f"{name}.csv", mapper)
        ]
        events.sort(key=lambda event: (event.observed_at, event.event_id))
        labels = {event.event_id: _label(event) for event in events}
        for event in events:
            pipeline.process.execute(
                event,
                recent_events=[],
                tickets=[],
                graph_edges=list(pipeline.graph_edges),
                polling_intervals_us=list(pipeline.polling_intervals_us),
                clock=event.observed_at,
            )
            events_store.add_recent_event(event, max_events=len(events))

        use_case = AutoAssembleIncidentsUseCase(
            assemble=AssembleIncidentUseCase(events=events_store, repo=repo, weights=weights),
            repo=repo,
            events=events_store,
        )
        repo.list_all_calls = 0
        report = use_case.execute()
        scans = repo.list_all_calls
        incidents = [
            (item, repo.get(item.case_id), Counter(
                labels.get(event_id, "?") for event_id in repo.get(item.case_id).normalized_event_ids
            ))
            for item in report.incidents
        ]
        yield report, incidents, scans
    finally:
        events_store.close()
        repo.close()


def test_chain_is_assembled_into_a_single_incident(assembled) -> None:
    """Было 21 дело на цепочку — стал один инцидент."""
    report, incidents, _ = assembled
    assert len(report.incidents) == EXPECTED_INCIDENTS
    _, case, counts = incidents[0]
    assert counts[CHAIN_ID] == EXPECTED_INCIDENT_EVENTS
    assert len(case.normalized_event_ids) == EXPECTED_INCIDENT_EVENTS
    assert EXPECTED_INCIDENT_EVENTS < CASES_BEFORE * 2  # разбор одной карточкой, а не лентой


def test_assembled_core_contains_no_background(assembled) -> None:
    """Ядро не смешивает цепочку с фоном — это и есть обещание «надёжного ядра».

    Проверка не на «мало фона», а на его отсутствие: пороги отличительности выше 25
    собирают цепочку полнее, но приводят с ней 245 фоновых событий, и такой инцидент
    читается не лучше, чем 21 отдельное дело.
    """
    _, incidents, _ = assembled
    for item, _, counts in incidents:
        other = {label: value for label, value in counts.items() if label != CHAIN_ID}
        assert not other, f"{item.case_id}: в ядро попал фон — {other}"


def test_seeds_match_the_entities_a_human_picked(assembled) -> None:
    """Сущности отобраны продуктом, а не назначены в конфигурации."""
    _, incidents, _ = assembled
    item, _, _ = incidents[0]
    assert item.seeds == EXPECTED_SEEDS


def test_report_names_what_was_examined_and_what_was_left(assembled) -> None:
    """Дело без отличительной сущности не молчит: оно названо в отчёте как пропущенное."""
    report, _, _ = assembled
    assert len(report.considered_cases) == EXPECTED_CONSIDERED_CASES
    assert len(report.skipped_cases) == EXPECTED_SKIPPED_CASES
    assert set(report.skipped_cases) <= set(report.considered_cases)


def test_incident_id_is_derived_from_seeds_not_random(assembled) -> None:
    """Повторный прогон даёт тот же инцидент, а не его копию рядом с прежним."""
    report, _, _ = assembled
    assert all(item.case_id.startswith("AUTO-") for item in report.incidents)
    assert len({item.case_id for item in report.incidents}) == len(report.incidents)


def test_assembled_incident_is_not_a_seed_for_the_next_run(assembled) -> None:
    """Собранный инцидент не попадает в отбор как дело конвейера."""
    report, _, _ = assembled
    assert {item.case_id for item in report.incidents}.isdisjoint(set(report.considered_cases))


def test_assembled_incident_keeps_the_trail_to_pipeline_cases(assembled) -> None:
    """Из инцидента видно, из каких дел конвейера он собран."""
    _, incidents, _ = assembled
    item, case, _ = incidents[0]
    assert item.source_case_ids
    assert case.related_cases == sorted(item.source_case_ids)
    assert case.status is CaseStatus.TRIAGE


def test_storage_is_scanned_once_per_run(assembled) -> None:
    """Полный обход хранилища — один на прогон, а не по одному на инцидент."""
    _, _, scans = assembled
    assert scans == 1, f"хранилище обойдено {scans} раз(а)"
