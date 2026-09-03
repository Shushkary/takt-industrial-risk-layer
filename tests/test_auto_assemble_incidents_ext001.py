"""Порог отличительности на независимом корпусе — EXT-001, реальная внешняя цепочка.

`AutoAssembleIncidentsUseCase` в `tests/test_auto_assemble_incidents.py` откалиброван на
корпусе INC-002 — синтетическом, собственном, 1030 событий. Порог по умолчанию (12) там
даёт чистый результат. Вопрос, который тот тест сам по себе не проверяет: генерализуется ли
число 12, или это константа, подогнанная под один конкретный корпус.

EXT-001 (`tests/fixtures/pt_techlab/ext_001/`) — не синтетика продукта, а конвертация
внешнего датасета (AIT Alert Data Set, независимая разметка, лицензия CC-BY-4.0). Все
208 событий фикстуры размечены одним инцидентом (`--only-labelled` в генераторе оставляет
только события внутри интервалов атаки, фона в фикстуре нет).

Замер показал: узлы и адреса этой цепочки естественно встречаются 18–37 раз каждый — атака
растянута на 18 часов, и повторные обращения к одному и тому же почтовому серверу дают
такую частоту без всякого фона. При пороге 12 (и вплоть до 30) ни одно из этих значений не
проходит порог, сиды не возникают, и `AutoAssembleIncidentsUseCase` не даёт **ни одного**
собранного инцидента — конвейер приёма отработал, а собрать цепочку в одно дело нечем, при
том что в фикстуре она есть целиком.

Это не баг в диагностике, а измеренный предел одного глобального порога: он не может
одновременно оставаться низким для короткой синтетической атаки (INC-002, где чистое плато
кончается на 25) и достаточно высоким для многочасовой атаки с частыми повторами (EXT-001,
где связность начинается около 40). Отсюда происходит `--distinctive-max-events` у
`load_dataset`, параметр `distinctive_max_events` у `POST /cases/assemble/auto` и
регулируемое поле в АРМ (`tests/test_arm_reachability.py`) — а не попытка найти одно число,
которое подойдёт всем.
"""

from __future__ import annotations

from pathlib import Path

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.auto_assemble_incidents import (
    AutoAssembleIncidentsUseCase,
    AutoAssemblyReport,
)
from takt.infrastructure.config.pipeline import build_assessment_pipeline
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.importers.soc_csv import CsvEventSourceReader, map_edr, map_siem
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "pt_techlab" / "ext_001"
MAPPERS = {"edr": map_edr, "siem": map_siem}

# Замер: суммарно 208 событий, все — одна размеченная цепочка (EXT-001), фона нет.
CORPUS_SIZE = 208


def _assemble(tmp_path: Path, *, threshold: int) -> AutoAssemblyReport:
    weights = load_risk_weights(ROOT / "config" / "risk_weights.yaml")
    events = [
        event
        for name, mapper in MAPPERS.items()
        for event in CsvEventSourceReader(FIXTURES / f"{name}.csv", mapper)
    ]
    events.sort(key=lambda event: (event.observed_at, event.event_id))
    assert len(events) == CORPUS_SIZE

    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    events_store = SqliteRecentEventStore(tmp_path / "cases.sqlite3")
    try:
        pipeline = build_assessment_pipeline(
            weights, repo=repo, invariant_catalog_dir=ROOT / "config" / "invariants"
        )
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
            distinctive_max_events=threshold,
        )
        return use_case.execute()
    finally:
        events_store.close()
        repo.close()


def test_shipped_default_finds_nothing_on_a_long_real_attack(tmp_path) -> None:
    """Порог 12 (значение по умолчанию) не даёт ни одного инцидента на EXT-001.

    Не потому, что цепочки нет: она есть целиком, размечена независимо, и её нет только
    потому, что ни одна сущность не проходит порог, откалиброванный на другом корпусе.
    Закреплено намеренно — как честно задокументированный предел, а не как цель.
    """
    report = _assemble(tmp_path, threshold=12)
    assert report.incidents == ()
    assert report.considered_cases, "фикстура не дошла до сборки: проверь конвейер приёма"


def test_raising_the_threshold_recovers_part_of_the_chain(tmp_path) -> None:
    """При поднятом пороге сборка находит связность — параметр действительно решает вопрос."""
    report = _assemble(tmp_path, threshold=40)
    assert report.incidents, "порог 40 должен связать хотя бы часть цепочки EXT-001"
    assert sum(item.event_count for item in report.incidents) >= 30
