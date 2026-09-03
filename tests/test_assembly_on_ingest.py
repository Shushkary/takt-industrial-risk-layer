"""Приём потока сам доводит события до инцидента — без сидов от аналитика и без кнопки.

Замечание, с которого начата работа: собрать связанный инцидент умел только пивот по
отличительным сущностям, а сущности называл человек и запускал сборку отдельно — утилитой
или кнопкой в АРМ. Автоматический отбор сущностей уже сделан
(`AutoAssembleIncidentsUseCase`), но запускать его всё равно приходилось руками: штатный
приём через API заканчивался лентой мелких дел конвейера.

Здесь проверяется недостающая половина: событие, принятое штатным путём, само доводит
поток до инцидента. Прогон на эталоне INC-002 идёт через `IngestAssessmentFacade` — тот же
фасад, который вызывают обработчики `POST /events` и `POST /events/batch`.

Числа закреплены точными значениями: результат потоковой сборки обязан совпасть с
результатом одного прогона в конце (`tests/test_auto_assemble_incidents.py`), иначе
«собирается само» означает «собирается хуже».
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.assembly_on_ingest import AssembleOnIngest
from takt.application.use_cases.auto_assemble_incidents import (
    AutoAssembleIncidentsUseCase,
    AutoAssemblyReport,
    retire_unconfirmed_editions,
)
from takt.application.use_cases.ingest_facade import IngestAssessmentFacade
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.config.pipeline import build_assessment_pipeline
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.importers.csv_events import raw_row_to_normalized
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

# Замер на боевом конфиге. Те же значения, что даёт один прогон в конце приёма — сборка по
# ходу потока обязана сойтись к тому же инциденту, а не к своей версии.
EXPECTED_INCIDENT_EVENTS = 23
EXPECTED_SEEDS = (
    "address:185.220.101.34",
    "artifact:domain:cdn-metrics.example-analytics.com",
    "artifact:repo:release-prod",
    "user:smirnov",
    "user:svc_build",
)

# Событий в корпусе и из них — со срабатыванием инварианта. Сборка запускается по
# срабатыванию, а не по каждому принятому событию: 19 прогонов против 1030.
EXPECTED_EVENTS = 1030
EXPECTED_RUNS = 19


def _label(event) -> str:
    return str(event.payload.get("incident_id") or "")


def _case(case_id: str, *, status: CaseStatus = CaseStatus.TRIAGE, audit: list[str] | None = None) -> Case:
    case = Case(
        case_id=case_id,
        status=status,
        title=case_id,
        risk_class="MEDIUM",
        risk_score=1.0,
        created_at=datetime(2026, 8, 17, tzinfo=UTC),
    )
    case.audit_log = list(audit or [])
    return case


# --- триггер приёма -------------------------------------------------------


class _SpyAssembly:
    """Заглушка сборки: считает прогоны, не трогая хранилища."""

    def __init__(self, fail: bool = False) -> None:
        self.runs = 0
        self.fail = fail

    def execute(self, *, actor: str = "", now=None) -> AutoAssemblyReport:
        self.runs += 1
        if self.fail:
            raise RuntimeError("хранилище недоступно")
        return AutoAssemblyReport(incidents=(), considered_cases=(), skipped_cases=())


def test_assembly_runs_only_on_invariant_hit() -> None:
    """Штатное событие сборку не запускает: разбор начинается со срабатывания."""
    spy = _SpyAssembly()
    trigger = AssembleOnIngest(assemble=spy)  # type: ignore[arg-type]
    for _ in range(50):
        trigger.after_ingest(invariant_hits=[])
    assert spy.runs == 0
    trigger.after_ingest(invariant_hits=["Inv_OT_01"])
    assert spy.runs == 1


def test_assembly_can_be_batched_by_hits() -> None:
    """На потоке с частыми срабатываниями прогон можно сделать реже — одним параметром."""
    spy = _SpyAssembly()
    trigger = AssembleOnIngest(assemble=spy, hits_between_runs=3)  # type: ignore[arg-type]
    for _ in range(8):
        trigger.after_ingest(invariant_hits=["Inv_OT_01"])
    assert spy.runs == 2  # на 3-м и 6-м срабатывании; 7-е и 8-е ждут следующего


def test_failed_assembly_does_not_break_ingest() -> None:
    """Сбой сборки не отменяет приём события: приём первичен, сборка — производная."""
    spy = _SpyAssembly(fail=True)
    seen: list[BaseException] = []
    trigger = AssembleOnIngest(assemble=spy, on_error=seen.append)  # type: ignore[arg-type]
    trigger.after_ingest(invariant_hits=["Inv_OT_01"])
    assert spy.runs == 1
    assert len(seen) == 1 and isinstance(seen[0], RuntimeError)


# --- уборка редакций, собранных по неполному потоку -----------------------


def test_unconfirmed_edition_is_retired_when_stream_grows() -> None:
    """Инцидент, который прогон на выросшем потоке не воспроизвёл, не остаётся в очереди.

    Отличительность сущности зависит от объёма принятого потока: адрес, встречавшийся три
    раза, к следующему прогону встречается сорок и сидом быть перестаёт. Замер на INC-002:
    без уборки в очереди рядом с инцидентом цепочки остаётся карточка из 12 событий чистого
    фона, собранная в начале потока.
    """
    stale = _case(
        "AUTO-stale",
        audit=[
            "2026-08-17T06:00:00+00:00 | incident assembled by pivot seeds=address:10.10.1.26 core=12 expanded=0 hosts=- | actor=ingest",
            "2026-08-17T06:00:00+00:00 | incident assembled automatically after ingest seeds=1 core=12 | actor=ingest",
        ],
    )
    touched = _case(
        "AUTO-touched",
        audit=[
            "2026-08-17T06:00:00+00:00 | incident assembled automatically after ingest seeds=1 core=12 | actor=ingest",
            "2026-08-17T07:00:00+00:00 | case decision submitted | actor=analyst",
        ],
    )
    pipeline_case = _case("CASE-1")
    retired = retire_unconfirmed_editions(
        [stale, touched, pipeline_case], fresh_case_ids={"AUTO-fresh"}
    )
    assert [case.case_id for case in retired] == ["AUTO-stale"]
    assert stale.status is CaseStatus.MERGED
    assert touched.status is CaseStatus.TRIAGE, "инцидент в работе аналитика не трогают"
    assert pipeline_case.status is CaseStatus.TRIAGE, "дело конвейера сборке не принадлежит"


# --- полный прогон приёма на эталоне INC-002 ------------------------------


@pytest.fixture(scope="module")
def ingested(tmp_path_factory):
    """Приём 1030 событий штатным фасадом. Сборка не вызывается ни разу — она сама."""
    directory = tmp_path_factory.mktemp("assembly-on-ingest")
    weights = load_risk_weights(ROOT / "config" / "risk_weights.yaml")
    repo = SqliteCaseStore(directory / "cases.sqlite3")
    events_store = SqliteRecentEventStore(directory / "cases.sqlite3")
    try:
        pipeline = build_assessment_pipeline(
            weights, repo=repo, invariant_catalog_dir=ROOT / "config" / "invariants"
        )
        trigger = AssembleOnIngest(
            assemble=AutoAssembleIncidentsUseCase(
                assemble=AssembleIncidentUseCase(events=events_store, repo=repo, weights=weights),
                repo=repo,
                events=events_store,
            )
        )
        facade = IngestAssessmentFacade(
            process=pipeline.process,
            repo=repo,
            event_window=[],
            event_window_max=100_000,
            graph_edges=pipeline.graph_edges,
            polling_intervals_us=list(pipeline.polling_intervals_us),
            raw_row_to_normalized=raw_row_to_normalized,
            recent_event_store=events_store,
            assembly=trigger,
        )
        events = [
            event
            for name, mapper in MAPPERS.items()
            for event in CsvEventSourceReader(FIXTURES / f"{name}.csv", mapper)
        ]
        events.sort(key=lambda event: (event.observed_at, event.event_id))
        labels = {event.event_id: _label(event) for event in events}
        for event in events:
            facade.assess_normalized_event(event)

        incidents = [
            (case, Counter(labels.get(event_id, "?") for event_id in case.normalized_event_ids))
            for case in repo.list_all()
            if case.case_id.startswith("AUTO-") and case.status is not CaseStatus.MERGED
        ]
        yield trigger, len(events), incidents
    finally:
        events_store.close()
        repo.close()


def test_stream_assembles_one_incident_without_an_analyst(ingested) -> None:
    """После приёма в очереди есть инцидент, и никто его не заказывал."""
    _, _, incidents = ingested
    assert len(incidents) == 1
    case, counts = incidents[0]
    assert counts[CHAIN_ID] == EXPECTED_INCIDENT_EVENTS
    assert len(case.normalized_event_ids) == EXPECTED_INCIDENT_EVENTS


def test_stream_result_matches_a_single_run_at_the_end(ingested) -> None:
    """Сборка по ходу потока даёт тот же инцидент, что и один прогон в конце.

    Сущности не назначены конфигурацией и не названы человеком: их отобрал продукт, и набор
    совпал с тем, что для этого корпуса отобрал аналитик (`CHAIN_PIVOTS`).
    """
    _, _, incidents = ingested
    case, _ = incidents[0]
    seeds = tuple(sorted(f"{item.type}:{item.value}" for item in case.artifacts if item.source == "pivot-seed"))
    assert seeds == EXPECTED_SEEDS


def test_assembly_is_not_run_on_every_event(ingested) -> None:
    """Стоимость шага привязана к срабатываниям, а не к объёму потока."""
    trigger, total_events, _ = ingested
    assert total_events == EXPECTED_EVENTS
    assert trigger.runs == EXPECTED_RUNS


# --- сборка приложения ----------------------------------------------------


def test_api_ingest_assembles_in_process_when_asked(tmp_path: Path, monkeypatch) -> None:
    """`mode: on_ingest` — прогон идёт в процессе приёма, отдельный процесс не нужен."""
    from takt.infrastructure.config.weights_loader import load_risk_weights
    from takt.interface_adapters.api.main import create_app

    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(tmp_path / "cases.sqlite"))

    def _weights(path):
        loaded = load_risk_weights(path)
        loaded["incident_assembly"] = {**loaded.get("incident_assembly", {}), "mode": "on_ingest"}
        return loaded

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", _weights)
    app = create_app()
    try:
        assert isinstance(app.state.ingest_facade.assembly, AssembleOnIngest)
    finally:
        for attr in ("assembly_queue", "recent_event_store", "repo", "baseline"):
            close = getattr(getattr(app.state, attr, None), "close", None)
            if callable(close):
                close()


def test_api_ingest_without_persistent_events_keeps_pipeline_cases(monkeypatch) -> None:
    """Без постоянного хранилища событий сборке не из чего искать — приём остаётся прежним."""
    from takt.interface_adapters.api.main import create_app

    monkeypatch.setenv("TAKT_STORAGE", "memory")
    app = create_app()
    assert app.state.ingest_facade.assembly is None
