"""Сборка инцидента отдельным процессом.

Сборка на приёме доводит поток до инцидента, но выполняется внутри запроса и на время
прогона держит замок: на эталонном корпусе это 60 мс, на хранилище в 8000 дел — 1,8 с
задержки приёма на каждое срабатывание инварианта. Для таких установок прогон выносится
из процесса API: приём только отмечает работу в очереди (одна короткая запись), а прогон
выполняет `python -m takt.tools.assembly_worker`.

Проверяется здесь ровно это: приём в режиме `worker` не собирает ничего сам, но и не теряет
ни одного срабатывания, а воркер по накопленным сигналам собирает тот же инцидент, что и
сборка внутри приёма.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.assembly_on_ingest import DeferAssemblyToWorker
from takt.application.use_cases.assembly_worker import (
    AssemblyWorkerService,
    assembly_config_mismatches,
)
from takt.application.use_cases.auto_assemble_incidents import AutoAssembleIncidentsUseCase
from takt.application.use_cases.ingest_facade import IngestAssessmentFacade
from takt.domain.entities.case import CaseStatus
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
from takt.infrastructure.stores.sqlite_assembly_queue import SqliteAssemblyQueue
from takt.infrastructure.stores.sqlite_recent_events import SqliteRecentEventStore
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "pt_techlab" / "inc_002"
MAPPERS = {"edr": map_edr, "siem": map_siem, "ndr": map_ndr, "ot": map_ot}

CHAIN_ID = "INC-002"
# Те же числа, что даёт сборка внутри приёма: вынос прогона в другой процесс меняет, кто и
# когда его выполняет, но не то, что получается.
EXPECTED_INCIDENT_EVENTS = 23
EXPECTED_HITS = 19

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


@pytest.fixture()
def queue(tmp_path: Path) -> SqliteAssemblyQueue:
    store = SqliteAssemblyQueue(tmp_path / "queue.sqlite3")
    yield store
    store.close()


# --- очередь сигналов -----------------------------------------------------


def test_ingest_only_marks_work(queue: SqliteAssemblyQueue) -> None:
    """Приём отмечает срабатывание и не собирает ничего сам."""
    defer = DeferAssemblyToWorker(queue=queue)
    for _ in range(5):
        defer.after_ingest(invariant_hits=[])
    assert queue.pending() == 0
    defer.after_ingest(invariant_hits=["Inv_OT_01"])
    defer.after_ingest(invariant_hits=["Inv_NET_02"])
    assert queue.pending() == 2


def test_taking_work_empties_the_queue(queue: SqliteAssemblyQueue) -> None:
    """Забранные сигналы не забираются повторно: иначе воркер крутил бы прогоны впустую."""
    queue.note_hits(3)
    assert queue.take_pending() == 3
    assert queue.take_pending() == 0


def test_signal_survives_worker_restart(tmp_path: Path) -> None:
    """Очередь лежит в той же базе, что дела: перезапуск воркера не теряет работу."""
    path = tmp_path / "queue.sqlite3"
    first = SqliteAssemblyQueue(path)
    first.note_hits(2)
    first.close()
    second = SqliteAssemblyQueue(path)
    try:
        assert second.take_pending() == 2
    finally:
        second.close()


# --- аренда: один воркер на базу ------------------------------------------


def test_second_worker_does_not_take_a_held_lease(queue: SqliteAssemblyQueue) -> None:
    """Два воркера на одной базе гоняли бы один и тот же прогон и мешали друг другу."""
    assert queue.acquire_lease(owner="host-a:1", now=NOW, ttl_sec=60) is True
    assert queue.acquire_lease(owner="host-b:2", now=NOW + timedelta(seconds=30), ttl_sec=60) is False


def test_expired_lease_is_taken_over(queue: SqliteAssemblyQueue) -> None:
    """Упавший воркер не блокирует сборку навсегда: аренда живёт, пока её продлевают."""
    queue.acquire_lease(owner="host-a:1", now=NOW, ttl_sec=60)
    assert queue.acquire_lease(owner="host-b:2", now=NOW + timedelta(seconds=61), ttl_sec=60) is True


def test_released_lease_is_free_immediately(queue: SqliteAssemblyQueue) -> None:
    """Штатная остановка воркера не заставляет сменщика ждать конца аренды."""
    queue.acquire_lease(owner="host-a:1", now=NOW, ttl_sec=60)
    queue.release_lease(owner="host-a:1")
    assert queue.acquire_lease(owner="host-b:2", now=NOW + timedelta(seconds=1), ttl_sec=60) is True


def test_foreign_worker_cannot_release_a_lease(queue: SqliteAssemblyQueue) -> None:
    """Освобождает аренду только тот, кто её взял."""
    queue.acquire_lease(owner="host-a:1", now=NOW, ttl_sec=60)
    queue.release_lease(owner="host-b:2")
    assert queue.acquire_lease(owner="host-b:2", now=NOW + timedelta(seconds=1), ttl_sec=60) is False


# --- служба воркера -------------------------------------------------------


class _SpyAssembly:
    def __init__(self) -> None:
        self.runs = 0

    def execute(self, *, actor: str = "", now=None):
        self.runs += 1
        from takt.application.use_cases.auto_assemble_incidents import AutoAssemblyReport

        return AutoAssemblyReport(incidents=(), considered_cases=(), skipped_cases=())


def test_worker_idles_without_signals(queue: SqliteAssemblyQueue) -> None:
    """Пустая очередь — пустой цикл: прогон стоит полного обхода хранилища дел."""
    spy = _SpyAssembly()
    service = AssemblyWorkerService(queue=queue, assemble=spy)  # type: ignore[arg-type]
    assert service.run_once() is None
    assert spy.runs == 0


def test_worker_collapses_accumulated_signals_into_one_run(queue: SqliteAssemblyQueue) -> None:
    """Сигналы, накопленные за цикл, дают один прогон, а не по прогону на срабатывание."""
    spy = _SpyAssembly()
    service = AssemblyWorkerService(queue=queue, assemble=spy)  # type: ignore[arg-type]
    queue.note_hits(7)
    assert service.run_once() is not None
    assert spy.runs == 1
    assert service.run_once() is None


def test_failed_run_returns_the_work_to_the_queue(queue: SqliteAssemblyQueue) -> None:
    """Сбой прогона не съедает сигналы: иначе одна ошибка оставляла бы поток без инцидента."""

    class _Failing:
        def execute(self, *, actor: str = "", now=None):
            raise RuntimeError("хранилище недоступно")

    seen: list[BaseException] = []
    service = AssemblyWorkerService(
        queue=queue,
        assemble=_Failing(),  # type: ignore[arg-type]
        on_error=seen.append,
    )
    queue.note_hits(2)
    assert service.run_once() is None
    assert len(seen) == 1
    assert queue.pending() == 2


# --- полный прогон приёма в режиме воркера --------------------------------


@pytest.fixture(scope="module")
def ingested_for_worker(tmp_path_factory):
    """Приём 1030 событий с отложенной сборкой, затем один прогон воркера."""
    directory = tmp_path_factory.mktemp("assembly-worker")
    database = directory / "cases.sqlite3"
    weights = load_risk_weights(ROOT / "config" / "risk_weights.yaml")
    repo = SqliteCaseStore(database)
    events_store = SqliteRecentEventStore(database)
    queue = SqliteAssemblyQueue(database)
    try:
        pipeline = build_assessment_pipeline(
            weights, repo=repo, invariant_catalog_dir=ROOT / "config" / "invariants"
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
            assembly=DeferAssemblyToWorker(queue=queue),
        )
        events = [
            event
            for name, mapper in MAPPERS.items()
            for event in CsvEventSourceReader(FIXTURES / f"{name}.csv", mapper)
        ]
        events.sort(key=lambda event: (event.observed_at, event.event_id))
        labels = {event.event_id: str(event.payload.get("incident_id") or "") for event in events}
        for event in events:
            facade.assess_normalized_event(event)
        pending_after_ingest = queue.pending()
        cases_after_ingest = [case for case in repo.list_all() if case.case_id.startswith("AUTO-")]

        service = AssemblyWorkerService(
            queue=queue,
            assemble=AutoAssembleIncidentsUseCase(
                assemble=AssembleIncidentUseCase(events=events_store, repo=repo, weights=weights),
                repo=repo,
                events=events_store,
            ),
        )
        report = service.run_once()
        incidents = [
            (case, Counter(labels.get(event_id, "?") for event_id in case.normalized_event_ids))
            for case in repo.list_all()
            if case.case_id.startswith("AUTO-") and case.status is not CaseStatus.MERGED
        ]
        yield pending_after_ingest, cases_after_ingest, report, incidents
    finally:
        queue.close()
        events_store.close()
        repo.close()


def test_ingest_does_not_assemble_in_worker_mode(ingested_for_worker) -> None:
    """Приём отдал 19 сигналов и не собрал ни одного инцидента сам."""
    pending, cases_after_ingest, _, _ = ingested_for_worker
    assert pending == EXPECTED_HITS
    assert cases_after_ingest == []


def test_worker_assembles_the_same_incident(ingested_for_worker) -> None:
    """Инцидент, собранный воркером, совпадает с тем, что даёт сборка внутри приёма."""
    _, _, report, incidents = ingested_for_worker
    assert report is not None
    assert len(incidents) == 1
    case, counts = incidents[0]
    assert counts[CHAIN_ID] == EXPECTED_INCIDENT_EVENTS
    assert len(case.normalized_event_ids) == EXPECTED_INCIDENT_EVENTS


# --- согласованность конфигурации API и воркера ---------------------------


def test_matching_settings_have_no_mismatches() -> None:
    """Одинаково настроенные процессы расхождений не дают."""
    assert (
        assembly_config_mismatches(
            api={"mode": "worker", "distinctive_max_events": 12},
            worker_mode="worker",
            worker_distinctive_max_events=12,
        )
        == []
    )


def test_mode_mismatch_is_reported() -> None:
    """API собирает сам, а воркер ждёт сигналов — он не получит ни одного."""
    found = assembly_config_mismatches(
        api={"mode": "on_ingest", "distinctive_max_events": 12},
        worker_mode="worker",
        worker_distinctive_max_events=12,
    )
    assert [item.field for item in found] == ["mode"]
    assert found[0].api == "on_ingest" and found[0].worker == "worker"


def test_threshold_mismatch_is_reported() -> None:
    """Разный порог отличительности — разные инциденты на одних и тех же данных."""
    found = assembly_config_mismatches(
        api={"mode": "worker", "distinctive_max_events": 12},
        worker_mode="worker",
        worker_distinctive_max_events=40,
    )
    assert [item.field for item in found] == ["distinctive_max_events"]


def test_missing_api_settings_are_not_a_mismatch() -> None:
    """Воркера могли запустить первым: сравнивать пока не с чем."""
    assert (
        assembly_config_mismatches(api=None, worker_mode="worker", worker_distinctive_max_events=12)
        == []
    )


def test_api_publishes_its_assembly_settings(tmp_path: Path, monkeypatch) -> None:
    """Поднявшийся API оставляет в базе отпечаток настройки — иначе сверять не с чем."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    app = create_app()
    try:
        assert app.state.assembly_queue.api_settings() is None, "объект приложения — ещё не API"
        with TestClient(app):
            pass
    finally:
        _close_app(app)

    # Читаем так же, как воркер: своим соединением с той же базой.
    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        published = queue.api_settings()
        assert published is not None
        assert published["mode"] == "worker"
        assert published["distinctive_max_events"] == 12
        assert published["config_path"].endswith(".yaml")
    finally:
        queue.close()


def test_worker_refuses_a_config_that_disagrees_with_the_api(tmp_path: Path, monkeypatch, capsys) -> None:
    """Воркер, настроенный иначе, чем API, не делает вид, что всё в порядке."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        queue.publish_api_settings(
            mode="on_ingest",
            distinctive_max_events=40,
            config_path="config/other.yaml",
            owner="host-a:1",
            at=datetime.now(UTC),
        )
    finally:
        queue.close()

    assert assembly_worker.run(once=True, poll_sec=0.01) == 4
    err = capsys.readouterr().err
    assert "mode" in err and "on_ingest" in err
    assert "distinctive_max_events" in err


def test_config_mismatch_can_be_allowed_on_purpose(tmp_path: Path, monkeypatch) -> None:
    """Догоняющая сборка с другим порогом — законный сценарий, но объявленный явно."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        queue.publish_api_settings(
            mode="on_ingest",
            distinctive_max_events=40,
            config_path="config/other.yaml",
            owner="host-a:1",
            at=datetime.now(UTC),
        )
    finally:
        queue.close()

    assert assembly_worker.run(once=True, poll_sec=0.01, allow_config_mismatch=True) == 0


def test_worker_warns_when_the_api_never_started(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пустая база — повод проверить путь к ней, а не молча ждать сигналов."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    queue.close()  # база есть, отпечатка API в ней нет

    assert assembly_worker.run(once=True, poll_sec=0.01) == 0
    assert "TAKT_SQLITE_PATH" in capsys.readouterr().out


def test_worker_leaves_its_own_trace(tmp_path: Path, monkeypatch) -> None:
    """По отметке воркера видно, что процесс сборки жив и с какими настройками."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    assembly_worker.run(once=True, poll_sec=0.01)

    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        trace = queue.worker_settings()
        assert trace is not None
        assert trace["mode"] == "worker"
        assert trace["distinctive_max_events"] == 12
    finally:
        queue.close()


# --- поставляемая конфигурация --------------------------------------------


def test_shipped_config_defers_assembly_to_the_worker() -> None:
    """Поставляемая конфигурация выносит сборку в отдельный процесс."""
    from takt.infrastructure.config.settings_helpers import incident_assembly_settings
    from takt.infrastructure.config.weights_loader import load_risk_weights

    settings = incident_assembly_settings(load_risk_weights(ROOT / "config" / "risk_weights.yaml"))
    assert settings.mode == "worker"


def test_compose_starts_the_worker_alongside_the_api() -> None:
    """Раз сборка вынесена в процесс, этот процесс должен подниматься вместе с API.

    Сторож ровно от той ошибки, ради которой писалась сверка настроек при старте: конфигурация
    говорит «собирает воркер», а разворачивание его не поднимает — приём работает, инцидентов
    нет, и никто не виноват.
    """
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "takt.tools.assembly_worker" in compose, "compose не поднимает сборку инцидентов"
    assert "profiles:" not in compose, "воркер под профилем не поднимется обычным `compose up`"


def test_systemd_unit_starts_the_worker() -> None:
    """На боевой ВМ воркер поднимается службой, а не руками после каждой перезагрузки."""
    unit = (ROOT / "deploy" / "systemd" / "takt-assembly-worker.service").read_text(encoding="utf-8")
    assert "takt.tools.assembly_worker" in unit
    assert "EnvironmentFile=" in unit, "API и воркер должны читать одни переменные окружения"


def test_systemd_unit_does_not_restart_on_config_error() -> None:
    """Неверная конфигурация должна остаться видимой, а не крутиться в перезапусках.

    Воркер выходит с кодом 4 при расхождении настроек с API и с кодом 3, когда аренду держит
    другой процесс. `Restart=always` превратил бы обе ошибки в бесконечный цикл, и служба
    выглядела бы работающей.
    """
    unit = (ROOT / "deploy" / "systemd" / "takt-assembly-worker.service").read_text(encoding="utf-8")
    prevent = [line for line in unit.splitlines() if line.startswith("RestartPreventExitStatus=")]
    assert prevent, "коды 3 и 4 не должны приводить к перезапуску"
    codes = set(prevent[0].split("=", 1)[1].split())
    assert {"3", "4"} <= codes


def test_systemd_units_put_directives_in_the_right_sections() -> None:
    """Директива не в своей секции игнорируется молча — юнит выглядит настроенным.

    Так и случилось при написании этих юнитов: предел перезапусков стоял в `[Service]`, где
    systemd его не читает, и служба с неверной конфигурацией перезапускалась бы бесконечно.
    """
    import configparser

    for name in ("takt-api.service", "takt-assembly-worker.service"):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(ROOT / "deploy" / "systemd" / name, encoding="utf-8")
        assert parser.sections() == ["Unit", "Service", "Install"], name
        for directive in ("StartLimitIntervalSec", "StartLimitBurst"):
            assert parser.has_option("Unit", directive), f"{name}: {directive} должен быть в [Unit]"
            assert not parser.has_option("Service", directive), f"{name}: {directive} в [Service]"
        for directive in ("ExecStart", "EnvironmentFile", "Restart"):
            assert parser.has_option("Service", directive), f"{name}: нет {directive}"


def test_systemd_target_starts_both_processes() -> None:
    """Одна команда поднимает пару: забыть второй процесс не должно быть возможно."""
    target = (ROOT / "deploy" / "systemd" / "takt.target").read_text(encoding="utf-8")
    assert "takt-api.service" in target
    assert "takt-assembly-worker.service" in target


def test_api_says_that_assembly_needs_a_worker(tmp_path: Path, monkeypatch, caplog) -> None:
    """Стенд без воркера иначе выглядит как отказ сборки, а не как незапущенный процесс."""
    import logging

    from takt.interface_adapters.api.main import create_app

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    with caplog.at_level(logging.INFO, logger="takt.api"):
        app = create_app()
    try:
        assert "takt.tools.assembly_worker" in caplog.text
    finally:
        _close_app(app)


def test_quickstart_names_the_worker() -> None:
    """Быстрый старт обязан называть оба процесса: иначе инциденты не появятся."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "python -m takt.tools.assembly_worker" in readme


# --- режим приложения и точка входа ---------------------------------------


def test_api_defers_assembly_in_worker_mode(tmp_path: Path, monkeypatch) -> None:
    """При `mode: worker` приём отмечает работу, а не собирает."""
    from takt.interface_adapters.api.main import create_app

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    app = create_app()
    try:
        assert isinstance(app.state.ingest_facade.assembly, DeferAssemblyToWorker)
        assert app.state.assembly_queue is not None
    finally:
        _close_app(app)


def test_api_assembles_nothing_in_off_mode(tmp_path: Path, monkeypatch) -> None:
    """`mode: off` оставляет сборку ручной — кнопкой в АРМ."""
    from takt.interface_adapters.api.main import create_app

    _sqlite_env(monkeypatch, tmp_path, mode="off")
    app = create_app()
    try:
        assert app.state.ingest_facade.assembly is None
        # Очередь всё равно открыта: в ней лежит отпечаток настройки, по которому воркер
        # поймёт, что API собирать не просили, и скажет об этом вместо молчания.
        assert app.state.assembly_queue is not None
    finally:
        _close_app(app)


def test_unknown_mode_is_rejected(tmp_path: Path, monkeypatch) -> None:
    """Опечатка в режиме не должна тихо откатываться на сборку внутри приёма."""
    from takt.interface_adapters.api.main import create_app

    _sqlite_env(monkeypatch, tmp_path, mode="worker-ish")
    with pytest.raises(ValueError, match=r"incident_assembly\.mode"):
        create_app()


def test_worker_entrypoint_runs_a_single_cycle(tmp_path: Path, monkeypatch, capsys) -> None:
    """`--once` отрабатывает цикл и освобождает аренду: годится для проверки настройки."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    assert assembly_worker.run(once=True, poll_sec=0.01) == 0
    assert "assembly worker started" in capsys.readouterr().out

    queue = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        assert queue.acquire_lease(owner="other:1", now=NOW, ttl_sec=60) is True
    finally:
        queue.close()


def test_worker_refuses_to_start_twice(tmp_path: Path, monkeypatch, capsys) -> None:
    """Второй воркер на той же базе выходит с кодом 3, а не гоняет тот же прогон."""
    from takt.tools import assembly_worker

    _sqlite_env(monkeypatch, tmp_path, mode="worker")
    held = SqliteAssemblyQueue(tmp_path / "cases.sqlite")
    try:
        held.acquire_lease(owner="host-a:1", now=datetime.now(UTC), ttl_sec=600)
        assert assembly_worker.run(once=True, poll_sec=0.01) == 3
        assert "аренда занята" in capsys.readouterr().err
    finally:
        held.close()


def _sqlite_env(monkeypatch, tmp_path: Path, *, mode: str) -> None:
    """Приложение на временной базе с заданным режимом сборки."""
    monkeypatch.setenv("TAKT_STORAGE", "sqlite")
    monkeypatch.setenv("TAKT_SQLITE_PATH", str(tmp_path / "cases.sqlite"))

    def _weights(path):
        from takt.infrastructure.config.weights_loader import load_risk_weights

        loaded = load_risk_weights(path)
        loaded["incident_assembly"] = {**loaded.get("incident_assembly", {}), "mode": mode}
        return loaded

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", _weights)


def _close_app(app) -> None:
    for attr in ("assembly_queue", "recent_event_store", "repo", "baseline"):
        close = getattr(getattr(app.state, attr, None), "close", None)
        if callable(close):
            close()
