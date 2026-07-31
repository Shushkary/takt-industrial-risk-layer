from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# TAKT_SQLITE_PATH и TAKT_CONFIG обязаны лежать под корнем проекта
# (settings_helpers._project_local_path), поэтому tmp_path здесь не подходит.
WORK_DIR = ROOT / "data" / "stand" / "_pytest"
STAND_CONFIG = ROOT / "deploy" / "stand" / "risk_weights.stand.yaml"


def _load(script: str):
    path = ROOT / "scripts" / script
    spec = importlib.util.spec_from_file_location(f"stand_script_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def work_dir() -> Iterator[Path]:
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        yield WORK_DIR
    finally:
        shutil.rmtree(WORK_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("TAKT_CONFIG", "TAKT_STORAGE", "TAKT_SQLITE_PATH", "TAKT_PROFILE",
                 "TAKT_AUTH_REQUIRED", "TAKT_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)


def _generate(dataset_module, out: Path, sources: str, *, incidents: int, noise: int, seed: int) -> dict:
    assert dataset_module.main(["--sources", sources, "--incidents", str(incidents),
                               "--noise", str(noise), "--seed", str(seed), "--out", str(out)]) == 0
    return json.loads((out / "ground_truth.json").read_text(encoding="utf-8"))


def test_dataset_is_deterministic_and_matches_contract(work_dir: Path) -> None:
    dataset = _load("stand_dataset.py")
    out = work_dir / "dataset"

    ground_truth = _generate(dataset, out, "edr,ot", incidents=2, noise=10, seed=11)
    first = (out / "edr.csv").read_text(encoding="utf-8")
    _generate(dataset, out, "edr,ot", incidents=2, noise=10, seed=11)
    assert (out / "edr.csv").read_text(encoding="utf-8") == first, "один seed обязан давать один датасет"

    assert first.splitlines()[0].split(",") == list(dataset.HEADERS["edr"])
    assert ground_truth["sources"] == ["edr", "ot"]
    assert len(ground_truth["incidents"]) == 2
    for incident in ground_truth["incidents"]:
        sources = {ground_truth["source_by_event"][event_id] for event_id in incident["event_ids"]}
        assert sources == {"edr", "ot"}
    # фон размечен поштучно, иначе pairwise-метрика не увидит ложных слияний
    background = [value for value in ground_truth["events"].values() if not value.startswith("INC-")]
    assert len(set(background)) == len(background)


def test_dataset_covers_all_four_source_classes(work_dir: Path) -> None:
    """Полный набор ADR-001: четыре CSV, и каждая цепочка видна всеми четырьмя источниками."""
    dataset = _load("stand_dataset.py")
    out = work_dir / "dataset"

    ground_truth = _generate(dataset, out, "ndr,ot,edr,siem", incidents=2, noise=12, seed=13)

    # порядок аргумента не влияет на датасет — источники канонизируются
    assert ground_truth["sources"] == ["edr", "siem", "ndr", "ot"]
    for source in ("edr", "siem", "ndr", "ot"):
        header = (out / f"{source}.csv").read_text(encoding="utf-8").splitlines()[0].split(",")
        assert header == list(dataset.HEADERS[source])
    for incident in ground_truth["incidents"]:
        sources = {ground_truth["source_by_event"][event_id] for event_id in incident["event_ids"]}
        assert sources == {"edr", "siem", "ndr", "ot"}


def test_dataset_rejects_bad_source_lists() -> None:
    dataset = _load("stand_dataset.py")
    for bad in ("edr", "", "edr,edr", "edr,syslog"):
        with pytest.raises(argparse.ArgumentTypeError):
            dataset.parse_sources(bad)


def test_two_source_stand_links_it_and_ot(work_dir: Path) -> None:
    dataset_script = _load("stand_dataset.py")
    runner = _load("stand_run.py")
    dataset_dir = work_dir / "dataset"
    report_dir = work_dir / "report"

    ground_truth = _generate(dataset_script, dataset_dir, "edr,ot", incidents=3, noise=20, seed=5)
    assert runner.run(dataset=dataset_dir, db_path=work_dir / "takt.db", report_dir=report_dir,
                      config=STAND_CONFIG, reset=True) == 0

    assert (report_dir / "report.md").is_file()
    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))

    expected_total = sum(ground_truth["counts"].values())
    assert report["ingest"]["processed_total"] == expected_total
    assert report["ingest"]["failed_total"] == 0
    assert report["store"]["events_total"] == expected_total
    assert set(report["store"]["events_by_source"]) == {"edr", "ot"}

    assert report["rule_coverage"]["generalized_enabled"] is True
    assert report["correlation"]["cross_source_case_count"] >= 1

    # map_ot переносит operator_id в user_id, поэтому OT участвует в user_destination;
    # артефакта hash у OT нет и не должно быть — file_hash для него слеп by design
    blind = {rule["rule"]: rule["blind_sources"] for rule in report["rule_coverage"]["rules"]}
    assert blind["host_window"] == []
    assert blind["user_destination"] == []
    assert blind["file_hash"] == ["ot"]


def test_four_source_stand_merges_all_classes_into_one_case(work_dir: Path) -> None:
    """Главная проверка стенда: все четыре класса ADR-001 сходятся в общий кейс."""
    dataset_script = _load("stand_dataset.py")
    runner = _load("stand_run.py")
    dataset_dir = work_dir / "dataset"
    report_dir = work_dir / "report"

    ground_truth = _generate(dataset_script, dataset_dir, "edr,siem,ndr,ot", incidents=3, noise=20, seed=5)
    assert runner.run(dataset=dataset_dir, db_path=work_dir / "takt.db", report_dir=report_dir,
                      config=STAND_CONFIG, reset=True) == 0

    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))

    assert report["stand"]["sources"] == ["edr", "siem", "ndr", "ot"]
    assert report["ingest"]["processed_total"] == sum(ground_truth["counts"].values())
    assert report["ingest"]["failed_total"] == 0
    assert set(report["store"]["events_by_source"]) == {"edr", "siem", "ndr", "ot"}
    assert set(report["ingest"]["processed_by_source"]) == {"edr", "siem", "ndr", "ot"}

    # хотя бы один кейс собрал все четыре класса — иначе стенд не проверяет то, ради чего он есть
    assert report["correlation"]["max_sources_in_case"] == 4
    assert sum(report["correlation"]["cases_by_source_count"].values()) == \
        report["correlation"]["cross_source_case_count"]

    # покрытие правил отражает контракт данных: у NDR нет пользователя, у NDR и OT — хеша
    blind = {rule["rule"]: rule["blind_sources"] for rule in report["rule_coverage"]["rules"]}
    assert blind["host_window"] == []
    assert blind["user_destination"] == ["ndr"]
    assert blind["file_hash"] == ["ndr", "ot"]

    # несобранные цепочки обязаны нести объяснение по конкретным правилам конфига
    for item in report["correlation"]["incident_recovery"]:
        assert set(item["sources"]) == {"edr", "siem", "ndr", "ot"}
        if not item["fully_merged"]:
            assert "`host_window`" in item["split_reason"] or "`user_destination`" in item["split_reason"]


def test_stand_run_on_production_config_has_no_cross_source_correlation(work_dir: Path) -> None:
    """Страховка от регресса документации: при mode=legacy корреляция источников молча выключена."""
    dataset_script = _load("stand_dataset.py")
    runner = _load("stand_run.py")
    dataset_dir = work_dir / "dataset"

    _generate(dataset_script, dataset_dir, "edr,siem,ndr,ot", incidents=2, noise=12, seed=3)
    assert runner.run(dataset=dataset_dir, db_path=work_dir / "legacy.db",
                      report_dir=work_dir / "legacy-report",
                      config=ROOT / "config" / "risk_weights.yaml", reset=True) == 0

    report = json.loads((work_dir / "legacy-report" / "report.json").read_text(encoding="utf-8"))
    assert report["rule_coverage"]["mode"] == "legacy"
    assert report["rule_coverage"]["generalized_enabled"] is False
    assert report["correlation"]["cross_source_case_count"] == 0
    assert report["correlation"]["max_sources_in_case"] == 0


def test_scenario_requires_four_source_classes(work_dir: Path) -> None:
    """ТЗ п. 12.1 требует не менее четырёх классов; на двух симуляция обязана отказать."""
    dataset_script = _load("stand_dataset.py")
    scenario = _load("stand_scenario.py")
    dataset_dir = work_dir / "dataset"

    _generate(dataset_script, dataset_dir, "edr,ot", incidents=2, noise=10, seed=9)
    rc = scenario.run(dataset=dataset_dir, db_path=work_dir / "takt.db",
                      report_dir=work_dir / "report", config=STAND_CONFIG)
    assert rc == 2


def test_scenario_covers_mvp_requirements_of_the_specification(work_dir: Path) -> None:
    """Сквозная симуляция расследования: все пункты минимального результата MVP (п. 14 ТЗ)."""
    dataset_script = _load("stand_dataset.py")
    scenario = _load("stand_scenario.py")
    dataset_dir = work_dir / "dataset"
    report_dir = work_dir / "report"

    _generate(dataset_script, dataset_dir, "edr,siem,ndr,ot", incidents=3, noise=24, seed=5)
    rc = scenario.run(dataset=dataset_dir, db_path=work_dir / "takt.db",
                      report_dir=report_dir, config=STAND_CONFIG)
    assert rc == 0, (report_dir / "scenario.md").read_text(encoding="utf-8")

    assert (report_dir / "scenario.md").is_file()
    report = json.loads((report_dir / "scenario.json").read_text(encoding="utf-8"))

    failed = [item["requirement"] for item in report["mvp_checklist"] if not item["ok"]]
    assert failed == []

    steps = {str(item["step"]): item for item in report["scenario"]["steps"]}
    assert len(steps) >= 12
    assert all(bool(item["ok"]) for item in steps.values())

    # единое окно действительно сводит все четыре класса
    window = next(item for name, item in steps.items() if name.startswith("Единое окно"))
    assert set(window["evidence"]["sources_in_case"]) == {"edr", "siem", "ndr", "ot"}
    assert window["evidence"]["timeline_entries"] > 0
    assert window["evidence"]["graph_nodes"] > 0

    # human-in-the-loop: до действий аналитика система не решает за него
    decision = next(item for name, item in steps.items() if name.startswith("Решение принимает аналитик"))
    assert decision["evidence"]["cases_decided_by_system_before_analyst"] == 0
    assert decision["evidence"]["status_after"] == "CONFIRMED"

    # ручная корректировка связи выполнена по-настоящему, а не пропущена
    manual = next(item for name, item in steps.items() if name.startswith("Ручная корректировка"))
    assert manual["evidence"]["mode"] in {"attach_orphan", "detach_attach_roundtrip"}
    assert manual["takt_actions"] >= 1

    assert report["rbac"]["ok"] is True
    assert report["scenario"]["totals"]["target_met"] is True


def test_scenario_is_repeatable_from_clean_database(work_dir: Path) -> None:
    """Повторный прогон не должен ломаться о решения и находки предыдущего."""
    dataset_script = _load("stand_dataset.py")
    scenario = _load("stand_scenario.py")
    dataset_dir = work_dir / "dataset"
    report_dir = work_dir / "report"

    _generate(dataset_script, dataset_dir, "edr,siem,ndr,ot", incidents=2, noise=16, seed=21)
    for _ in range(2):
        assert scenario.run(dataset=dataset_dir, db_path=work_dir / "takt.db",
                            report_dir=report_dir, config=STAND_CONFIG) == 0
