from __future__ import annotations

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


def test_dataset_is_deterministic_and_matches_contract(work_dir: Path) -> None:
    dataset = _load("stand_dataset.py")
    out = work_dir / "dataset"

    assert dataset.main(["--pair", "edr,ot", "--incidents", "2", "--noise", "10",
                         "--seed", "11", "--out", str(out)]) == 0
    first = (out / "edr.csv").read_text(encoding="utf-8")

    assert dataset.main(["--pair", "edr,ot", "--incidents", "2", "--noise", "10",
                         "--seed", "11", "--out", str(out)]) == 0
    assert (out / "edr.csv").read_text(encoding="utf-8") == first, "один seed обязан давать один датасет"

    header = first.splitlines()[0].split(",")
    assert header == list(dataset.HEADERS["edr"])

    ground_truth = json.loads((out / "ground_truth.json").read_text(encoding="utf-8"))
    assert ground_truth["pair"] == ["edr", "ot"]
    assert len(ground_truth["incidents"]) == 2
    # каждая цепочка наблюдается обоими источниками
    for incident in ground_truth["incidents"]:
        sources = {ground_truth["source_by_event"][event_id] for event_id in incident["event_ids"]}
        assert sources == {"edr", "ot"}
    # фон размечен поштучно, иначе pairwise-метрика не увидит ложных слияний
    background = [value for value in ground_truth["events"].values() if not value.startswith("INC-")]
    assert len(set(background)) == len(background)


def test_dataset_rejects_bad_pair() -> None:
    dataset = _load("stand_dataset.py")
    import argparse

    for bad in ("edr", "edr,edr", "edr,syslog"):
        with pytest.raises(argparse.ArgumentTypeError):
            dataset.parse_pair(bad)


def test_stand_run_produces_report_with_cross_source_case(work_dir: Path) -> None:
    dataset_script = _load("stand_dataset.py")
    runner = _load("stand_run.py")
    dataset_dir = work_dir / "dataset"
    report_dir = work_dir / "report"

    assert dataset_script.main(["--pair", "edr,ot", "--incidents", "3", "--noise", "20",
                                "--seed", "5", "--out", str(dataset_dir)]) == 0

    rc = runner.run(dataset=dataset_dir, db_path=work_dir / "takt.db", report_dir=report_dir,
                    config=ROOT / "deploy" / "stand" / "risk_weights.stand.yaml", reset=True)
    assert rc == 0

    assert (report_dir / "report.md").is_file()
    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))

    ground_truth = json.loads((dataset_dir / "ground_truth.json").read_text(encoding="utf-8"))
    expected_total = sum(ground_truth["counts"].values())
    assert report["ingest"]["processed_total"] == expected_total
    assert report["ingest"]["failed_total"] == 0
    assert report["store"]["events_total"] == expected_total
    assert set(report["store"]["events_by_source"]) == {"edr", "ot"}

    # обобщённый коррелятор включён конфигом стенда и действительно связывает домены
    assert report["rule_coverage"]["generalized_enabled"] is True
    assert report["correlation"]["cross_source_case_count"] >= 1

    # map_ot переносит operator_id в user_id, поэтому OT участвует в user_destination;
    # артефакта hash у OT нет и не должно быть — file_hash для него слеп by design
    blind = {rule["rule"]: rule["blind_sources"] for rule in report["rule_coverage"]["rules"]}
    assert blind["host_window"] == []
    assert blind["user_destination"] == []
    assert blind["file_hash"] == ["ot"]

    # несобранные цепочки обязаны нести объяснение, иначе отчёт бесполезен для отладки
    for item in report["correlation"]["incident_recovery"]:
        if not item["fully_merged"]:
            assert item["split_reason"]


def test_stand_run_on_production_config_has_no_cross_source_correlation(work_dir: Path) -> None:
    """Страховка от регресса документации: при mode=legacy корреляция источников молча выключена."""
    dataset_script = _load("stand_dataset.py")
    runner = _load("stand_run.py")
    dataset_dir = work_dir / "dataset"

    assert dataset_script.main(["--pair", "edr,ot", "--incidents", "2", "--noise", "10",
                                "--seed", "3", "--out", str(dataset_dir)]) == 0

    rc = runner.run(dataset=dataset_dir, db_path=work_dir / "legacy.db",
                    report_dir=work_dir / "legacy-report",
                    config=ROOT / "config" / "risk_weights.yaml", reset=True)
    assert rc == 0

    report = json.loads((work_dir / "legacy-report" / "report.json").read_text(encoding="utf-8"))
    assert report["rule_coverage"]["mode"] == "legacy"
    assert report["rule_coverage"]["generalized_enabled"] is False
    assert report["correlation"]["cross_source_case_count"] == 0
