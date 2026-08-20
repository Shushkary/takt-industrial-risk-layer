"""Конвертер внешних цепочек атак: инварианты формата и разметки.

Проверяется то, что должно быть верно независимо от конкретного датасета: время в ISO 8601
UTC, сортировка по времени, разметка фазы по интервалам атак авторов корпуса, отсутствие
сырых строк журнала в результате. Отдельно закреплено, что техника ATT&CK не подставляется
там, где метка её не задаёт.

Входные образцы синтетические и написаны в формате AIT-ADS: сами данные корпуса в
репозиторий не вносятся.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scripts.import_external_chains import (
    ATTACK_TO_PHASE,
    DETECTOR_TO_SOURCE,
    convert,
    load_windows,
    window_for,
    write_fixture,
)

_FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "pt_techlab" / "ext_001"

# Интервалы совпадают по смыслу с labels.csv датасета: сценарий, тип атаки, начало и конец.
_LABELS = [
    ("shaw", "network_scans", 1643467020.0, 1643467117.0),
    ("shaw", "webshell", 1643467180.0, 1643467201.0),
    ("shaw", "reverse_shell", 1643469610.0, 1643469650.0),
    ("other", "dnsteal", 1643404082.0, 1643407682.0),
]


@pytest.fixture()
def labels(tmp_path: Path) -> Path:
    path = tmp_path / "labels.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["scenario", "attack", "start", "end"])
        writer.writerows(_LABELS)
    return path


def _wazuh(tmp_path: Path, moments: list[float]) -> Path:
    path = tmp_path / "scenario_wazuh.json"
    with path.open("w", encoding="utf-8") as stream:
        for index, moment in enumerate(moments):
            record = {
                "@timestamp": f"{_iso(moment)}",
                "agent": {"ip": "10.70.33.128"},
                "predecoder": {"hostname": "mail"},
                "rule": {"description": "Web server 400 error code."},
                "full_log": "секретная строка журнала, которой не место в фикстуре",
                "id": str(index),
            }
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def _aminer(tmp_path: Path, moments: list[float]) -> Path:
    path = tmp_path / "scenario_aminer.json"
    with path.open("w", encoding="utf-8") as stream:
        for moment in moments:
            record = {
                "AnalysisComponent": {"AnalysisComponentName": "AMiner: New event type."},
                "LogData": {"Timestamps": [moment], "RawLogData": ["сырая строка"]},
                "AMiner": {"ID": "10.38.242.230"},
            }
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def _iso(moment: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(moment, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_windows_are_scenario_scoped(labels: Path) -> None:
    windows = load_windows(labels, "shaw")
    assert [item.attack for item in windows] == ["network_scans", "webshell", "reverse_shell"]
    with pytest.raises(LookupError):
        load_windows(labels, "нет-такого-сценария")


def test_moment_outside_any_window_has_no_phase(labels: Path) -> None:
    windows = load_windows(labels, "shaw")
    starts = [item.start for item in windows]
    assert window_for(windows, starts, 1643467050.0).attack == "network_scans"
    assert window_for(windows, starts, 1643467150.0) is None
    assert window_for(windows, starts, 1.0) is None


def test_phase_comes_from_labels_not_from_alert_text(tmp_path: Path, labels: Path) -> None:
    """Одинаковые по тексту алерты получают разные фазы — по времени, а не по содержанию."""
    inside_scan = 1643467050.0
    inside_webshell = 1643467190.0
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, [inside_scan, inside_webshell])},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    phases = [row[-2] for row in rows["edr"]]
    assert phases == ["recon", "initial_access"]


def test_unlabelled_alerts_are_background(tmp_path: Path, labels: Path) -> None:
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, [1643467150.0])},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    row = rows["edr"][0]
    assert row[-2] == ""
    assert row[-3] == "BACKGROUND"


def test_only_labelled_drops_background(tmp_path: Path, labels: Path) -> None:
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, [1643467050.0, 1643467150.0])},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
        only_labelled=True,
    )
    assert len(rows["edr"]) == 1


def test_timestamps_are_iso_utc_and_sorted(tmp_path: Path, labels: Path) -> None:
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, [1643467190.0, 1643467050.0, 1643467060.0])},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    stamps = [row[0] for row in rows["edr"]]
    assert stamps == sorted(stamps)
    assert all(stamp.endswith("Z") and stamp[10] == "T" for stamp in stamps)


def test_raw_log_lines_are_not_carried_over(tmp_path: Path, labels: Path) -> None:
    """Сырые строки журнала остаются в исходном датасете, а не в репозитории."""
    rows = convert(
        sources={
            "wazuh": _wazuh(tmp_path, [1643467050.0]),
            "aminer": _aminer(tmp_path, [1643467050.0]),
        },
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    flat = " ".join(value for items in rows.values() for row in items for value in row)
    assert "секретная строка" not in flat
    assert "сырая строка" not in flat


def test_detectors_map_to_source_classes(tmp_path: Path, labels: Path) -> None:
    rows = convert(
        sources={
            "wazuh": _wazuh(tmp_path, [1643467050.0]),
            "aminer": _aminer(tmp_path, [1643467055.0]),
        },
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    assert len(rows[DETECTOR_TO_SOURCE["wazuh"]]) == 1
    assert len(rows[DETECTOR_TO_SOURCE["aminer"]]) == 1


def test_limit_per_phase_keeps_every_phase(tmp_path: Path, labels: Path) -> None:
    """Ограничение по фазе сохраняет представленность цепочки, а не обрезает её конец."""
    moments = [1643467050.0] * 5 + [1643467190.0] * 5
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, moments)},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
        only_labelled=True,
        limit_per_phase=2,
    )
    phases = sorted({row[-2] for row in rows["edr"]})
    assert phases == ["initial_access", "recon"]
    assert len(rows["edr"]) == 4


def test_technique_is_empty_where_label_does_not_define_it() -> None:
    """Метка называет цель шага, а не механизм — идентификатор ATT&CK не выдумывается."""
    assert ATTACK_TO_PHASE["reverse_shell"] == ("c2", "")
    assert ATTACK_TO_PHASE["privilege_escalation"] == ("privilege_escalation", "")
    assert ATTACK_TO_PHASE["service_stop"] == ("impact", "T1489")


def test_written_fixture_matches_the_inc002_contract(tmp_path: Path, labels: Path) -> None:
    """Заголовки совпадают с INC-002: конвертированный сценарий читают те же импортёры."""
    rows = convert(
        sources={"wazuh": _wazuh(tmp_path, [1643467050.0])},
        labels_path=labels,
        scenario="shaw",
        incident_id="EXT-001",
    )
    out = tmp_path / "ext"
    write_fixture(rows, out)
    written = list(csv.reader((out / "edr.csv").open(encoding="utf-8")))
    reference = list(
        csv.reader(
            (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "pt_techlab" / "inc_002" / "edr.csv").open(
                encoding="utf-8"
            )
        )
    )
    assert written[0] == reference[0]


# --- Поставляемая фикстура -------------------------------------------------


@pytest.mark.parametrize("name", ["edr.csv", "siem.csv", "README_EXT-001.md"])
def test_shipped_fixture_files_exist(name: str) -> None:
    assert (_FIXTURE / name).is_file(), name


def test_shipped_fixture_is_labelled_and_sorted() -> None:
    for name, column in (("edr.csv", "timestamp"), ("siem.csv", "event_time")):
        rows = list(csv.DictReader((_FIXTURE / name).open(encoding="utf-8")))
        assert rows, name
        assert all(row["attack_phase"] for row in rows), f"{name}: есть события без фазы"
        stamps = [row[column] for row in rows]
        assert stamps == sorted(stamps), f"{name}: нарушен порядок времени"
        assert all(stamp.endswith("Z") for stamp in stamps), f"{name}: время не в UTC"


def test_shipped_fixture_readme_states_licence_and_citation() -> None:
    text = (_FIXTURE / "README_EXT-001.md").read_text(encoding="utf-8")
    assert "CC-BY-4.0" in text
    assert "Landauer" in text
    assert "8263181" in text
    assert "сокращённая выборка" in text
