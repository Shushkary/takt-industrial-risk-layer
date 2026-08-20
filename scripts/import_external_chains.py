"""Конвертер внешних многошаговых цепочек атак в формат фикстур ТАКТ.

Зачем. Демонстрационный сценарий INC-002 синтетический и написан под задачу. Чтобы проверять
разбор на чужих данных, нужен внешний корпус с размеченными многошаговыми атаками. Сырые
датасеты в репозиторий не вносятся — велики по объёму и живут по собственным лицензиям;
здесь только конвертер и результат конвертации одного сценария.

Источник: **AIT Alert Data Set (AIT-ADS)** — алерты AMiner, Wazuh и Suricata на сценариях
AIT Log Data Set V2.0. Данные опубликованы на Zenodo (запись 8263181) под лицензией
**CC-BY-4.0**, то есть производные допустимы при указании авторства. Скрипты генерации в
репозитории `ait-aecid/alert-data-set` распространяются под GPL-3.0 и здесь не
используются: конвертер читает готовый CSV и написан с нуля.

Цитирование обязательно: Landauer, M., Skopik, F., Wurzenberger, M. (2024). Introducing a
New Alert Data Set for Multi-Step Attack Analysis. CSET 2024.

Формат входа. В опубликованном на Zenodo архиве нет каталога `alerts_csv` из README: он
собирается их скриптами локально. Архив содержит выгрузки детекторов построчным JSON —
`<сценарий>_wazuh.json` и `<сценарий>_aminer.json`. Конвертер читает именно их:

- Wazuh: `@timestamp` (ISO 8601), `agent.ip`, `predecoder.hostname`, `rule.description`;
- AMiner: `LogData.Timestamps[0]` (epoch), `AnalysisComponent.AnalysisComponentName`,
  `AMiner.ID` (адрес).

Suricata в этой записи Zenodo отсутствует, поэтому классов источников на выходе два.

Фаза шага определяется не по тексту алерта, а по временным интервалам атак из `labels.csv`
того же датасета — то есть по разметке авторов корпуса, а не по нашей догадке. Алерт вне
интервала атаки фазы не получает.

В фикстуру переносятся только время, узел, адрес и имя правила детектора. Поле `full_log`
Wazuh с сырой строкой журнала не переносится: в нём произвольное содержимое, и его место —
в исходном датасете, а не в репозитории.

BOTS v3 (`splunk/botsv3`, CC0-1.0) в MVP не конвертируется: датасет распространяется как
предындексированный Splunk, и корректное извлечение требует запуска Splunk. Заготовка
сопоставления описана в `docs/pt_techlab/simulation.md`.

Запуск:

    python -m scripts.import_external_chains \\
        --alerts <путь>/alerts_csv/fox_alerts.txt \\
        --labels <путь>/labels.csv \\
        --scenario fox \\
        --out tests/fixtures/pt_techlab/ext_001
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from bisect import bisect_right
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# Сопоставление типов атак AIT с фазами цепочки и техниками ATT&CK.
#
# Техника указывается только там, где метка задаёт её однозначно. Для `reverse_shell` и
# `privilege_escalation` метка называет цель шага, а не механизм, поэтому техника остаётся
# пустой: выдумывать идентификатор ATT&CK по догадке нельзя — он попадёт в отчёты и в сверку
# покрытия детектирования.
ATTACK_TO_PHASE: dict[str, tuple[str, str]] = {
    "network_scans": ("recon", "T1046"),
    "service_scans": ("recon", "T1046"),
    "dirb": ("recon", "T1595.003"),
    "wpscan": ("recon", "T1595.002"),
    "webshell": ("initial_access", "T1505.003"),
    "cracking": ("privilege_escalation", "T1110.002"),
    "reverse_shell": ("c2", ""),
    "privilege_escalation": ("privilege_escalation", ""),
    "service_stop": ("impact", "T1489"),
    "dnsteal": ("exfiltration", "T1048.003"),
}

# Класс источника ТАКТ подбирается по природе свидетельства: Wazuh — агент на узле,
# AMiner — разбор журналов, то есть корреляционное правило.
DETECTOR_TO_SOURCE: dict[str, str] = {"wazuh": "edr", "aminer": "siem"}

# Заголовки совпадают с фикстурой INC-002, чтобы конвертированный сценарий читался теми же
# импортёрами без отдельной ветки кода.
HEADERS: dict[str, list[str]] = {
    "edr": [
        "timestamp", "event_id", "hostname", "username", "process_guid",
        "parent_process_guid", "remote_ip", "sha256", "image_path", "event_type",
        "incident_id", "attack_phase", "mitre_technique",
    ],
    "siem": [
        "event_time", "record_id", "device_host", "subject_user", "src_ip", "dst_ip",
        "rule_name", "indicator_type", "indicator", "incident_id", "attack_phase",
        "mitre_technique",
    ],
    "ndr": [
        "start_time", "flow_id", "src_host", "src_ip", "dst_ip", "app_protocol",
        "verdict", "dns_query", "bytes", "incident_id", "attack_phase", "mitre_technique",
    ],
}


@dataclass(frozen=True, slots=True)
class AttackWindow:
    """Интервал атаки из разметки авторов корпуса."""

    attack: str
    start: float
    end: float


def load_windows(labels_path: Path, scenario: str) -> list[AttackWindow]:
    """Интервалы атак выбранного сценария, отсортированные по началу."""
    with labels_path.open(encoding="utf-8-sig", newline="") as stream:
        rows = [row for row in csv.DictReader(stream) if row.get("scenario") == scenario]
    if not rows:
        raise LookupError(f"в разметке нет сценария {scenario!r}")
    windows = [
        AttackWindow(attack=row["attack"].strip(), start=float(row["start"]), end=float(row["end"]))
        for row in rows
    ]
    return sorted(windows, key=lambda item: item.start)


def window_for(windows: list[AttackWindow], starts: list[float], moment: float) -> AttackWindow | None:
    """Интервал, в который попадает момент времени, или None."""
    index = bisect_right(starts, moment) - 1
    if index < 0:
        return None
    candidate = windows[index]
    return candidate if candidate.start <= moment <= candidate.end else None


def _operation(name: str) -> str:
    """Имя правила детектора в виде операции: без префикса продукта и в верхнем регистре."""
    text = name.split(":", 1)[1] if ":" in name else name
    cleaned = "".join(char if char.isalnum() else "_" for char in text.strip())
    return "_".join(part for part in cleaned.split("_") if part).upper()[:80] or "ALERT"


def _iso(moment: float) -> str:
    """Момент в ISO 8601 UTC — единый формат времени всех фикстур."""
    return datetime.fromtimestamp(moment, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _wazuh_alert(record: dict) -> tuple[float, str, str, str] | None:
    """Момент, узел, адрес и правило из записи Wazuh."""
    raw = str(record.get("@timestamp") or "").strip()
    if not raw:
        return None
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    host = str((record.get("predecoder") or {}).get("hostname") or "").strip()
    address = str((record.get("agent") or {}).get("ip") or "").strip()
    rule = str((record.get("rule") or {}).get("description") or "").strip()
    return moment, host, address, rule


def _aminer_alert(record: dict) -> tuple[float, str, str, str] | None:
    """Момент, узел, адрес и правило из записи AMiner."""
    stamps = (record.get("LogData") or {}).get("Timestamps") or []
    if not stamps:
        return None
    try:
        moment = float(stamps[0])
    except (TypeError, ValueError):
        return None
    address = str((record.get("AMiner") or {}).get("ID") or "").strip()
    component = record.get("AnalysisComponent") or {}
    rule = str(component.get("AnalysisComponentName") or component.get("Message") or "").strip()
    # У AMiner узел в отдельном поле не приходит: адрес идентифицирует источник записи.
    return moment, address, address, rule


_READERS = {"wazuh": _wazuh_alert, "aminer": _aminer_alert}


def read_alerts(path: Path, detector: str):
    """Построчный JSON детектора: по одной записи в строке."""
    reader = _READERS[detector]
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            parsed = reader(record)
            if parsed is not None:
                yield parsed


def convert(
    *,
    sources: dict[str, Path],
    labels_path: Path,
    scenario: str,
    incident_id: str,
    limit_per_source: int | None = None,
    limit_per_phase: int | None = None,
    only_labelled: bool = False,
) -> dict[str, list[list[str]]]:
    """Раскладывает алерты детекторов по классам источников ТАКТ.

    `only_labelled` оставляет лишь шаги внутри интервалов атак. Он нужен, чтобы фикстура
    оставалась обозримой: в исходном корпусе на один шаг атаки приходятся десятки тысяч
    фоновых алертов, и полный перенос сделал бы файл нечитаемым и бесполезным для проверки.

    `limit_per_phase` ограничивает выборку по каждой фазе, а не по источнику. Ограничение по
    источнику обрезает хронологию по порядку файла и оставляет ранние фазы, теряя поздние;
    ограничение по фазе сохраняет представленность всей цепочки. Это сокращение выборки,
    и оно указано в README фикстуры.
    """
    windows = load_windows(labels_path, scenario)
    starts = [window.start for window in windows]
    rows: dict[str, list[list[str]]] = {"edr": [], "siem": [], "ndr": []}
    counters = {"edr": 0, "siem": 0, "ndr": 0}
    per_phase: dict[tuple[str, str], int] = {}

    for detector, path in sources.items():
        source = DETECTOR_TO_SOURCE[detector]
        for moment, host, address, rule in read_alerts(path, detector):
            window = window_for(windows, starts, moment)
            phase, technique = ATTACK_TO_PHASE.get(window.attack, ("", "")) if window else ("", "")
            if only_labelled and not phase:
                continue
            if limit_per_source is not None and counters[source] >= limit_per_source:
                continue
            if limit_per_phase is not None:
                key = (source, phase)
                if per_phase.get(key, 0) >= limit_per_phase:
                    continue
                per_phase[key] = per_phase.get(key, 0) + 1

            counters[source] += 1
            event_id = f"{source}-{counters[source]:04d}"
            timestamp = _iso(moment)
            operation = _operation(rule)
            label = incident_id if phase else "BACKGROUND"

            if source == "edr":
                rows[source].append(
                    [timestamp, event_id, host, "", "", "", address, "", "", operation,
                     label, phase, technique]
                )
            else:
                rows[source].append(
                    [timestamp, event_id, host, "", address, "", operation, "host", host,
                     label, phase, technique]
                )

    for source in rows:
        rows[source].sort(key=lambda row: (row[0], row[1]))
    return rows


def write_fixture(rows: dict[str, list[list[str]]], out_dir: Path) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, int] = {}
    for source, items in rows.items():
        path = out_dir / f"{source}.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(HEADERS[source])
            writer.writerows(items)
        written[source] = len(items)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Конвертация внешней цепочки атак в фикстуру ТАКТ")
    parser.add_argument("--wazuh", type=Path, default=None, help="<сценарий>_wazuh.json")
    parser.add_argument("--aminer", type=Path, default=None, help="<сценарий>_aminer.json")
    parser.add_argument("--labels", type=Path, required=True, help="labels.csv из того же датасета")
    parser.add_argument("--scenario", required=True, help="имя сценария, например shaw")
    parser.add_argument("--out", type=Path, default=Path("tests/fixtures/pt_techlab/ext_001"))
    parser.add_argument("--incident-id", default="EXT-001")
    parser.add_argument("--limit-per-source", type=int, default=None)
    parser.add_argument(
        "--limit-per-phase",
        type=int,
        default=None,
        help="не более N событий на фазу и источник — сохраняет представленность всей цепочки",
    )
    parser.add_argument(
        "--only-labelled",
        action="store_true",
        help="оставить только шаги внутри интервалов атак — иначе фикстура утонет в фоне",
    )
    args = parser.parse_args()

    sources = {name: path for name, path in (("wazuh", args.wazuh), ("aminer", args.aminer)) if path}
    if not sources:
        print("error: укажи хотя бы один источник: --wazuh или --aminer", file=sys.stderr)
        return 2
    for path in (*sources.values(), args.labels):
        if not path.is_file():
            print(f"error: файл не найден: {path}", file=sys.stderr)
            return 2

    try:
        rows = convert(
            sources=sources,
            labels_path=args.labels,
            scenario=args.scenario,
            incident_id=args.incident_id,
            limit_per_source=args.limit_per_source,
            limit_per_phase=args.limit_per_phase,
            only_labelled=args.only_labelled,
        )
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    written = write_fixture(rows, args.out)
    phased = sum(1 for items in rows.values() for row in items if row[-2])
    print(
        "converted scenario=%s total=%d phased=%d edr=%d siem=%d ndr=%d out=%s"
        % (args.scenario, sum(written.values()), phased, written["edr"], written["siem"],
           written["ndr"], args.out)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
