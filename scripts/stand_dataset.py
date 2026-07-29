#!/usr/bin/env python3
"""
Генератор датасета стенда «два источника» с размеченной истиной (ground truth).

Формирует по одному CSV на каждый класс источника в формате
`docs/pt_techlab/data_contract.md` и файл `ground_truth.json`
(event_id → incident_id), по которому `scripts/stand_run.py` считает
pairwise precision/recall корреляции.

Модель стенда:

* фон (`BACKGROUND-*`) — независимые события каждого источника: рабочие станции,
  штатный опрос PLC, разрешённый DNS, успешные правила SIEM;
* инцидент (`INC-<n>`) — цепочка, наблюдаемая обоими источниками на **общем узле-пивоте**
  (инженерная станция / АРМ), укладывающаяся в окно правила `host_window` (600 с).

Связок между IT и OT две: общий `host_id` узла-пивота (правило `host_window`) и пара
«оператор + адрес назначения» (правило `user_destination`) — OT-строки несут колонку
`operator_id` из контракта. Что из этого реально сработало, видно в `rule_coverage`
отчёта; стенд показывает разрывы, а не маскирует их.

Usage:
    python scripts/stand_dataset.py --pair edr,ot --incidents 6 --noise 300 --seed 7
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCES = ("edr", "siem", "ndr", "ot")

HEADERS: dict[str, tuple[str, ...]] = {
    "edr": ("timestamp", "event_id", "hostname", "username", "process_guid", "parent_process_guid",
            "remote_ip", "sha256", "image_path", "event_type", "incident_id"),
    "siem": ("event_time", "record_id", "device_host", "subject_user", "src_ip", "dst_ip",
             "rule_name", "indicator_type", "indicator", "incident_id"),
    "ndr": ("start_time", "flow_id", "src_host", "src_ip", "dst_ip", "app_protocol", "verdict",
            "dns_query", "bytes", "incident_id"),
    "ot": ("timestamp", "event_id", "asset_id", "operator_id", "src_address", "dst_address",
           "protocol", "operation", "tag", "payload_size", "incident_id"),
}

# Узлы-пивоты: наблюдаются и IT-, и OT-источником (АРМ инженера, HMI шкафа).
PIVOT_HOSTS = ("ews-01", "hmi-01", "ews-02")
WORKSTATIONS = tuple(f"ws-{index:02d}" for index in range(1, 13))
PLC_HOSTS = ("plc-01", "plc-02", "plc-03")
USERS = ("ivanov", "petrova", "sidorov", "svc_backup", "operator1")
OT_TAGS = ("boiler.pressure", "boiler.level", "pump.speed", "valve.position", "turbine.rpm")
BENIGN_DOMAINS = ("intranet.local", "update.corp.local", "ntp.corp.local")
C2_DOMAINS = ("evil.example", "cdn-sync.example", "metrics-agent.example")

BASE_TIME = datetime(2026, 6, 1, 8, 0, 0, tzinfo=UTC)


def _ts(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


class Row(dict):
    """CSV-строка одного источника плюс её класс."""

    def __init__(self, source: str, **fields: object) -> None:
        super().__init__(**{key: str(value) for key, value in fields.items()})
        self.source = source

    @property
    def incident_id(self) -> str:
        return self["incident_id"]

    @property
    def event_id(self) -> str:
        for key in ("event_id", "record_id", "flow_id"):
            if key in self:
                return self[key]
        raise KeyError("row has no identifier column")


# --- фон -------------------------------------------------------------------


def _noise_edr(rng: random.Random, index: int, moment: datetime) -> Row:
    host = rng.choice(WORKSTATIONS)
    user = rng.choice(USERS)
    return Row("edr",
               timestamp=_ts(moment), event_id=f"edr-bg-{index:05d}", hostname=host, username=user,
               process_guid=f"p-{rng.randrange(10**6):06d}", parent_process_guid=f"p-{rng.randrange(10**6):06d}",
               remote_ip=f"10.10.1.{rng.randrange(2, 250)}", sha256=_sha256(f"benign-{index}"),
               image_path=r"C:\Windows\System32\svchost.exe", event_type="PROCESS_START",
               incident_id="BACKGROUND")


def _noise_siem(rng: random.Random, index: int, moment: datetime) -> Row:
    host = rng.choice(WORKSTATIONS)
    return Row("siem",
               event_time=_ts(moment), record_id=f"siem-bg-{index:05d}", device_host=host,
               subject_user=rng.choice(USERS), src_ip=f"10.10.1.{rng.randrange(2, 250)}",
               dst_ip=f"10.10.1.{rng.randrange(2, 250)}", rule_name="BACKUP_SUCCESS",
               indicator_type="host", indicator=f"backup-{rng.randrange(1, 9):02d}",
               incident_id="BACKGROUND")


def _noise_ndr(rng: random.Random, index: int, moment: datetime) -> Row:
    host = rng.choice(WORKSTATIONS)
    return Row("ndr",
               start_time=_ts(moment), flow_id=f"ndr-bg-{index:05d}", src_host=host,
               src_ip=f"10.10.1.{rng.randrange(2, 250)}", dst_ip="10.10.1.53", app_protocol="DNS",
               verdict="ALLOWED", dns_query=rng.choice(BENIGN_DOMAINS), bytes=rng.randrange(64, 512),
               incident_id="BACKGROUND")


def _noise_ot(rng: random.Random, index: int, moment: datetime) -> Row:
    asset = rng.choice(PLC_HOSTS)
    return Row("ot",
               timestamp=_ts(moment), event_id=f"ot-bg-{index:05d}", asset_id=asset,
               operator_id=rng.choice(USERS),
               src_address=f"10.10.2.{rng.randrange(2, 40)}", dst_address=f"10.10.2.{rng.randrange(40, 90)}",
               protocol="IEC104", operation="POLL", tag=rng.choice(OT_TAGS),
               payload_size=rng.randrange(32, 96), incident_id="BACKGROUND")


NOISE: dict[str, Callable[[random.Random, int, datetime], Row]] = {
    "edr": _noise_edr, "siem": _noise_siem, "ndr": _noise_ndr, "ot": _noise_ot,
}


# --- цепочка инцидента -----------------------------------------------------


def _incident_rows(source: str, rng: random.Random, number: int, start: datetime,
                   pivot: str, plc: str, user: str, domain: str, malware_hash: str) -> list[Row]:
    """Наблюдения одного источника внутри одной цепочки (окно ~5 минут)."""
    incident = f"INC-{number:03d}"
    plc_ip = f"10.10.2.{20 + number % 40}"
    pivot_ip = f"10.10.1.{100 + number % 50}"

    if source == "edr":
        return [
            Row("edr", timestamp=_ts(start), event_id=f"edr-{incident}-1", hostname=pivot,
                username=user, process_guid=f"p-{number}01", parent_process_guid=f"p-{number}00",
                remote_ip="203.0.113.10", sha256=malware_hash, image_path=r"C:\Temp\update.exe",
                event_type="PROCESS_START", incident_id=incident),
            Row("edr", timestamp=_ts(start + timedelta(seconds=90)), event_id=f"edr-{incident}-2",
                hostname=pivot, username=user, process_guid=f"p-{number}02", parent_process_guid=f"p-{number}01",
                remote_ip=plc_ip, sha256=malware_hash, image_path=r"C:\Temp\iec-client.exe",
                event_type="NETWORK_CONNECT", incident_id=incident),
        ]
    if source == "siem":
        return [
            Row("siem", event_time=_ts(start + timedelta(seconds=30)), record_id=f"siem-{incident}-1",
                device_host=pivot, subject_user=user, src_ip=pivot_ip, dst_ip="203.0.113.10",
                rule_name="SUSPICIOUS_OUTBOUND", indicator_type="domain", indicator=domain,
                incident_id=incident),
            Row("siem", event_time=_ts(start + timedelta(seconds=150)), record_id=f"siem-{incident}-2",
                device_host=pivot, subject_user=user, src_ip=pivot_ip, dst_ip=plc_ip,
                rule_name="OT_PROTOCOL_FROM_WORKSTATION", indicator_type="address", indicator=plc_ip,
                incident_id=incident),
        ]
    if source == "ndr":
        return [
            Row("ndr", start_time=_ts(start + timedelta(seconds=20)), flow_id=f"ndr-{incident}-1",
                src_host=pivot, src_ip=pivot_ip, dst_ip="203.0.113.10", app_protocol="DNS",
                verdict="C2_SUSPECT", dns_query=domain, bytes=211, incident_id=incident),
            Row("ndr", start_time=_ts(start + timedelta(seconds=120)), flow_id=f"ndr-{incident}-2",
                src_host=pivot, src_ip=pivot_ip, dst_ip=plc_ip, app_protocol="IEC104",
                verdict="POLICY_VIOLATION", dns_query="", bytes=1840, incident_id=incident),
        ]
    # ot: команда в контур наблюдается ISIM на узле-пивоте (АРМ-источник команды)
    # и на самом PLC; вторая строка корреляционно «сирота» — это ожидаемый разрыв.
    return [
        Row("ot", timestamp=_ts(start + timedelta(seconds=210)), event_id=f"ot-{incident}-1",
            asset_id=pivot, operator_id=user, src_address=pivot_ip, dst_address=plc_ip, protocol="IEC104",
            operation="WRITE_SETPOINT", tag=rng.choice(OT_TAGS), payload_size=64, incident_id=incident),
        Row("ot", timestamp=_ts(start + timedelta(seconds=240)), event_id=f"ot-{incident}-2",
            asset_id=plc, operator_id=user, src_address=pivot_ip, dst_address=plc_ip, protocol="IEC104",
            operation="ADMIN_LOGIN", tag=rng.choice(OT_TAGS), payload_size=128, incident_id=incident),
    ]


def build_dataset(*, pair: tuple[str, str], incidents: int, noise: int, seed: int,
                  minutes: int) -> tuple[dict[str, list[Row]], dict[str, object]]:
    rng = random.Random(seed)
    rows: dict[str, list[Row]] = {source: [] for source in pair}

    span = timedelta(minutes=minutes)
    for index in range(noise):
        source = pair[index % len(pair)]
        moment = BASE_TIME + timedelta(seconds=rng.randrange(int(span.total_seconds())))
        rows[source].append(NOISE[source](rng, index, moment))

    incident_specs: list[dict[str, object]] = []
    for number in range(1, incidents + 1):
        start = BASE_TIME + timedelta(seconds=rng.randrange(int(span.total_seconds()) - 300))
        pivot = PIVOT_HOSTS[number % len(PIVOT_HOSTS)]
        plc = PLC_HOSTS[number % len(PLC_HOSTS)]
        user = USERS[number % len(USERS)]
        domain = C2_DOMAINS[number % len(C2_DOMAINS)]
        malware_hash = _sha256(f"dropper-{seed}-{number}")
        produced: list[str] = []
        for source in pair:
            chain = _incident_rows(source, rng, number, start, pivot, plc, user, domain, malware_hash)
            rows[source].extend(chain)
            produced.extend(row.event_id for row in chain)
        incident_specs.append({
            "incident_id": f"INC-{number:03d}", "pivot_host": pivot, "plc": plc, "user": user,
            "c2_domain": domain, "started_at": _ts(start), "event_ids": produced,
        })

    for source in pair:
        rows[source].sort(key=lambda row: row[HEADERS[row.source][0]])

    ground_truth = {
        "pair": list(pair),
        "seed": seed,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "counts": {source: len(rows[source]) for source in pair},
        "incidents": incident_specs,
        # Фон в CSV помечен одним литералом BACKGROUND ради читаемости, но для
        # pairwise-метрик каждое фоновое событие — отдельная группа: связывать их
        # между собой корреляция не обязана и не должна.
        "events": {
            row.event_id: (row.incident_id if row.incident_id.startswith("INC-") else f"BACKGROUND:{row.event_id}")
            for source in pair
            for row in rows[source]
        },
        "source_by_event": {row.event_id: source for source in pair for row in rows[source]},
    }
    return rows, ground_truth


def write_dataset(out_dir: Path, rows: dict[str, list[Row]], ground_truth: dict[str, object]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for source, items in rows.items():
        target = out_dir / f"{source}.csv"
        with target.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(HEADERS[source]))
            writer.writeheader()
            writer.writerows(items)
    (out_dir / "ground_truth.json").write_text(
        json.dumps(ground_truth, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_pair(raw: str) -> tuple[str, str]:
    parts = tuple(item.strip().lower() for item in raw.split(",") if item.strip())
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("--pair ожидает ровно два источника, например edr,ot")
    unknown = [item for item in parts if item not in SOURCES]
    if unknown:
        raise argparse.ArgumentTypeError(f"неизвестные источники: {', '.join(unknown)}; допустимы {', '.join(SOURCES)}")
    if parts[0] == parts[1]:
        raise argparse.ArgumentTypeError("источники в паре должны различаться")
    return parts  # type: ignore[return-value]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Датасет стенда двух источников с ground truth")
    parser.add_argument("--pair", type=parse_pair, default=("edr", "ot"),
                        help="пара классов источников, по умолчанию edr,ot")
    parser.add_argument("--incidents", type=int, default=6, help="число размеченных цепочек")
    parser.add_argument("--noise", type=int, default=300, help="число фоновых событий (делится между источниками)")
    parser.add_argument("--minutes", type=int, default=180, help="длительность окна наблюдения")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "stand" / "dataset")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if args.incidents < 0 or args.noise < 0:
        print("error: --incidents и --noise не могут быть отрицательными")
        return 2
    rows, ground_truth = build_dataset(pair=args.pair, incidents=args.incidents, noise=args.noise,
                                       seed=args.seed, minutes=args.minutes)
    write_dataset(args.out, rows, ground_truth)
    counts = ", ".join(f"{source}={len(items)}" for source, items in rows.items())
    print(f"dataset out={args.out} pair={','.join(args.pair)} incidents={args.incidents} {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
