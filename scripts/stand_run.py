#!/usr/bin/env python3
"""
Прогон стенда «два источника»: загрузка двух CSV-потоков в общий SQLite,
проверки через HTTP-контракт и отчёт для отладки.

Что делает:

1. фиксирует окружение стенда (`TAKT_CONFIG`, `TAKT_STORAGE=sqlite`, `TAKT_SQLITE_PATH`);
2. читает оба CSV мапперами `soc_csv.py` и подаёт события **в хронологическом слиянии**
   (как приходят два независимых фида), а не файл за файлом;
3. снимает метрики через тот же HTTP API, которым пользуется АРМ (`TestClient`);
4. сверяет фактическую группировку по кейсам с `ground_truth.json`
   (pairwise precision/recall) и считает покрытие правил корреляции по источникам;
5. пишет `report.json` и `report.md`.

Usage:
    python scripts/stand_run.py --reset
    python scripts/stand_run.py --dataset data/stand/dataset --report data/stand/report
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_DATASET = ROOT / "data" / "stand" / "dataset"
DEFAULT_DB = ROOT / "data" / "stand" / "takt.db"
DEFAULT_REPORT = ROOT / "data" / "stand" / "report"
DEFAULT_CONFIG = ROOT / "deploy" / "stand" / "risk_weights.stand.yaml"


def prepare_environment(*, config: Path, db_path: Path) -> None:
    """Переменные окружения стенда; читаются `create_app()` в момент вызова."""
    os.environ["TAKT_CONFIG"] = str(config)
    os.environ["TAKT_STORAGE"] = "sqlite"
    os.environ["TAKT_SQLITE_PATH"] = str(db_path)
    os.environ.setdefault("TAKT_PROFILE", "dev")
    os.environ.setdefault("TAKT_AUTH_REQUIRED", "0")
    os.environ.setdefault("TAKT_LOG_LEVEL", "WARNING")


def _merged_stream(dataset: Path, pair: tuple[str, str], trust_by_source: dict[str, float]) -> Iterator[object]:
    """Слияние двух источников по observed_at (ленивое, без материализации набора)."""
    from takt.infrastructure.importers.soc_csv import CsvEventSourceReader, map_edr, map_ndr, map_ot, map_siem

    mappers = {"edr": map_edr, "siem": map_siem, "ndr": map_ndr, "ot": map_ot}
    streams = [
        CsvEventSourceReader(dataset / f"{source}.csv", mappers[source],
                             ingest_trust=float(trust_by_source.get(source, 1.0)))
        for source in pair
    ]
    return heapq.merge(*streams, key=lambda event: event.observed_at)


def load_sources(app, dataset: Path, pair: tuple[str, str]) -> dict[str, object]:
    trust_by_source = dict(getattr(app.state, "trust_by_source", None) or {})
    processed: Counter[str] = Counter()
    failed: list[dict[str, str]] = []
    started = time.perf_counter()
    for event in _merged_stream(dataset, pair, trust_by_source):
        try:
            app.state.ingest_facade.assess_normalized_event(event, trust_by_source=trust_by_source)
            processed[event.source.value] += 1
        except Exception as exc:  # отдельная строка не должна ронять поток
            failed.append({"event_id": event.event_id, "source": event.source.value, "reason": str(exc)})
    elapsed = max(time.perf_counter() - started, 1e-9)
    total = sum(processed.values())
    return {
        "processed_by_source": dict(processed),
        "processed_total": total,
        "failed_total": len(failed),
        "failed_sample": failed[:10],
        "elapsed_sec": round(elapsed, 3),
        "events_per_sec": round(total / elapsed, 1),
        "ingest_trust_by_source": {source: trust_by_source.get(source) for source in pair},
    }


def _all_cases(client) -> list[dict]:
    cases: list[dict] = []
    offset = 0
    while True:
        page = client.get("/cases", params={"offset": offset, "limit": 200}).json()
        cases.extend(page)
        if len(page) < 200:
            return cases
        offset += 200


def _all_events(client) -> list[dict]:
    events: list[dict] = []
    offset = 0
    while True:
        page = client.get("/events/search", params={"offset": offset, "limit": 1000}).json()
        events.extend(page)
        if len(page) < 1000:
            return events
        offset += 1000


def rule_coverage(events: list[dict], config_path: Path) -> dict[str, object]:
    """Сколько событий каждого источника вообще получают отпечаток по каждому правилу."""
    import yaml

    from takt.domain.engines.alert_fatigue import correlation_rules_from_config

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    correlation = raw.get("correlation") if isinstance(raw, dict) else None
    mode = str((correlation or {}).get("mode", "legacy")).strip().lower()
    rules = correlation_rules_from_config(correlation or {})

    by_source: Counter[str] = Counter(event["source"] for event in events)
    coverage: list[dict[str, object]] = []
    for rule in rules:
        hits: Counter[str] = Counter()
        for event in events:
            entities = event.get("entities") or {}
            artifacts = {item["type"]: item["value"] for item in event.get("artifacts") or []}
            values = [
                artifacts.get(field.split(":", 1)[1]) if field.startswith("artifact:") else entities.get(field)
                for field in rule.fields
            ]
            if all(value for value in values):
                hits[event["source"]] += 1
        coverage.append({
            "rule": rule.name,
            "fields": list(rule.fields),
            "bucket_sec": rule.bucket_sec,
            "covered_by_source": {source: hits.get(source, 0) for source in sorted(by_source)},
            "blind_sources": sorted(source for source in by_source if not hits.get(source)),
        })
    return {"mode": mode, "generalized_enabled": mode != "legacy", "rules": coverage}


def _split_reason(members: list[str], events_by_id: dict[str, dict], bucket_sec: int = 600) -> str:
    """Почему события одного инцидента разъехались по разным кейсам."""
    hosts, buckets = set(), set()
    for event_id in members:
        event = events_by_id.get(event_id)
        if event is None:
            continue
        hosts.add(((event.get("entities") or {}).get("host_id")) or "—")
        moment = datetime.fromisoformat(event["observed_at"])
        buckets.add(int(moment.timestamp()) // bucket_sec)
    reasons = []
    if len(hosts) > 1:
        reasons.append(f"разные host_id ({', '.join(sorted(hosts))}) — правило host_window не связывает")
    if len(buckets) > 1:
        reasons.append(f"события попали в разные окна bucket_sec={bucket_sec} (границу окна пересекает цепочка)")
    return "; ".join(reasons) or "нет общего значения ни по одному правилу корреляции"


def correlation_metrics(cases: list[dict], client, ground_truth: dict,
                        events_by_id: dict[str, dict]) -> dict[str, object]:
    from takt.domain.engines.correlation_quality import pairwise_correlation_metrics

    expected: dict[str, str] = dict(ground_truth.get("events") or {})
    source_by_event: dict[str, str] = dict(ground_truth.get("source_by_event") or {})

    predicted: dict[str, str] = {}
    events_by_case: dict[str, list[str]] = {}
    for summary in cases:
        case_id = summary["case_id"]
        detail = client.get(f"/cases/{case_id}").json()
        event_ids = list(detail.get("event_ids") or [])
        events_by_case[case_id] = event_ids
        for event_id in event_ids:
            predicted[event_id] = case_id

    # Индивидуальные события без кейса считаем собственной группой, иначе
    # recall завышается за счёт «невидимых» пар.
    for event_id in expected:
        predicted.setdefault(event_id, f"__unassigned__{event_id}")

    metrics = pairwise_correlation_metrics(expected, predicted)

    cross_source_cases = []
    for case_id, event_ids in events_by_case.items():
        sources = sorted({source_by_event[event_id] for event_id in event_ids if event_id in source_by_event})
        if len(sources) > 1:
            incidents = sorted({expected.get(event_id, "?") for event_id in event_ids})
            cross_source_cases.append({
                "case_id": case_id, "sources": sources, "event_count": len(event_ids),
                "incidents": incidents, "pure": len(incidents) == 1 and incidents[0].startswith("INC-"),
            })

    incident_recovery = []
    for incident in ground_truth.get("incidents") or []:
        incident_id = str(incident["incident_id"])
        members = [event_id for event_id in incident.get("event_ids") or [] if event_id in predicted]
        groups = sorted({predicted[event_id] for event_id in members})
        recovered_sources = sorted({source_by_event.get(event_id, "?") for event_id in members})
        incident_recovery.append({
            "incident_id": incident_id, "pivot_host": incident.get("pivot_host"),
            "events": len(members), "case_groups": len(groups), "sources": recovered_sources,
            "fully_merged": len(groups) == 1,
            "split_reason": "" if len(groups) == 1 else _split_reason(members, events_by_id),
        })

    return {
        "pairwise": {
            "true_positive": metrics.true_positive,
            "false_positive": metrics.false_positive,
            "false_negative": metrics.false_negative,
            "precision": round(metrics.precision, 4),
            "recall": round(metrics.recall, 4),
        },
        "cross_source_cases": sorted(cross_source_cases, key=lambda item: item["case_id"]),
        "cross_source_case_count": len(cross_source_cases),
        "incident_recovery": incident_recovery,
        "incidents_fully_merged": sum(1 for item in incident_recovery if item["fully_merged"]),
    }


def collect_report(client, *, dataset: Path, pair: tuple[str, str], ingest: dict,
                   ground_truth: dict, config_path: Path) -> dict[str, object]:
    health = client.get("/health").json()
    stats = client.get("/cases/stats").json()
    data_quality = client.get("/data-quality").json()
    events = _all_events(client)
    cases = _all_cases(client)

    invariants: Counter[str] = Counter()
    risk_classes: Counter[str] = Counter()
    for summary in cases:
        risk_classes[summary["risk_class"]] += 1
    for summary in sorted(cases, key=lambda item: -item["risk_score"])[:50]:
        detail = client.get(f"/cases/{summary['case_id']}").json()
        invariants.update(detail.get("invariant_hits") or [])

    top_case = max(cases, key=lambda item: item["risk_score"], default=None)
    attack_chain = None
    if top_case is not None:
        response = client.get(f"/cases/{top_case['case_id']}/attack-chain")
        if response.status_code == 200:
            attack_chain = response.json()

    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "stand": {
            "pair": list(pair),
            "dataset": str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT) else str(dataset),
            "config": str(config_path.relative_to(ROOT)) if config_path.is_relative_to(ROOT) else str(config_path),
            "build_revision": health.get("build_revision"),
            "version": health.get("version"),
        },
        "ingest": ingest,
        "store": {
            "events_total": len(events),
            "events_by_source": dict(Counter(event["source"] for event in events)),
            "cases_total": stats.get("total"),
            "cases_by_risk_class": dict(risk_classes),
            "avg_risk_score": round(float(stats.get("avg_risk_score") or 0.0), 4),
            "avg_dq_score": round(float(stats.get("avg_dq_score") or 0.0), 4),
            "dq_partial_count": stats.get("dq_partial_count"),
            "distinct_invariant_hits": stats.get("distinct_invariant_hits"),
        },
        "invariant_hits_top": dict(invariants.most_common(15)),
        "data_quality": data_quality,
        "correlation": correlation_metrics(cases, client, ground_truth,
                                           {event["event_id"]: event for event in events}),
        "rule_coverage": rule_coverage(events, config_path),
        "attack_chain_sample": attack_chain,
    }


def render_markdown(report: dict) -> str:
    stand = report["stand"]
    ingest = report["ingest"]
    store = report["store"]
    correlation = report["correlation"]
    coverage = report["rule_coverage"]
    pairwise = correlation["pairwise"]

    lines = [
        "# Отчёт стенда «два источника»",
        "",
        f"Сгенерировано `scripts/stand_run.py` {report['generated_at']}.",
        "",
        f"- пара источников: **{' + '.join(stand['pair'])}**",
        f"- датасет: `{stand['dataset']}`",
        f"- конфиг: `{stand['config']}`",
        f"- режим корреляции: **{coverage['mode']}** "
        f"({'обобщённый коррелятор включён' if coverage['generalized_enabled'] else 'ОБОБЩЁННЫЙ КОРРЕЛЯТОР ОТКЛЮЧЁН'})",
        "",
        "## Загрузка",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| Принято событий | {ingest['processed_total']} |",
        f"| По источникам | {ingest['processed_by_source']} |",
        f"| Отказов | {ingest['failed_total']} |",
        f"| Время загрузки, с | {ingest['elapsed_sec']} |",
        f"| Пропускная способность, соб./с | {ingest['events_per_sec']} |",
        f"| ingest_trust | {ingest['ingest_trust_by_source']} |",
        "",
        "## Состояние хранилища",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| Событий в поиске | {store['events_total']} {store['events_by_source']} |",
        f"| Кейсов | {store['cases_total']} |",
        f"| Классы риска | {store['cases_by_risk_class']} |",
        f"| Средний риск | {store['avg_risk_score']} |",
        f"| Средний DQ | {store['avg_dq_score']} (частичных: {store['dq_partial_count']}) |",
        f"| Уникальных инвариантов | {store['distinct_invariant_hits']} |",
        "",
        "## Корреляция против ground truth",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| pairwise precision | {pairwise['precision']} |",
        f"| pairwise recall | {pairwise['recall']} |",
        f"| TP / FP / FN | {pairwise['true_positive']} / {pairwise['false_positive']} / {pairwise['false_negative']} |",
        f"| Кейсов с двумя источниками | {correlation['cross_source_case_count']} |",
        f"| Инцидентов собрано в один кейс | {correlation['incidents_fully_merged']} из {len(correlation['incident_recovery'])} |",
        "",
        "Фон в ground truth размечен как отдельная группа на каждое событие: связывание двух",
        "не связанных событий одного узла считается false positive.",
        "",
        "### Восстановление инцидентов",
        "",
        "| incident_id | пивот | событий | групп-кейсов | источники | собран | почему разъехался |",
        "|---|---|---:|---:|---|---|---|",
    ]
    for item in correlation["incident_recovery"]:
        lines.append(
            f"| `{item['incident_id']}` | {item['pivot_host']} | {item['events']} | {item['case_groups']} | "
            f"{', '.join(item['sources'])} | {'да' if item['fully_merged'] else 'нет'} | "
            f"{item.get('split_reason') or '—'} |"
        )

    lines += [
        "",
        "## Покрытие правил корреляции",
        "",
        "Показывает, какие источники в принципе не могут дать отпечаток по правилу — "
        "главная причина несобранных цепочек.",
        "",
        "| правило | поля | окно, с | покрытие по источникам | слепые источники |",
        "|---|---|---:|---|---|",
    ]
    for rule in coverage["rules"]:
        blind = ", ".join(rule["blind_sources"]) or "—"
        lines.append(
            f"| `{rule['rule']}` | {', '.join(rule['fields'])} | {rule['bucket_sec'] or '—'} | "
            f"{rule['covered_by_source']} | {blind} |"
        )

    if report["invariant_hits_top"]:
        lines += ["", "## Топ инвариантов", "", "| invariant_id | срабатываний |", "|---|---:|"]
        for name, count in report["invariant_hits_top"].items():
            lines.append(f"| `{name}` | {count} |")

    if ingest["failed_sample"]:
        lines += ["", "## Отказы загрузки (первые записи)", "", "| event_id | источник | причина |", "|---|---|---|"]
        for item in ingest["failed_sample"]:
            lines.append(f"| `{item['event_id']}` | {item['source']} | {item['reason']} |")

    lines.append("")
    return "\n".join(lines)


def run(*, dataset: Path, db_path: Path, report_dir: Path, config: Path, reset: bool) -> int:
    ground_truth_path = dataset / "ground_truth.json"
    if not ground_truth_path.is_file():
        print(f"error: нет {ground_truth_path}; сначала запустите scripts/stand_dataset.py", file=sys.stderr)
        return 2
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    pair = tuple(ground_truth.get("pair") or ())
    if len(pair) != 2:
        print("error: ground_truth.json без корректного поля pair", file=sys.stderr)
        return 2
    missing = [source for source in pair if not (dataset / f"{source}.csv").is_file()]
    if missing:
        print(f"error: в датасете нет CSV для: {', '.join(missing)}", file=sys.stderr)
        return 2
    if not config.is_file():
        print(f"error: нет конфига стенда {config}", file=sys.stderr)
        return 2

    if reset:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()

    prepare_environment(config=config, db_path=db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    app = create_app()
    ingest = load_sources(app, dataset, pair)  # type: ignore[arg-type]
    for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
        close = getattr(getattr(app.state, attr, None), "close", None)
        if callable(close):
            close()

    with TestClient(create_app()) as client:
        report = collect_report(client, dataset=dataset, pair=pair, ingest=ingest,  # type: ignore[arg-type]
                                ground_truth=ground_truth, config_path=config)

    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (report_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")

    pairwise = report["correlation"]["pairwise"]
    print(
        f"stand complete pair={','.join(pair)} events={ingest['processed_total']} "
        f"failed={ingest['failed_total']} cases={report['store']['cases_total']} "
        f"precision={pairwise['precision']} recall={pairwise['recall']} "
        f"cross_source_cases={report['correlation']['cross_source_case_count']}"
    )
    print(f"report {report_dir / 'report.md'}")
    return 0 if ingest["failed_total"] == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Прогон стенда двух источников ТАКТ")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--reset", action="store_true", help="удалить БД стенда перед загрузкой")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return run(dataset=args.dataset, db_path=args.db, report_dir=args.report,
               config=args.config, reset=args.reset)


if __name__ == "__main__":
    raise SystemExit(main())
