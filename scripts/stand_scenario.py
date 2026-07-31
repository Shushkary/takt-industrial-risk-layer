#!/usr/bin/env python3
"""
Полная симуляция расследования на стенде по ТЗ «единый интеллектуальный интерфейс
ИБ-продуктов для расследования киберинцидентов» (Positive Technologies, 2026).

Прогоняет сквозной сценарий аналитика SOC на датасете из **четырёх классов
источников** (требование п. 4.1 и п. 12.1 ТЗ) и проверяет минимальный результат
MVP из п. 14: единое окно, автоматическая корреляция, контекст по узлу/пользователю/
процессу, фиксация находок и артефактов, пакет для реагирования, измеримое
сокращение ручных действий.

Каждый шаг сценария несёт две оценки трудоёмкости:

* **базовая линия** — сколько действий (запросов, переключений между консолями,
  ручных сопоставлений) стоит тот же результат в текущем процессе, где у каждого
  ИБ-продукта своя консоль и свой язык запросов;
* **ТАКТ** — фактическое число обращений к единому API.

ВАЖНО: базовая линия здесь **модельная** — она выведена из числа подключённых
классов источников, а не измерена на реальных аналитиках. ТЗ (п. 12) требует
фиксировать базовую линию с заказчиком; до этого цифра ускорения — оценка сверху
по методике, описанной в отчёте, а не подтверждённый результат.

Симуляция всегда стартует с чистой БД стенда (иначе решения и находки предыдущего
прогона делают проверку human-in-the-loop бессмысленной); `--keep-db` это отключает.

Usage:
    python scripts/stand_scenario.py
    python scripts/stand_scenario.py --dataset data/stand/dataset --report data/stand/report
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_DATASET = ROOT / "data" / "stand" / "dataset"
DEFAULT_DB = ROOT / "data" / "stand" / "takt.db"
DEFAULT_REPORT = ROOT / "data" / "stand" / "report"
DEFAULT_CONFIG = ROOT / "deploy" / "stand" / "risk_weights.stand.yaml"

REQUIRED_SOURCES = ("edr", "siem", "ndr", "ot")

# Модель базовой линии: во сколько действий обходится шаг, когда единого окна нет.
# switch — переключение между консолями продуктов, query — запрос на своём языке,
# manual — ручное сопоставление/выписывание в блокнот.
ACTION_COST = {"switch": 1, "query": 1, "manual": 1}


def _load_module(script: str):
    """Скрипты репозитория лежат плоско и не образуют пакет — грузим по пути."""
    path = ROOT / "scripts" / script
    spec = importlib.util.spec_from_file_location(f"stand_{path.stem}", path)
    if spec is None or spec.loader is None:  # pragma: no cover - защита от опечатки в имени
        raise RuntimeError(f"не удалось загрузить {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Ledger:
    """Счётчик шагов сценария и трудоёмкости против базовой линии."""

    def __init__(self) -> None:
        self.steps: list[dict[str, object]] = []

    def record(self, *, step: str, tz: str, takt_calls: int, baseline: dict[str, int],
               baseline_note: str, ok: bool, evidence: dict[str, object]) -> None:
        baseline_actions = sum(ACTION_COST[kind] * count for kind, count in baseline.items())
        self.steps.append({
            "step": step,
            "tz": tz,
            "takt_actions": takt_calls,
            "baseline_actions": baseline_actions,
            "baseline_breakdown": dict(baseline),
            "baseline_note": baseline_note,
            "saved_actions": baseline_actions - takt_calls,
            "ok": ok,
            "evidence": evidence,
        })

    def totals(self) -> dict[str, object]:
        baseline = sum(int(item["baseline_actions"]) for item in self.steps)
        takt = sum(int(item["takt_actions"]) for item in self.steps)
        reduction = (baseline - takt) / baseline if baseline else 0.0
        return {
            "baseline_actions": baseline,
            "takt_actions": takt,
            "saved_actions": baseline - takt,
            "reduction_ratio": round(reduction, 4),
            "target_ratio": 0.30,
            "target_met": reduction >= 0.30,
            "steps_ok": all(bool(item["ok"]) for item in self.steps),
        }


def _pick_incident_case(client, ground_truth: dict) -> tuple[str, dict]:
    """Кейс с максимальным числом классов источников — рабочий стол расследования."""
    source_by_event = dict(ground_truth.get("source_by_event") or {})
    best: tuple[int, str, dict] | None = None
    offset = 0
    while True:
        page = client.get("/cases", params={"offset": offset, "limit": 200}).json()
        for summary in page:
            detail = client.get(f"/cases/{summary['case_id']}").json()
            sources = {source_by_event.get(event_id) for event_id in detail.get("event_ids") or []}
            sources.discard(None)
            incidents = {
                ground_truth["events"].get(event_id, "")
                for event_id in detail.get("event_ids") or []
            }
            has_incident = any(item.startswith("INC-") for item in incidents)
            rank = len(sources) + (10 if has_incident else 0)
            if best is None or rank > best[0]:
                best = (rank, summary["case_id"], detail)
        if len(page) < 200:
            break
        offset += 200
    if best is None:
        raise RuntimeError("в хранилище нет кейсов — сначала загрузите датасет")
    return best[1], best[2]


def _incident_of_case(detail: dict, ground_truth: dict) -> str:
    for event_id in detail.get("event_ids") or []:
        incident = ground_truth["events"].get(event_id, "")
        if incident.startswith("INC-"):
            return incident
    return ""


def run_scenario(client, ground_truth: dict, sources: tuple[str, ...]) -> dict[str, object]:
    ledger = Ledger()
    source_count = len(sources)

    # Снимок до любых действий аналитика: система не имеет права сама переводить
    # кейс в решённый статус (ТЗ п. 6.3 — финальное решение принимает аналитик).
    statuses_after_ingest = dict(client.get("/cases/stats").json().get("by_status") or {})
    decided_before_analyst = sum(
        count for status, count in statuses_after_ingest.items()
        if status in {"CONFIRMED", "FALSE_POSITIVE", "EXPECTED_BEHAVIOR"}
    )

    # --- Шаг 1. Квалификация: одна очередь вместо очереди в каждой консоли -------
    queue = client.get("/cases", params={"limit": 50, "sort": "risk_score_desc"}).json()
    case_id, detail = _pick_incident_case(client, ground_truth)
    incident_id = _incident_of_case(detail, ground_truth)
    ledger.record(
        step="Квалификация: единая очередь инцидентов",
        tz="п. 5.1 единый рабочий стол; п. 12.1 единое окно",
        takt_calls=1,
        baseline={"query": source_count, "switch": source_count},
        baseline_note=f"очередь алертов просматривается в каждой из {source_count} консолей",
        ok=bool(queue),
        evidence={"cases_in_queue": len(queue), "picked_case": case_id, "ground_truth_incident": incident_id},
    )

    # --- Шаг 2. Единое окно: кейс, события, таймлайн, граф одним запросом --------
    workspace = client.get(f"/cases/{case_id}/workspace").json()
    ws_sources = sorted({event["source"] for event in workspace.get("events") or []})
    ledger.record(
        step="Единое окно расследования (события, таймлайн, граф)",
        tz="п. 5.1, 5.4 граф/таймлайн; п. 9.1 frontend",
        takt_calls=1,
        baseline={"query": source_count, "switch": source_count, "manual": 2},
        baseline_note="выгрузка из каждой консоли и ручная сборка таймлайна и графа связей",
        ok=len(ws_sources) >= 2 and bool(workspace.get("timeline")),
        evidence={
            "sources_in_case": ws_sources,
            "events": len(workspace.get("events") or []),
            "timeline_entries": len(workspace.get("timeline") or []),
            "graph_nodes": len((workspace.get("graph") or {}).get("nodes") or []),
            "graph_edges": len((workspace.get("graph") or {}).get("edges") or []),
        },
    )

    # --- Шаг 3. Контекст по узлу, пользователю и процессу ------------------------
    events = workspace.get("events") or []
    host_id = next((e["entities"]["host_id"] for e in events if (e.get("entities") or {}).get("host_id")), "")
    user_id = next((e["entities"]["user_id"] for e in events if (e.get("entities") or {}).get("user_id")), "")
    process_id = next((e["entities"]["process_id"] for e in events if (e.get("entities") or {}).get("process_id")), "")
    cards = {}
    for kind, value in (("host", host_id), ("user", user_id), ("process", process_id)):
        if not value:
            cards[kind] = None
            continue
        cards[kind] = client.get(f"/entities/{kind}/{value}/card").json()
    filled = [kind for kind, card in cards.items() if card]
    with_typicality = [kind for kind, card in cards.items() if card and card.get("typicality")]
    ledger.record(
        step="Контекст по сущностям: историчность и окружение",
        tz="п. 4.3 сбор контекста; п. 5.5 карточка сущности; п. 12.3 полнота контекста",
        takt_calls=len(filled),
        baseline={"query": source_count * 3, "switch": source_count * 3, "manual": 3},
        baseline_note=f"по каждой из 3 сущностей обход {source_count} систем и ручная сводка",
        ok=len(filled) >= 2 and len(with_typicality) == len(filled),
        evidence={
            "entities": {kind: (card or {}).get("id") for kind, card in cards.items()},
            "typicality": {kind: ((card or {}).get("typicality") or {}).get("status") for kind, card in cards.items()},
            "environment_totals": {kind: (card or {}).get("environment_total") for kind, card in cards.items()},
        },
    )

    # --- Шаг 4. Оценка распространения: поиск по артефактам во всех источниках ---
    artifacts = [item for event in events for item in event.get("artifacts") or []]
    hash_value = next((item["value"] for item in artifacts if item["type"] == "hash"), "")
    domain_value = next((item["value"] for item in artifacts if item["type"] == "domain"), "")
    spread: dict[str, object] = {}
    calls = 0
    for kind, value in (("hash", hash_value), ("domain", domain_value)):
        if not value:
            continue
        found = client.get("/events/search",
                           params={"artifact_type": kind, "artifact_value": value, "limit": 200}).json()
        calls += 1
        spread[kind] = {
            "value": value,
            "events": len(found),
            "hosts": sorted({(item.get("entities") or {}).get("host_id") for item in found if
                             (item.get("entities") or {}).get("host_id")}),
            "sources": sorted({item["source"] for item in found}),
        }
    ledger.record(
        step="Оценка распространения по артефактам (C2, хеш)",
        tz="п. 4.7 оценка распространения; п. 5.8 единый поиск",
        takt_calls=calls,
        baseline={"query": source_count * max(calls, 1), "switch": source_count, "manual": 1},
        baseline_note="поиск повторяется в каждой консоли на её языке запросов",
        ok=bool(spread),
        evidence=spread,
    )

    # --- Шаг 5. Обогащение артефакта (декодирование) ----------------------------
    decoded = client.post("/enrichment/decode", json={"value": domain_value or host_id or "dGVzdA=="}).json()
    ledger.record(
        step="Обогащение артефакта: декодирование в интерфейсе",
        tz="п. 4.4 обогащение; п. 5.7 обогащение артефактов",
        takt_calls=1,
        baseline={"switch": 1, "query": 1, "manual": 1},
        baseline_note="переход во внешний инструмент, копирование значения и обратно",
        ok=bool(decoded.get("decodings")),
        evidence={"input": decoded.get("input"), "decodings": len(decoded.get("decodings") or [])},
    )

    # --- Шаг 6. Ручная корректировка связей -------------------------------------
    # ТЗ п. 5.3 требует не только автокорреляции, но и ручной правки связей.
    # Берём событие цепочки, которое коррелятор не связал (типичный случай —
    # OT-событие, атрибутированное самому PLC).
    incident_events = [
        event_id for event_id, value in ground_truth["events"].items()
        if incident_id and value == incident_id
    ]
    attached = list(detail.get("event_ids") or [])
    orphan = next((event_id for event_id in sorted(incident_events) if event_id not in attached), "")
    if orphan:
        # Типовой случай: событие цепочки, которое коррелятор не связал автоматически.
        mode = "attach_orphan"
        result = client.post(f"/cases/{case_id}/events/attach",
                             json={"event_id": orphan, "reason": "аналитик подтвердил связь с цепочкой"})
        manual = result.json() if result.status_code == 200 else {}
        manual_ok = result.status_code == 200 and orphan in (manual.get("event_ids") or [])
        calls = 1
    elif attached:
        # Несвязанных событий не осталось — демонстрируем правку связи циклом
        # detach → attach на реальном событии, иначе шаг прошёл бы вхолостую.
        mode = "detach_attach_roundtrip"
        target = attached[-1]
        detached = client.post(f"/cases/{case_id}/events/{target}/detach",
                               json={"reason": "аналитик оспорил связь"})
        result = client.post(f"/cases/{case_id}/events/attach",
                             json={"event_id": target, "reason": "аналитик вернул связь"})
        manual = result.json() if result.status_code == 200 else {}
        manual_ok = (detached.status_code == 200 and result.status_code == 200
                     and target not in (detached.json().get("event_ids") or [])
                     and target in (manual.get("event_ids") or []))
        orphan = target
        calls = 2
    else:
        mode, manual, manual_ok, calls = "no_events", {}, False, 0
    ledger.record(
        step="Ручная корректировка связей (attach недостающего события)",
        tz="п. 5.3 корреляция с ручной корректировкой",
        takt_calls=calls,
        baseline={"manual": 2, "switch": 1},
        baseline_note="в текущем процессе связь фиксируется только в заметках аналитика",
        ok=manual_ok,
        evidence={"mode": mode, "event": orphan,
                  "events_after": len(manual.get("event_ids") or attached)},
    )

    # --- Шаг 7. Находки и артефакты, привязанные к инциденту --------------------
    finding_body = {
        "text": f"Подтверждена цепочка {incident_id or 'инцидента'}: запуск на АРМ, обращение к C2, "
                f"воздействие на технологический контур.",
        "event_ids": (detail.get("event_ids") or [])[:5],
        "artifacts": [item for item in (
            {"type": "hash", "value": hash_value, "host_id": host_id} if hash_value else None,
            {"type": "domain", "value": domain_value, "host_id": host_id} if domain_value else None,
            {"type": "host", "value": host_id, "host_id": host_id} if host_id else None,
        ) if item],
    }
    finding = client.post(f"/cases/{case_id}/findings", json=finding_body)
    findings = client.get(f"/cases/{case_id}/findings").json()
    ledger.record(
        step="Фиксация находки и артефактов в карточке инцидента",
        tz="п. 4.5 привязка находок; п. 5.6 журнал находок; п. 14 MVP",
        takt_calls=2,
        baseline={"switch": 1, "manual": 3},
        baseline_note="выписывание идентификаторов в блокнот или сторонний тикет",
        ok=finding.status_code == 200 and bool(findings),
        evidence={"status": finding.status_code, "findings_total": len(findings)},
    )

    # --- Шаг 8. Реконструкция цепочки атаки -------------------------------------
    chain = client.get(f"/cases/{case_id}/attack-chain").json()
    ledger.record(
        step="Реконструкция цепочки атаки (точка входа, шаги)",
        tz="п. 4.6 реконструкция цепочки",
        takt_calls=1,
        baseline={"query": source_count, "switch": source_count, "manual": 3},
        baseline_note="восстановление хронологии вручную по выгрузкам всех источников",
        ok=bool(chain.get("steps")),
        evidence={"entry_point": chain.get("entry_point"), "steps": len(chain.get("steps") or []),
                  "artifacts": len(chain.get("artifacts") or [])},
    )

    # --- Шаг 9. Пакет для реагирования ------------------------------------------
    case_artifacts = client.get(f"/cases/{case_id}/artifacts").json()
    typed = [item for item in (case_artifacts if isinstance(case_artifacts, list) else
                               case_artifacts.get("artifacts") or []) if item.get("type")]
    ledger.record(
        step="Подготовка пакета артефактов для реагирования",
        tz="п. 4.8 контекст для реагирования; п. 5.11 пакет реагирования; п. 14 MVP",
        takt_calls=1,
        baseline={"query": source_count, "switch": source_count, "manual": 3},
        baseline_note="сбор артефактов из каждой консоли и ручное оформление списка",
        ok=bool(typed),
        evidence={"artifacts": len(typed), "types": sorted({item["type"] for item in typed})},
    )

    # --- Шаг 10. Решение аналитика (human-in-the-loop) --------------------------
    before = client.get(f"/cases/{case_id}").json().get("status")
    decision = client.post(f"/cases/{case_id}/decision",
                           json={"status": "CONFIRMED", "reason": "цепочка подтверждена аналитиком"})
    after = client.get(f"/cases/{case_id}").json().get("status")
    ledger.record(
        step="Решение принимает аналитик (human-in-the-loop)",
        tz="п. 6.3 ограничения; п. 12.7 отсутствие автоматических критичных действий",
        takt_calls=1,
        baseline={"switch": 1, "manual": 2},
        baseline_note="решение фиксируется в отдельной системе учёта инцидентов",
        ok=(decided_before_analyst == 0 and before != "CONFIRMED"
            and after == "CONFIRMED" and decision.status_code == 200),
        evidence={
            "status_before": before, "status_after": after,
            "cases_decided_by_system_before_analyst": decided_before_analyst,
            "case_statuses_after_ingest": statuses_after_ingest,
        },
    )

    # --- Шаг 11. Отчёт по инциденту ---------------------------------------------
    siem_export = client.get(f"/cases/{case_id}/export/siem.json")
    ledger.record(
        step="Экспорт описания инцидента и результатов",
        tz="п. 4.10 описание инцидента; п. 5.12 отчёт; п. 9.2 экспорт",
        takt_calls=1,
        baseline={"manual": 4},
        baseline_note="итоговое описание собирается по памяти и записям",
        ok=siem_export.status_code == 200,
        evidence={"status": siem_export.status_code,
                  "payload_keys": sorted(siem_export.json().keys()) if siem_export.status_code == 200 else []},
    )

    # --- Шаг 12. Журнал действий: целостность ------------------------------------
    ledger_verify = client.get(f"/cases/{case_id}/audit-ledger/verify")
    verified = ledger_verify.json() if ledger_verify.status_code == 200 else {}
    ledger.record(
        step="Журнал действий аналитика и системы (проверка целостности)",
        tz="п. 5.14 журнал действий; п. 7.7 безопасность; п. 12.7 управляемость",
        takt_calls=1,
        baseline={"manual": 2},
        baseline_note="аудит собирается вручную из журналов каждой системы",
        ok=ledger_verify.status_code == 200 and bool(verified.get("ok", verified.get("valid", True))),
        evidence=verified if isinstance(verified, dict) else {},
    )

    return {
        "case_id": case_id,
        "incident_id": incident_id,
        "steps": ledger.steps,
        "totals": ledger.totals(),
    }


def check_rbac() -> dict[str, object]:
    """
    Отдельная проверка ролей ТЗ п. 5.13: аналитик 1-й и 2-й линии, руководитель,
    администратор. Требует включённой аутентификации, поэтому поднимается свой
    экземпляр приложения с ключами.
    """
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    keys = {
        "manager": "k-manager", "analyst_l1": "k-l1",
        "analyst_l2": "k-l2", "admin": "k-admin",
    }
    saved = {name: os.environ.get(name) for name in ("TAKT_API_KEYS", "TAKT_AUTH_REQUIRED", "TAKT_PROFILE")}
    os.environ["TAKT_API_KEYS"] = ",".join(f"{key}:{role}-actor:{role}" for role, key in keys.items())
    os.environ["TAKT_AUTH_REQUIRED"] = "1"
    os.environ.pop("TAKT_PROFILE", None)
    try:
        with TestClient(create_app()) as client:
            case_id = client.get("/cases", params={"limit": 1},
                                 headers={"X-Takt-Api-Key": keys["admin"]}).json()[0]["case_id"]

            def call(role: str | None, method: str, path: str, **kwargs):
                headers = {"X-Takt-Api-Key": keys[role]} if role else {}
                return getattr(client, method)(path, headers=headers, **kwargs)

            # Несуществующий source_case_id: авторизованные роли получат 404, а не выполнят слияние.
            merge_body = {"source_case_id": "no-such-case", "reason": "проверка прав"}
            checks = {
                "no_key_rejected": call(None, "get", f"/cases/{case_id}").status_code in (401, 403),
                "manager_can_read": call("manager", "get", f"/cases/{case_id}").status_code == 200,
                "manager_cannot_write": call("manager", "post", f"/cases/{case_id}/findings",
                                             json={"text": "нет прав"}).status_code == 403,
                "analyst_l1_can_add_finding": call("analyst_l1", "post", f"/cases/{case_id}/findings",
                                                   json={"text": "находка первой линии"}).status_code == 200,
                "analyst_l1_cannot_merge": call("analyst_l1", "post", f"/cases/{case_id}/merge",
                                                json=merge_body).status_code == 403,
                "analyst_l2_can_merge_route": call("analyst_l2", "post", f"/cases/{case_id}/merge",
                                                   json=merge_body).status_code != 403,
                "admin_can_import": call("admin", "post", "/cases/import/full.json",
                                         json={"cases": []}).status_code != 403,
                "analyst_l2_cannot_import": call("analyst_l2", "post", "/cases/import/full.json",
                                                 json={"cases": []}).status_code == 403,
            }
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return {"checks": checks, "ok": all(checks.values())}


def mvp_checklist(scenario: dict, rbac: dict, sources: tuple[str, ...]) -> list[dict[str, object]]:
    """Минимальный результат MVP из п. 14 ТЗ и чем он подтверждён в прогоне."""
    by_step = {str(item["step"]): item for item in scenario["steps"]}

    def step_ok(prefix: str) -> bool:
        return any(bool(item["ok"]) for name, item in by_step.items() if name.startswith(prefix))

    def evidence(prefix: str, key: str = "") -> str:
        for name, item in by_step.items():
            if not name.startswith(prefix):
                continue
            data = item.get("evidence") or {}
            value = data.get(key) if key else data
            return ", ".join(f"{k}={v}" for k, v in value.items()) if isinstance(value, dict) else str(value)
        return "нет данных"

    sources_in_case = (by_step.get("Единое окно расследования (события, таймлайн, граф)", {})
                       .get("evidence") or {}).get("sources_in_case") or []
    totals = scenario["totals"]
    return [
        {"requirement": "единое окно с данными не менее чем из четырёх классов источников",
         "tz": "п. 14, п. 12.1",
         "ok": len(sources) >= 4 and len(sources_in_case) >= 4,
         "evidence": f"источников в датасете: {len(sources)}, в одном кейсе: {len(sources_in_case)} "
                     f"({', '.join(sources_in_case)})"},
        {"requirement": "автоматическая корреляция и группировка связанных событий",
         "tz": "п. 14, п. 5.3", "ok": step_ok("Единое окно"),
         "evidence": f"событий в кейсе: {evidence('Единое окно', 'events')}"},
        {"requirement": "ручная корректировка связей аналитиком",
         "tz": "п. 5.3", "ok": step_ok("Ручная корректировка"),
         "evidence": evidence("Ручная корректировка")},
        {"requirement": "сбор контекста по узлу, пользователю и процессу",
         "tz": "п. 14, п. 4.3", "ok": step_ok("Контекст по сущностям"),
         "evidence": evidence("Контекст по сущностям", "typicality")},
        {"requirement": "фиксация находок и артефактов с привязкой к инциденту",
         "tz": "п. 14, п. 4.5", "ok": step_ok("Фиксация находки"),
         "evidence": evidence("Фиксация находки")},
        {"requirement": "подготовка пакета артефактов для реагирования",
         "tz": "п. 14, п. 4.8", "ok": step_ok("Подготовка пакета"),
         "evidence": evidence("Подготовка пакета")},
        {"requirement": "реконструкция цепочки атаки и оценка распространения",
         "tz": "п. 4.6, п. 4.7",
         "ok": step_ok("Реконструкция") and step_ok("Оценка распространения"),
         "evidence": evidence("Реконструкция")},
        {"requirement": "финальное решение принимает аналитик, критичные действия не автоматические",
         "tz": "п. 6.3, п. 12.7", "ok": step_ok("Решение принимает аналитик"),
         "evidence": evidence("Решение принимает аналитик")},
        {"requirement": "роли и права доступа (1-я линия, 2-я линия, руководитель, администратор)",
         "tz": "п. 5.13, п. 12.7", "ok": bool(rbac["ok"]),
         "evidence": ", ".join(f"{name}={'да' if value else 'НЕТ'}" for name, value in rbac["checks"].items())},
        {"requirement": "журналирование действий пользователя и системы",
         "tz": "п. 5.14, п. 7.7", "ok": step_ok("Журнал действий"),
         "evidence": evidence("Журнал действий")},
        {"requirement": "измеримое сокращение ручных действий (ориентир ≥ 30%)",
         "tz": "п. 14, п. 12.4", "ok": bool(totals["target_met"]),
         "evidence": f"{totals['baseline_actions']} → {totals['takt_actions']} действий, "
                     f"сокращение {totals['reduction_ratio']:.0%} (базовая линия модельная)"},
    ]


def render_markdown(report: dict) -> str:
    totals = report["scenario"]["totals"]
    lines = [
        "# Симуляция расследования по ТЗ (Positive Technologies, 2026)",
        "",
        f"Сгенерировано `scripts/stand_scenario.py` {report['generated_at']}.",
        "",
        f"- источники ({len(report['sources'])}): **{' + '.join(report['sources'])}**",
        f"- кейс расследования: `{report['scenario']['case_id']}` "
        f"(цепочка ground truth: `{report['scenario']['incident_id'] or 'н/д'}`)",
        f"- конфиг: `{report['config']}`",
        "",
        "## Минимальный результат MVP (п. 14 ТЗ)",
        "",
        "| Требование | Пункт ТЗ | Статус | Подтверждение |",
        "|---|---|---|---|",
    ]
    for item in report["mvp_checklist"]:
        status = "выполнено" if item["ok"] else "**НЕ ВЫПОЛНЕНО**"
        lines.append(f"| {item['requirement']} | {item['tz']} | {status} | {item['evidence']} |")

    lines += [
        "",
        "## Шаги сценария и трудоёмкость",
        "",
        "| # | Шаг | Пункт ТЗ | Базовая линия | ТАКТ | Экономия | Статус |",
        "|---:|---|---|---:|---:|---:|---|",
    ]
    for index, step in enumerate(report["scenario"]["steps"], start=1):
        lines.append(
            f"| {index} | {step['step']} | {step['tz']} | {step['baseline_actions']} | "
            f"{step['takt_actions']} | {step['saved_actions']} | {'ок' if step['ok'] else '**сбой**'} |"
        )

    lines += [
        "",
        "### Как считается базовая линия",
        "",
        "| # | Шаг | Модель текущего процесса |",
        "|---:|---|---|",
    ]
    for index, step in enumerate(report["scenario"]["steps"], start=1):
        lines.append(f"| {index} | {step['step']} | {step['baseline_note']} ({step['baseline_breakdown']}) |")

    lines += [
        "",
        "## Итог по трудоёмкости",
        "",
        "| Метрика | Значение |",
        "|---|---:|",
        f"| Действий в текущем процессе (модель) | {totals['baseline_actions']} |",
        f"| Действий в едином окне ТАКТ | {totals['takt_actions']} |",
        f"| Сокращение | {totals['reduction_ratio']:.0%} |",
        f"| Ориентир ТЗ (п. 12.4) | {totals['target_ratio']:.0%} — "
        f"{'достигнут' if totals['target_met'] else 'НЕ достигнут'} |",
        "",
        "### Что именно посчитано",
        "",
        "* **Считается**: обращения к системам (запросы), переключения между консолями продуктов и шаги, "
        "которые в текущем процессе выполняются вручную (сведение таймлайна, выписывание артефактов).",
        "* **Не считается**: время чтения и анализа данных аналитиком — оно одинаково в обоих процессах; "
        "клики внутри одного интерфейса; время ответа систем.",
        "* Выбор демонстрационного кейса выполняется по разметке ground truth, чтобы прогон был "
        "воспроизводим. Служебные запросы выбора кейса в трудоёмкость не входят и не засчитываются "
        "ни одной из сторон.",
        "",
        "> **Оговорка о базовой линии.** Цифры текущего процесса — модельные: они выведены из числа "
        "подключённых классов источников (по запросу и переключению на каждую консоль) и из шагов, "
        "которые в текущем процессе выполняются вручную. ТЗ (п. 12) требует фиксировать базовую линию "
        "и методику измерения с заказчиком; до этого показатель — оценка сверху по описанной методике "
        "и **не является** подтверждённым замером на аналитиках. Показатель отражает сокращение "
        "переключений и обращений к системам, а не напрямую сокращение времени расследования.",
        "",
        "## Роли и права доступа (п. 5.13)",
        "",
        "| Проверка | Результат |",
        "|---|---|",
    ]
    for name, value in report["rbac"]["checks"].items():
        lines.append(f"| `{name}` | {'ок' if value else '**сбой**'} |")

    lines += [
        "",
        "## Ограничения симуляции",
        "",
        "* Датасет синтетический (`scripts/stand_dataset.py`), это не выгрузка заказчика.",
        "* Обогащение ограничено декодированием: подключение репутационных сервисов и песочницы "
        "по ТЗ (п. 6.2) допускается только по согласованию с заказчиком и требует внешних интеграций.",
        "* Ускорение измерено против модельной базовой линии, см. оговорку выше.",
        "",
    ]
    return "\n".join(lines)


def run(*, dataset: Path, db_path: Path, report_dir: Path, config: Path, keep_db: bool = False) -> int:
    stand_run = _load_module("stand_run.py")

    ground_truth_path = dataset / "ground_truth.json"
    if not ground_truth_path.is_file():
        print(f"error: нет {ground_truth_path}; сначала запустите scripts/stand_dataset.py", file=sys.stderr)
        return 2
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    sources = tuple(ground_truth.get("sources") or ground_truth.get("pair") or ())
    missing = [source for source in REQUIRED_SOURCES if source not in sources]
    if missing:
        print(f"error: ТЗ требует не менее четырёх классов источников; в датасете нет: {', '.join(missing)}. "
              f"Соберите датасет: python scripts/stand_dataset.py --sources {','.join(REQUIRED_SOURCES)}",
              file=sys.stderr)
        return 2

    if not keep_db:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()

    stand_run.prepare_environment(config=config, db_path=db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    if not keep_db or not db_path.exists():
        app = create_app()
        ingest = stand_run.load_sources(app, dataset, sources)
        for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
            close = getattr(getattr(app.state, attr, None), "close", None)
            if callable(close):
                close()
        print(f"загружено событий: {ingest['processed_total']}, отказов: {ingest['failed_total']}")
    else:
        ingest = {"processed_total": None, "failed_total": None, "note": "использована существующая БД стенда"}

    with TestClient(create_app()) as client:
        scenario = run_scenario(client, ground_truth, sources)

    rbac = check_rbac()

    report = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": list(sources),
        "config": str(config.relative_to(ROOT)) if config.is_relative_to(ROOT) else str(config),
        "dataset": str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT) else str(dataset),
        "ingest": ingest,
        "scenario": scenario,
        "rbac": rbac,
    }
    report["mvp_checklist"] = mvp_checklist(scenario, rbac, sources)

    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "scenario.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (report_dir / "scenario.md").write_text(render_markdown(report), encoding="utf-8")

    totals = scenario["totals"]
    failed = [item["requirement"] for item in report["mvp_checklist"] if not item["ok"]]
    print(
        f"scenario complete case={scenario['case_id']} steps_ok={totals['steps_ok']} "
        f"baseline={totals['baseline_actions']} takt={totals['takt_actions']} "
        f"reduction={totals['reduction_ratio']:.0%} target_met={totals['target_met']} "
        f"rbac_ok={rbac['ok']}"
    )
    print(f"report {report_dir / 'scenario.md'}")
    if failed:
        print("НЕ ВЫПОЛНЕНО: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Полная симуляция расследования на стенде ТАКТ по ТЗ")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--keep-db", action="store_true",
                        help="не перезаливать БД стенда (по умолчанию симуляция стартует с чистой базы)")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return run(dataset=args.dataset, db_path=args.db, report_dir=args.report,
               config=args.config, keep_db=args.keep_db)


if __name__ == "__main__":
    raise SystemExit(main())
