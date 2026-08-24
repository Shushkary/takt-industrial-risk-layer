from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.infrastructure.stores.memory import InMemoryCaseStore, InMemoryExpectedBehavior
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore, SqliteExpectedBehavior


def _project_local_path(path: Path, *, project_root: Path, label: str) -> Path:
    root = project_root.resolve()
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under project root: {root}") from exc
    return resolved


def topology_from_weights(weights: Mapping[str, Any]) -> tuple[str, frozenset[str]]:
    """Эталон jump-хост и множество ПЛК/критических узлов для детектора обхода."""
    top = weights.get("topology")
    if not isinstance(top, dict):
        return "jump-01", frozenset({"plc-01", "plc-02"})
    jump = str(top.get("jump_host") or "jump-01")
    raw = top.get("plc_hosts")
    if isinstance(raw, list) and raw:
        return jump, frozenset(str(x) for x in raw)
    return jump, frozenset({"plc-01", "plc-02"})


def enrichment_from_weights(weights: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Секция enrichment из YAML; None — не обогащать."""
    e = weights.get("enrichment")
    if not isinstance(e, dict):
        return None
    return e


def siem_webhook_retries(weights: Mapping[str, Any]) -> tuple[int, float]:
    sw = weights.get("siem_webhook")
    if not isinstance(sw, dict):
        return 3, 0.35
    return int(sw.get("retries", 3)), float(sw.get("backoff_sec", 0.35))


def trust_by_source_from_weights(weights: Mapping[str, Any]) -> dict[str, float] | None:
    """
    Карта доверия по `EventSource.value` для DQ (см. `evaluate_source_reputation`).
    Секция YAML: `ingest_trust.by_source` (ключи: plc_polling, auth_logs, …).
    """
    raw = weights.get("ingest_trust")
    if not isinstance(raw, dict):
        return None
    inner = raw.get("by_source")
    if not isinstance(inner, dict) or not inner:
        return None
    out: dict[str, float] = {}
    for k, v in inner.items():
        key = str(k).strip()
        if not key:
            continue
        try:
            out[key] = float(v)
        except (TypeError, ValueError):
            continue
    return out if out else None


def graph_edges_from_weights(
    weights: Mapping[str, Any],
    *,
    plc_hosts: frozenset[str],
) -> list[GraphEdge]:
    """Рёбра из topology.demo_graph_edges или одно демо-ребро к первому ПЛК."""
    top = weights.get("topology")
    if isinstance(top, dict):
        raw = top.get("demo_graph_edges")
        if isinstance(raw, list) and raw:
            out: list[GraphEdge] = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                src = str(item.get("src", "")).strip()
                dst = str(item.get("dst", "")).strip()
                kind = str(item.get("kind", "tcp")).strip() or "tcp"
                if src and dst:
                    out.append(GraphEdge(src=src, dst=dst, kind=kind))
            if out:
                return out
    plcs = sorted(plc_hosts)
    demo_dst = plcs[0] if plcs else "plc-01"
    return [GraphEdge(src="eng-workstation", dst=demo_dst, kind="ssh")]


def apply_storage_env_overrides(weights: dict[str, Any]) -> None:
    """
    Переменная **TAKT_STORAGE**: `memory` | `sqlite` — переопределяет `storage.backend` из YAML
    (удобно для Docker без правки файла).
    """
    mode = os.environ.get("TAKT_STORAGE", "").strip().lower()
    if not mode:
        return
    if mode not in ("memory", "sqlite"):
        raw = os.environ.get("TAKT_STORAGE", "")
        raise ValueError(f"TAKT_STORAGE must be 'memory' or 'sqlite', not {raw!r}")
    current = weights.get("storage")
    if isinstance(current, dict):
        weights["storage"] = {**current, "backend": mode}
    else:
        weights["storage"] = {"backend": mode, "sqlite_path": "data/takt_cases.db"}


RISK_SCALES = ("industrial", "soc")


def apply_risk_scale(weights: dict[str, Any]) -> None:
    """Выбирает шкалу классов риска по контуру: `risk_scale` в YAML или **TAKT_RISK_SCALE**.

    Расчёт балла для обоих контуров один и тот же — меняются только пороги классов. Причина
    в том, что достижимый максимум шкалы равен 0.800: вектор качества данных и множитель
    качества связаны обратно, поэтому вес 0.20 не «обналичивается». Пороги 0.65/0.85 назначены
    как доли от 1.0, и в SOC-контуре, где промышленные векторы не поднимаются срабатываниями,
    это оставляло классы «высокий» и «критический» практически недостижимыми.

    Выбранная шкала подставляется в `risk_class_thresholds`, поэтому дальше по коду ничего не
    меняется: и оценка события, и сборка инцидента читают один и тот же ключ.
    """
    scale = (os.environ.get("TAKT_RISK_SCALE", "") or str(weights.get("risk_scale", "industrial"))).strip().lower()
    if scale not in RISK_SCALES:
        raise ValueError(f"risk scale must be one of {', '.join(RISK_SCALES)}, not {scale!r}")
    if scale == "industrial":
        return
    thresholds = weights.get("risk_class_thresholds_soc")
    if not isinstance(thresholds, dict):
        raise ValueError("risk_scale: soc требует секцию risk_class_thresholds_soc в конфигурации")
    weights["risk_class_thresholds"] = dict(thresholds)


def sqlite_storage_db_path(weights: Mapping[str, Any], *, project_root: Path) -> Path | None:
    """Путь к файлу SQLite при `storage.backend: sqlite`; иначе None."""
    raw = weights.get("storage")
    if not isinstance(raw, dict):
        return None
    backend = str(raw.get("backend", "memory")).strip().lower()
    if backend != "sqlite":
        return None
    env_override = os.environ.get("TAKT_SQLITE_PATH", "").strip()
    if env_override:
        raw_path = Path(env_override)
    else:
        path_raw = raw.get("sqlite_path")
        rel = Path(str(path_raw).strip() if path_raw else "data/takt_cases.db")
        raw_path = rel if rel.is_absolute() else (project_root / rel)
    path = _project_local_path(raw_path, project_root=project_root, label="TAKT_SQLITE_PATH/storage.sqlite_path")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def case_repository_from_weights(weights: Mapping[str, Any], *, project_root: Path) -> CaseRepositoryPort:
    """Хранилище кейсов: `memory` (по умолчанию) или `sqlite` (файл под project_root)."""
    path = sqlite_storage_db_path(weights, project_root=project_root)
    if path is None:
        return InMemoryCaseStore()
    return SqliteCaseStore(path)


def expected_behavior_from_weights(weights: Mapping[str, Any], *, project_root: Path) -> ExpectedBehaviorPort:
    """Baseline EXPECTED_BEHAVIOR: в памяти или в том же SQLite-файле, что и кейсы."""
    path = sqlite_storage_db_path(weights, project_root=project_root)
    if path is None:
        return InMemoryExpectedBehavior()
    return SqliteExpectedBehavior(path)
