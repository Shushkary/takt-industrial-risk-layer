from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


@dataclass(frozen=True, slots=True)
class IncidentAssemblySettings:
    """Настройка сборки инцидента: раздел `incident_assembly` в YAML.

    Читается и API, и воркером — режим должен быть одним и тем же с обеих сторон. Если API
    работает в `on_ingest`, а воркер запущен, он не увидит ни одного сигнала: приём их не
    оставляет.
    """

    mode: str = "on_ingest"
    distinctive_max_events: int = 12
    hits_between_runs: int = 1
    worker_poll_sec: float = 2.0

    @property
    def assembles_on_ingest(self) -> bool:
        return self.mode == "on_ingest"

    @property
    def defers_to_worker(self) -> bool:
        return self.mode == "worker"


_ASSEMBLY_MODES = frozenset({"on_ingest", "worker", "off"})


def incident_assembly_settings(weights: Mapping[str, Any]) -> IncidentAssemblySettings:
    """Разбирает `incident_assembly`; неизвестный режим — ошибка, а не тихий откат.

    Опечатка в режиме означала бы сборку не там, где её ждут: при `worker` инцидент собирает
    отдельный процесс, при откате на умолчание — процесс API, и разница видна только по
    задержке приёма.
    """
    raw = weights.get("incident_assembly")
    cfg: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    mode = str(cfg.get("mode", "on_ingest")).strip().lower()
    if mode not in _ASSEMBLY_MODES:
        raise ValueError(
            f"incident_assembly.mode must be one of {', '.join(sorted(_ASSEMBLY_MODES))}, not {mode!r}"
        )
    return IncidentAssemblySettings(
        mode=mode,
        distinctive_max_events=int(cfg.get("distinctive_max_events", 12)),
        hits_between_runs=int(cfg.get("hits_between_runs", 1)),
        worker_poll_sec=float(cfg.get("worker_poll_sec", 2.0)),
    )


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
