"""Инкрементальная корреляция событий: Union-Find (DSU) + TTL-окно.

Алгоритм полностью детерминирован (никакой рандомизации): при одинаковой
последовательности событий на входе возвращается один и тот же набор рёбер
корреляции. Связывание происходит по общим сущностям
(``host_id``, ``user_id``, ``process``, ``address``, ``artifact``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from takt.domain.soc.normalized_event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class CorrelationEdge:
    """Ребро корреляции между двумя событиями по общей сущности."""

    event_a_ref: str
    event_b_ref: str
    shared_entity: str
    correlation_reason: str


class _DSU:
    """Система непересекающихся множеств (Union-Find) со сжатием путей."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: str) -> str:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        # Сжатие путей — детерминированное, не влияет на результат групп.
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        self.add(a)
        self.add(b)
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        # Детерминированное правило слияния: меньший корень (лексикографически)
        # становится родителем — не зависит от порядка вызовов.
        parent, child = (ra, rb) if ra < rb else (rb, ra)
        self._parent[child] = parent

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for item in sorted(self._parent):
            out.setdefault(self.find(item), []).append(item)
        return out


class CorrelationEngine:
    """Инкрементальный корреляционный движок с TTL-окном.

    События старше ``ttl_seconds`` относительно времени последнего пришедшего
    события выпадают из корреляции (эвикция по ``event.ts``, а не по стенным часам —
    ради детерминизма и воспроизводимости на исторических выгрузках).
    """

    _ENTITY_ORDER = ("host_id", "user_id", "process", "address", "artifact")

    def __init__(self, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds должен быть положительным")
        self._ttl = timedelta(seconds=ttl_seconds)
        self._active: dict[str, NormalizedEvent] = {}
        self._index: dict[tuple[str, str], list[str]] = {}
        self._edges: list[tuple[str, str, str]] = []
        self._dsu = _DSU()
        self._latest_ts: datetime | None = None

    def ingest(self, event: NormalizedEvent) -> list[CorrelationEdge]:
        """Учесть событие и вернуть новые рёбра корреляции с активным окном."""
        ref = event.raw_ref
        # Повторный ref считаем дублем и не корре­лируем повторно (идемпотентность).
        if ref in self._active:
            return []

        self._latest_ts = event.ts if self._latest_ts is None else max(self._latest_ts, event.ts)
        self._evict(self._latest_ts)

        new_edges: list[CorrelationEdge] = []
        shared = event.shared_entities()
        # Детерминированный порядок обхода сущностей.
        for key in self._ENTITY_ORDER:
            value = shared.get(key)
            if not value:
                continue
            index_key = (key, value)
            for prior_ref in self._index.get(index_key, []):
                reason = f"shared_{key}: {value}"
                new_edges.append(
                    CorrelationEdge(
                        event_a_ref=prior_ref,
                        event_b_ref=ref,
                        shared_entity=f"{key}:{value}",
                        correlation_reason=reason,
                    )
                )
                self._edges.append((prior_ref, ref, f"{key}:{value}"))
                self._dsu.union(prior_ref, ref)
            self._index.setdefault(index_key, []).append(ref)

        self._active[ref] = event
        self._dsu.add(ref)
        return new_edges

    def _evict(self, now_ts: datetime) -> None:
        cutoff = now_ts - self._ttl
        expired = [ref for ref, ev in self._active.items() if ev.ts < cutoff]
        if not expired:
            return
        expired_set = set(expired)
        for ref in expired:
            del self._active[ref]
        for index_key, refs in list(self._index.items()):
            kept = [r for r in refs if r not in expired_set]
            if kept:
                self._index[index_key] = kept
            else:
                del self._index[index_key]
        self._edges = [e for e in self._edges if e[0] not in expired_set and e[1] not in expired_set]
        self._rebuild_dsu()

    def _rebuild_dsu(self) -> None:
        dsu = _DSU()
        for ref in sorted(self._active):
            dsu.add(ref)
        for a, b, _ in self._edges:
            dsu.union(a, b)
        self._dsu = dsu

    def active_refs(self) -> list[str]:
        """Ссылки событий, находящихся в активном TTL-окне."""
        return sorted(self._active)

    def groups(self) -> list[list[str]]:
        """Текущие связные компоненты (кластеры коррелированных событий)."""
        return [sorted(members) for members in self._dsu.groups().values()]

    def component_of(self, ref: str) -> list[str]:
        """Кластер, которому принадлежит событие ``ref`` (пустой список, если выпало)."""
        if ref not in self._active:
            return []
        root = self._dsu.find(ref)
        return sorted(r for r in self._active if self._dsu.find(r) == root)
