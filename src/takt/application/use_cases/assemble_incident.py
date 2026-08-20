"""Сборка инцидента пивотом по сущностям — прикладной слой.

Доменный движок `takt.domain.engines.incident_pivot` отвечает на вопрос «какие события
относятся к этому инциденту», но до сих пор вызывался только из теста. Штатный конвейер
приёма группирует события по burst-фингерпринту, и на демонстрационной фикстуре INC-002
это даёт 121 мелкий кейс вместо одной цепочки атаки: аналитик видит ленту низкорисковых
срабатываний, а не инцидент.

Этот use case соединяет движок с хранилищами: достаёт события по отличительным сущностям,
собирает ядро, при необходимости расширяет разбор до уровня узла и сохраняет результат
как обычный кейс.

Границы продукта не двигаются. Сборка — это **группировка уже принятых событий**, а не
действие и не вердикт: риск не вычисляется заново, а агрегируется из кейсов, которые
конвейер уже оценил; вердикт и пакет реагирования остаются за аналитиком.

Детерминизм: порядок событий задаётся движком (`observed_at`, `event_id`), обращений к сети,
случайности и моделям здесь нет — см. `tests/test_verdict_determinism_guard.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from takt.domain.engines.incident_pivot import PivotKey, assemble_by_pivot, expand_to_hosts
from takt.domain.engines.risk_engine import combine_risk, worst_risk_class
from takt.domain.entities.case import Case, CaseStatus, Observation
from takt.domain.entities.event import NormalizedEvent
from takt.domain.invariants.evaluator import risk_vectors_from_invariants
from takt.domain.ports.case_repository import CaseRepositoryPort

# Разбор за один запрос к хранилищу: фикстура INC-002 — 1030 событий, страничный
# обход по 500 держит и её, и заметно больший поток.
_PAGE = 500

# Сколько страниц готовы прочитать по одной сущности. Ограничение защищает от пивота
# по сущности, которая массово встречается в фоне.
_MAX_PAGES = 40

_SEED_KINDS = ("host", "user", "address", "artifact")

# Метка в журнале собранного кейса. По ней сборка отличает кейсы конвейера от кейсов,
# собранных ранее ею же: иначе повторная сборка агрегировала бы риск сама с себя.
_ASSEMBLY_MARKER = "incident assembled by pivot"

# Ключи весов, без которых нельзя посчитать F(R, G, C, U, DQ).
_RISK_VECTOR_WEIGHTS = frozenset({"rhythm", "graph", "context", "user", "data_quality"})


class IncidentEventSearchPort(Protocol):
    """Чтение принятых событий. Реализуется хранилищем событий (L4)."""

    def search_events(self, **criteria: Any) -> tuple[list[NormalizedEvent], int]: ...


@dataclass(frozen=True, slots=True)
class IncidentSeed:
    """Отличительная сущность инцидента в виде «вид — значение»."""

    kind: str
    value: str

    @staticmethod
    def parse(raw: str) -> "IncidentSeed":
        """Разбирает запись вида `host:ws-17`, `user:smirnov`, `artifact:repo:release-prod`."""
        text = str(raw).strip()
        if ":" not in text:
            raise ValueError(f"сущность задаётся как «вид:значение», получено: {raw!r}")
        kind, value = text.split(":", 1)
        kind = kind.strip().lower()
        value = value.strip()
        if not value:
            raise ValueError(f"пустое значение сущности: {raw!r}")
        if kind not in _SEED_KINDS:
            raise ValueError(f"неизвестный вид сущности: {kind!r}, допустимы {', '.join(_SEED_KINDS)}")
        if kind == "artifact":
            # `artifact:repo:release-prod` — тип артефакта и его значение.
            artifact_type, _, artifact_value = value.partition(":")
            if not artifact_type.strip() or not artifact_value.strip():
                raise ValueError(f"артефакт задаётся как «artifact:тип:значение», получено: {raw!r}")
        return IncidentSeed(kind, value)

    @property
    def pivot_keys(self) -> tuple[PivotKey, ...]:
        """Ключи движка. Адрес ищется и как источник, и как назначение."""
        if self.kind == "host":
            return (PivotKey.of("host_id", self.value),)
        if self.kind == "user":
            return (PivotKey.of("user_id", self.value),)
        if self.kind == "address":
            return (PivotKey.of("src_address", self.value), PivotKey.of("dst_address", self.value))
        artifact_type, _, artifact_value = self.value.partition(":")
        return (PivotKey.of(f"artifact:{artifact_type}", artifact_value),)

    def search_criteria(self) -> dict[str, str]:
        """Критерии для хранилища событий."""
        if self.kind == "host":
            return {"host_id": self.value}
        if self.kind == "user":
            return {"user_id": self.value}
        if self.kind == "address":
            return {"address": self.value}
        artifact_type, _, artifact_value = self.value.partition(":")
        return {"artifact_type": artifact_type, "artifact_value": artifact_value}

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True, slots=True)
class AssembledIncident:
    """Результат сборки: кейс и разбор того, чем он набран."""

    case: Case
    core_event_ids: tuple[str, ...]
    expanded_event_ids: tuple[str, ...]
    source_case_ids: tuple[str, ...]

    @property
    def total_events(self) -> int:
        return len(self.core_event_ids) + len(self.expanded_event_ids)


@dataclass(slots=True)
class AssembleIncidentUseCase:
    """Собирает кейс из принятых событий по отличительным сущностям."""

    events: IncidentEventSearchPort
    repo: CaseRepositoryPort
    weights: Mapping[str, float] = field(default_factory=dict)
    page_size: int = _PAGE
    max_pages: int = _MAX_PAGES

    def execute(
        self,
        *,
        case_id: str,
        seeds: Sequence[IncidentSeed],
        title: str = "",
        expand_hosts: Sequence[str] = (),
        expand_padding_sec: int = 0,
        actor: str = "",
        now: datetime | None = None,
    ) -> AssembledIncident:
        if not case_id.strip():
            raise ValueError("case_id обязателен")
        if not seeds:
            raise ValueError("нужна хотя бы одна отличительная сущность")

        candidates = self._candidates(seeds)
        pivots = [key for seed in seeds for key in seed.pivot_keys]
        core = assemble_by_pivot(candidates.values(), pivots)
        if not core:
            raise LookupError(
                "по указанным сущностям событий не найдено: " + ", ".join(str(seed) for seed in seeds)
            )

        assembled = core
        if expand_hosts:
            window = self._host_window(core, expand_hosts, padding_sec=expand_padding_sec)
            assembled = expand_to_hosts(window, core, expand_hosts, padding_sec=expand_padding_sec)

        core_ids = tuple(event.event_id for event in core)
        core_id_set = set(core_ids)
        expanded_ids = tuple(event.event_id for event in assembled if event.event_id not in core_id_set)
        case = self._build_case(
            case_id=case_id,
            title=title,
            seeds=seeds,
            assembled=assembled,
            core_ids=core_ids,
            expanded_ids=expanded_ids,
            expand_hosts=expand_hosts,
            actor=actor,
            now=now or _latest(assembled),
        )
        self.repo.save(case)
        return AssembledIncident(
            case=case,
            core_event_ids=core_ids,
            expanded_event_ids=expanded_ids,
            source_case_ids=tuple(case.related_cases),
        )

    # --- чтение хранилища -------------------------------------------------

    def _candidates(self, seeds: Sequence[IncidentSeed]) -> dict[str, NormalizedEvent]:
        """События, где встречается любая из отличительных сущностей, без дублей."""
        found: dict[str, NormalizedEvent] = {}
        for seed in seeds:
            for event in self._search_all(seed.search_criteria()):
                found[event.event_id] = event
        return found

    def _host_window(
        self,
        core: Sequence[NormalizedEvent],
        hosts: Iterable[str],
        *,
        padding_sec: int,
    ) -> list[NormalizedEvent]:
        """События указанных узлов во временном окне ядра — вход для расширения."""
        start = min(event.observed_at for event in core) - timedelta(seconds=padding_sec)
        end = max(event.observed_at for event in core) + timedelta(seconds=padding_sec)
        window: dict[str, NormalizedEvent] = {}
        for host in hosts:
            criteria = {"host_id": host, "observed_from": start, "observed_to": end}
            for event in self._search_all(criteria):
                window[event.event_id] = event
        return list(window.values())

    def _search_all(self, criteria: dict[str, Any]) -> list[NormalizedEvent]:
        collected: list[NormalizedEvent] = []
        offset = 0
        for _ in range(self.max_pages):
            page, total = self.events.search_events(offset=offset, limit=self.page_size, **criteria)
            collected.extend(page)
            offset += len(page)
            if not page or offset >= total:
                break
        return collected

    # --- сборка карточки --------------------------------------------------

    def _build_case(
        self,
        *,
        case_id: str,
        title: str,
        seeds: Sequence[IncidentSeed],
        assembled: Sequence[NormalizedEvent],
        core_ids: tuple[str, ...],
        expanded_ids: tuple[str, ...],
        expand_hosts: Sequence[str],
        actor: str,
        now: datetime,
    ) -> Case:
        event_ids = [event.event_id for event in assembled]
        contributing = self._contributing_cases(set(event_ids), exclude_case_id=case_id)
        invariant_hits = sorted({hit for case in contributing for hit in case.invariant_hits})
        risk_score, risk_class = _incident_risk(invariant_hits, contributing, assembled, self.weights)

        case = Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title=title or _default_title(seeds),
            risk_class=risk_class,
            risk_score=risk_score,
            created_at=now,
            normalized_event_ids=event_ids,
            xai_summary=_summary(seeds, core_ids, expanded_ids, expand_hosts, assembled),
            primary_asset_id=_primary_asset(assembled),
            trigger_operation=assembled[0].operation if assembled else "",
            operator_id=actor,
            invariant_hits=invariant_hits,
            observations=_observations(assembled),
            last_event_source=assembled[-1].source.value if assembled else "",
            related_cases=sorted(item.case_id for item in contributing),
        )
        case.append_audit(
            _ASSEMBLY_MARKER
            + f" seeds={','.join(str(seed) for seed in seeds)}"
            f" core={len(core_ids)} expanded={len(expanded_ids)}"
            f" hosts={','.join(expand_hosts) if expand_hosts else '-'}",
            now,
            actor=actor,
        )
        return case

    def _contributing_cases(self, event_ids: set[str], *, exclude_case_id: str) -> list[Case]:
        """Кейсы конвейера, из событий которых собран инцидент.

        Ранее собранные пивотом кейсы исключаются: они не источник оценки, а такой же
        результат сборки, и агрегировать риск с них означало бы считать его дважды.
        """
        return [
            case
            for case in self.repo.list_all()
            if case.case_id != exclude_case_id
            and not _is_assembled(case)
            and set(case.normalized_event_ids) & event_ids
        ]


# --- вспомогательные чистые функции ---------------------------------------


def _is_assembled(case: Case) -> bool:
    """Кейс собран этим же use case — по метке в журнале."""
    return any(_ASSEMBLY_MARKER in line for line in case.audit_log)


def _latest(events: Sequence[NormalizedEvent]) -> datetime:
    return max(event.observed_at for event in events)


def _default_title(seeds: Sequence[IncidentSeed]) -> str:
    return "Инцидент по сущностям: " + ", ".join(str(seed) for seed in seeds[:3])


def _primary_asset(events: Sequence[NormalizedEvent]) -> str:
    for event in events:
        host = getattr(event.entities, "host_id", "") if event.entities else ""
        if host:
            return host
    return ""


def _observations(events: Sequence[NormalizedEvent]) -> list[Observation]:
    by_source: dict[str, list[str]] = {}
    trust: dict[str, float] = {}
    for event in events:
        source = event.source.value
        by_source.setdefault(source, []).append(event.event_id)
        trust.setdefault(source, float(getattr(event, "ingest_trust", 1.0) or 1.0))
    return [
        Observation(source=source, ingest_trust=trust[source], event_ids=ids)
        for source, ids in sorted(by_source.items())
    ]


def _incident_risk(
    invariant_hits: Sequence[str],
    contributing: Sequence[Case],
    assembled: Sequence[NormalizedEvent],
    weights: Mapping[str, float],
) -> tuple[float, str]:
    """Риск собранного инцидента — по той же модели F(R, G, C, U, DQ), что и у события.

    Смысл сборки в том, что набор срабатываний инцидента больше любого отдельного из них:
    канал управления, перемещение между узлами и работа вне окна по отдельности дают
    слабый сигнал, вместе — картину атаки. Поэтому векторы строятся по объединению
    сработавших инвариантов (общая функция `risk_vectors_from_invariants`), а не берутся
    от самого «тяжёлого» события.

    Новая модель риска при этом не вводится: те же веса из `config/risk_weights.yaml`,
    та же `combine_risk`, те же пороги классов. Результат не может оказаться ниже самого
    опасного из вошедших кейсов — инцидент не бывает безопаснее своей худшей части.
    """
    if not contributing and not invariant_hits:
        return 0.0, "UNKNOWN"
    if not _RISK_VECTOR_WEIGHTS <= set(weights):
        # Без весов из `config/risk_weights.yaml` модель F(R, G, C, U, DQ) неприменима.
        # Выдумывать веса нельзя, поэтому берётся худший из вошедших кейсов —
        # оценка заведомо не завышена.
        return _worst_of(contributing)

    dq_score = min((case.dq_score for case in contributing), default=1.0)
    assessment = combine_risk(
        risk_vectors_from_invariants(invariant_hits, data_quality=1.0 - dq_score),
        weights,
        dq_score=dq_score,
        eps_estimate=_events_per_second(assembled),
        mandel_cap=float(weights.get("mandelbrot_entropy_cap", 2.5)),
        eps_soft_cap=float(weights.get("eps_soft_cap", 100_000)),
        risk_class_thresholds=weights.get("risk_class_thresholds"),
    )
    if not contributing:
        return assessment.score, assessment.risk_class
    top_score, top_class = _worst_of(contributing)
    return (
        max(assessment.score, top_score),
        worst_risk_class(assessment.risk_class, top_class),
    )


def _worst_of(contributing: Sequence[Case]) -> tuple[float, str]:
    if not contributing:
        return 0.0, "UNKNOWN"
    top = max(contributing, key=lambda case: case.risk_score)
    return top.risk_score, top.risk_class


def _events_per_second(events: Sequence[NormalizedEvent]) -> float:
    """Интенсивность потока инцидента; при нулевом интервале — по числу событий."""
    if len(events) < 2:
        return float(len(events))
    span = (max(e.observed_at for e in events) - min(e.observed_at for e in events)).total_seconds()
    return len(events) / span if span > 0 else float(len(events))


def _summary(
    seeds: Sequence[IncidentSeed],
    core_ids: Sequence[str],
    expanded_ids: Sequence[str],
    expand_hosts: Sequence[str],
    assembled: Sequence[NormalizedEvent],
) -> str:
    sources = sorted({event.source.value for event in assembled})
    text = (
        f"Собрано {len(assembled)} событий из источников: {', '.join(sources)}. "
        f"Ядро по отличительным сущностям ({', '.join(str(seed) for seed in seeds)}) — "
        f"{len(core_ids)} событий."
    )
    if expanded_ids:
        text += (
            f" Расширение до уровня узла ({', '.join(expand_hosts)}) добавило {len(expanded_ids)}"
            " событий без отличительных признаков; отсев остаётся за аналитиком."
        )
    return text
