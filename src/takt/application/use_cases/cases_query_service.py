from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import EventSource
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort

CASE_LIST_SORT_KEYS = frozenset(
    {
        "risk_score_desc",
        "risk_score_asc",
        "created_at_desc",
        "created_at_asc",
        "dq_score_desc",
        "dq_score_asc",
        "invariant_hits_desc",
        "invariant_hits_asc",
        "event_count_desc",
        "event_count_asc",
        "title_desc",
        "title_asc",
        "case_id_desc",
        "case_id_asc",
        "primary_asset_id_desc",
        "primary_asset_id_asc",
    }
)
VALID_RISK_CLASSES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

CASE_GROUP_KEYS = frozenset({"asset", "operation"})
"""Два разреза одной очереди.

`asset` — актив, операция и класс риска: отвечает на вопрос «какой узел шумит».
`operation` — операция и класс риска: отвечает на вопрос «какое правило шумит», то есть даёт
материал для правки правила, а не для разбора срабатываний поштучно."""


@dataclass(frozen=True, slots=True)
class CasesListQuery:
    status: str | None = None
    risk_class: str | None = None
    risk_classes: str | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    min_risk_score: float | None = None
    max_risk_score: float | None = None
    min_dq_score: float | None = None
    max_dq_score: float | None = None
    dq_partial: bool | None = None
    has_invariant: str | None = None
    has_dq_reason: str | None = None
    primary_asset_id: str | None = None
    fingerprint: str | None = None
    fingerprint_prefix: str | None = None
    title_contains: str | None = None
    case_id_prefix: str | None = None
    trigger_operation_contains: str | None = None
    min_invariant_hits: int | None = None
    max_invariant_hits: int | None = None
    xai_contains: str | None = None
    min_event_count: int | None = None
    max_event_count: int | None = None
    audit_contains: str | None = None
    event_source: str | None = None
    sort: str = "risk_score_desc"
    offset: int = 0
    limit: int | None = None


@dataclass(frozen=True, slots=True)
class CasesListResult:
    items: list[Case]
    total_before_slice: int


@dataclass(frozen=True, slots=True)
class CaseGroup:
    """Однотипные дела, сведённые в одну строку очереди."""

    key: str
    primary_asset_id: str
    assets: int
    trigger_operation: str
    risk_class: str
    cases: int
    events: int
    max_risk_score: float
    top_case_id: str
    first_created_at: str
    last_created_at: str
    by_status: dict[str, int]


@dataclass(frozen=True, slots=True)
class CasesGroupResult:
    items: list[CaseGroup]
    total_groups: int
    total_cases: int


@dataclass(frozen=True, slots=True)
class CasesStats:
    total: int
    open: int
    by_status: dict[str, int]
    by_risk_class: dict[str, int]
    avg_risk_score: float
    avg_dq_score: float
    dq_partial_count: int
    normalized_events_total: int
    distinct_invariant_hits: int
    invariant_hits_occurrences_total: int
    by_last_event_source: dict[str, int]


@dataclass(frozen=True, slots=True)
class CasesFullExportResult:
    exported_at: str
    items: list[Case]
    total: int
    offset: int
    limit: int | None


@dataclass(frozen=True, slots=True)
class CasesImportResult:
    imported: int
    skipped: int
    mode: str


class CasesQueryService:
    def __init__(self, repo: CaseRepositoryPort | None, clock: SystemClockPort | None = None) -> None:
        self._repo = repo
        self._clock = clock

    @property
    def sort_keys(self) -> frozenset[str]:
        return CASE_LIST_SORT_KEYS

    @property
    def valid_risk_classes(self) -> frozenset[str]:
        return VALID_RISK_CLASSES

    def list_cases(self, query: CasesListQuery) -> CasesListResult:
        items = list(self._require_repo().list_all())
        items = self._apply_filters(items, query)
        items = self.sort_cases(items, query.sort)
        total = len(items)
        sliced = items[query.offset :]
        if query.limit is not None:
            sliced = sliced[: query.limit]
        return CasesListResult(items=sliced, total_before_slice=total)

    @staticmethod
    def group_key(case: Case, group_by: str = "asset") -> str:
        """Ключ однотипности: актив, операция и класс риска.

        Собственный `burst_fingerprint` дела для этого не годится: в него входит корзина
        времени, поэтому одинаковые срабатывания на одном активе попадают в разные корзины и
        считаются разными делами. Именно из-за этого очередь на демонстрационном датасете
        состоит из 263 почти одинаковых дел «низкий: ALLOWED» — дедупликация работает, но
        только внутри одной минуты. Ключ группы время не включает намеренно.

        Класс риска входит в ключ: одинаковые операции с разной оценкой — это разные строки
        очереди, и слить их значило бы спрятать более тяжёлое дело за более лёгким.
        """
        asset = (case.primary_asset_id or "").strip()
        operation = (case.trigger_operation or "").strip()
        if group_by == "operation":
            return f"|{operation}|{case.risk_class}"
        return f"{asset}|{operation}|{case.risk_class}"

    def group_cases(self, query: CasesListQuery, group_by: str = "asset") -> CasesGroupResult:
        """Очередь, сведённая по однотипности. Фильтры те же, что у списка дел.

        Группировка не меняет ни одного дела: это способ показа, а не сборки. Каждое дело
        остаётся отдельным и открывается как раньше — иначе правка состава и вердикт по
        группе стали бы неотличимы от вердикта по делу.
        """
        if group_by not in CASE_GROUP_KEYS:
            raise ValueError(f"unsupported group_by: {group_by}")
        items = self._apply_filters(list(self._require_repo().list_all()), query)
        buckets: dict[str, list[Case]] = {}
        for case in items:
            buckets.setdefault(self.group_key(case, group_by), []).append(case)

        groups: list[CaseGroup] = []
        for key, cases in buckets.items():
            top = max(cases, key=lambda c: (c.risk_score, c.case_id))
            created = sorted(c.created_at.astimezone(UTC).isoformat(timespec="seconds") for c in cases)
            assets = {c.primary_asset_id for c in cases if c.primary_asset_id}
            groups.append(
                CaseGroup(
                    key=key,
                    # В разрезе по операции активов у группы несколько: показать актив
                    # представителя значило бы приписать всей группе один узел.
                    primary_asset_id=top.primary_asset_id if len(assets) <= 1 else "",
                    assets=len(assets),
                    trigger_operation=top.trigger_operation,
                    risk_class=top.risk_class,
                    cases=len(cases),
                    events=sum(len(c.normalized_event_ids) for c in cases),
                    max_risk_score=top.risk_score,
                    top_case_id=top.case_id,
                    first_created_at=created[0],
                    last_created_at=created[-1],
                    by_status=dict(Counter(c.status.value for c in cases)),
                )
            )

        # Порядок: сначала самое тяжёлое, при равном балле — самое многочисленное. Ключ
        # замыкает сравнение, чтобы повторный прогон давал тот же порядок.
        groups.sort(key=lambda g: (-g.max_risk_score, -g.cases, g.key))
        total_cases = sum(g.cases for g in groups)
        sliced = groups[query.offset :]
        if query.limit is not None:
            sliced = sliced[: query.limit]
        return CasesGroupResult(items=sliced, total_groups=len(groups), total_cases=total_cases)

    def stats(self) -> CasesStats:
        all_c = list(self._require_repo().list_all())
        n = len(all_c)
        by_status = Counter(c.status.value for c in all_c)
        by_rc = Counter(c.risk_class.upper() for c in all_c)
        open_n = sum(1 for c in all_c if c.status in (CaseStatus.NEW, CaseStatus.TRIAGE))
        avg_r = sum(c.risk_score for c in all_c) / n if n else 0.0
        avg_dq = sum(c.dq_score for c in all_c) / n if n else 0.0
        dq_part = sum(1 for c in all_c if c.dq_partial)
        ev_total = sum(len(c.normalized_event_ids) for c in all_c)
        inv_seen: set[str] = set()
        inv_occ = 0
        for c in all_c:
            inv_seen.update(c.invariant_hits)
            inv_occ += len(c.invariant_hits)
        by_es = Counter((c.last_event_source or "unknown") for c in all_c)
        return CasesStats(
            total=n,
            open=open_n,
            by_status=dict(sorted(by_status.items())),
            by_risk_class=dict(sorted(by_rc.items())),
            avg_risk_score=avg_r,
            avg_dq_score=avg_dq,
            dq_partial_count=dq_part,
            normalized_events_total=ev_total,
            distinct_invariant_hits=len(inv_seen),
            invariant_hits_occurrences_total=inv_occ,
            by_last_event_source=dict(sorted(by_es.items())),
        )

    def sorted_for_full_export(self) -> list[Case]:
        return self.sort_cases(list(self._require_repo().list_all()), "created_at_desc")

    def full_export(self, *, offset: int, limit: int | None) -> CasesFullExportResult:
        all_sorted = self.sorted_for_full_export()
        total = len(all_sorted)
        slice_start = min(offset, total)
        rest = all_sorted[slice_start:]
        batch = rest if limit is None else rest[:limit]
        return CasesFullExportResult(
            exported_at=self._now_utc().isoformat(timespec="seconds"),
            items=batch,
            total=total,
            offset=offset,
            limit=limit,
        )

    def get_case_or_none(self, case_id: str) -> Case | None:
        return self._require_repo().get(case_id)

    def import_cases(self, cases: list[Case], *, mode: str, actor: str = "import_api") -> CasesImportResult:
        repo = self._require_repo()
        imported = 0
        skipped = 0

        def apply() -> None:
            nonlocal imported, skipped
            op_rec = getattr(repo, "record_operation_event", None)
            for case in cases:
                if mode == "skip_existing" and repo.get(case.case_id) is not None:
                    skipped += 1
                    continue
                repo.save(case)
                imported += 1
                if callable(op_rec):
                    op_rec(
                        operation_type="import",
                        entity_id=case.case_id,
                        actor=actor,
                        payload_json=json.dumps(
                            {
                                "case_id": case.case_id,
                                "mode": mode,
                                "event_ids_count": len(case.normalized_event_ids),
                                "risk_class": case.risk_class,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        created_at=self._now_utc().isoformat(timespec="seconds"),
                    )

        tx_cm = getattr(self._repo, "transaction", None)
        if callable(tx_cm):
            with tx_cm():
                apply()
        else:
            apply()
        return CasesImportResult(imported=imported, skipped=skipped, mode=mode)

    def _require_repo(self) -> CaseRepositoryPort:
        """Хранилище кейсов или отказ, если сервис собран без него.

        Возвращает порт, а не проверяет молча: вызывающий работает с уже сужённым типом, и
        обращение к `None` становится невозможным по построению, а не по договорённости.
        """
        if self._repo is None:
            raise RuntimeError("case repository is required")
        return self._repo

    def _now_utc(self) -> datetime:
        if self._clock is not None:
            return self._clock.now_utc()
        return datetime.now(UTC)

    def sort_cases(self, items: list[Case], sort_key: str) -> list[Case]:
        sk = sort_key.strip().lower()
        if sk == "risk_score_desc":
            return sorted(items, key=lambda c: c.risk_score, reverse=True)
        if sk == "risk_score_asc":
            return sorted(items, key=lambda c: c.risk_score)
        if sk == "created_at_desc":
            return sorted(items, key=lambda c: self.as_utc_boundary(c.created_at), reverse=True)
        if sk == "created_at_asc":
            return sorted(items, key=lambda c: self.as_utc_boundary(c.created_at))
        if sk == "dq_score_desc":
            return sorted(items, key=lambda c: c.dq_score, reverse=True)
        if sk == "dq_score_asc":
            return sorted(items, key=lambda c: c.dq_score)
        if sk == "invariant_hits_desc":
            return sorted(items, key=lambda c: len(c.invariant_hits), reverse=True)
        if sk == "invariant_hits_asc":
            return sorted(items, key=lambda c: len(c.invariant_hits))
        if sk == "event_count_desc":
            return sorted(items, key=lambda c: len(c.normalized_event_ids), reverse=True)
        if sk == "event_count_asc":
            return sorted(items, key=lambda c: len(c.normalized_event_ids))
        if sk == "title_desc":
            return sorted(items, key=lambda c: c.title.lower(), reverse=True)
        if sk == "title_asc":
            return sorted(items, key=lambda c: c.title.lower())
        if sk == "case_id_desc":
            return sorted(items, key=lambda c: c.case_id.lower(), reverse=True)
        if sk == "case_id_asc":
            return sorted(items, key=lambda c: c.case_id.lower())
        if sk == "primary_asset_id_desc":
            return sorted(items, key=lambda c: c.primary_asset_id.lower(), reverse=True)
        if sk == "primary_asset_id_asc":
            return sorted(items, key=lambda c: c.primary_asset_id.lower())
        raise ValueError(f"invalid sort; use one of: {', '.join(sorted(CASE_LIST_SORT_KEYS))}")

    @staticmethod
    def coerce_case_status(raw: str) -> CaseStatus:
        try:
            return CaseStatus(raw.strip().upper())
        except ValueError as e:
            allowed = ", ".join(s.value for s in CaseStatus)
            raise ValueError(f"invalid status; use one of: {allowed}") from e

    @staticmethod
    def coerce_event_source(raw: str | None) -> EventSource:
        if raw is None or raw == "":
            return EventSource.PLC_POLLING
        try:
            return EventSource(raw)
        except ValueError as e:
            allowed = ", ".join(s.value for s in EventSource)
            raise ValueError(f"invalid source; use one of: {allowed}") from e

    @staticmethod
    def as_utc_boundary(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _apply_filters(self, items: list[Case], query: CasesListQuery) -> list[Case]:
        if query.status is not None and query.status.strip() != "":
            st = self.coerce_case_status(query.status)
            items = [c for c in items if c.status == st]
        if query.risk_class is not None and query.risk_class.strip() != "":
            rc = query.risk_class.strip().upper()
            if rc not in VALID_RISK_CLASSES:
                raise ValueError(f"invalid risk_class; use one of: {', '.join(sorted(VALID_RISK_CLASSES))}")
            items = [c for c in items if c.risk_class.upper() == rc]
        if query.risk_classes is not None and query.risk_classes.strip() != "":
            parts = {p.strip().upper() for p in query.risk_classes.split(",") if p.strip()}
            unknown = parts - VALID_RISK_CLASSES
            if unknown:
                raise ValueError(
                    f"invalid risk_classes token(s): {', '.join(sorted(unknown))}; use: {', '.join(sorted(VALID_RISK_CLASSES))}"
                )
            items = [c for c in items if c.risk_class.upper() in parts]
        if query.created_after is not None:
            t0 = self.as_utc_boundary(query.created_after)
            items = [c for c in items if c.created_at >= t0]
        if query.created_before is not None:
            t1 = self.as_utc_boundary(query.created_before)
            items = [c for c in items if c.created_at <= t1]
        if query.min_risk_score is not None:
            items = [c for c in items if c.risk_score >= query.min_risk_score]
        if query.max_risk_score is not None:
            items = [c for c in items if c.risk_score <= query.max_risk_score]
        if query.min_dq_score is not None:
            items = [c for c in items if c.dq_score >= query.min_dq_score]
        if query.max_dq_score is not None:
            items = [c for c in items if c.dq_score <= query.max_dq_score]
        if query.dq_partial is not None:
            items = [c for c in items if c.dq_partial == query.dq_partial]
        items = self._apply_text_filters(items, query)
        if query.min_invariant_hits is not None:
            items = [c for c in items if len(c.invariant_hits) >= query.min_invariant_hits]
        if query.max_invariant_hits is not None:
            items = [c for c in items if len(c.invariant_hits) <= query.max_invariant_hits]
        if query.min_event_count is not None:
            items = [c for c in items if len(c.normalized_event_ids) >= query.min_event_count]
        if query.max_event_count is not None:
            items = [c for c in items if len(c.normalized_event_ids) <= query.max_event_count]
        if query.event_source is not None and query.event_source.strip() != "":
            es = self.coerce_event_source(query.event_source.strip())
            items = [c for c in items if c.last_event_source == es.value]
        return items

    @staticmethod
    def _apply_text_filters(items: list[Case], query: CasesListQuery) -> list[Case]:
        if query.has_invariant is not None and query.has_invariant.strip() != "":
            needle = query.has_invariant.strip().lower()
            items = [c for c in items if any(needle in h.lower() for h in c.invariant_hits)]
        if query.has_dq_reason is not None and query.has_dq_reason.strip() != "":
            needle = query.has_dq_reason.strip().lower()
            items = [c for c in items if any(needle in r.lower() for r in c.dq_reasons)]
        if query.primary_asset_id is not None and query.primary_asset_id.strip() != "":
            aid = query.primary_asset_id.strip().lower()
            items = [c for c in items if c.primary_asset_id.lower() == aid]
        if query.fingerprint is not None and query.fingerprint.strip() != "":
            fpq = query.fingerprint.strip()
            items = [c for c in items if c.burst_fingerprint == fpq]
        if query.fingerprint_prefix is not None and query.fingerprint_prefix.strip() != "":
            fpfx = query.fingerprint_prefix.strip().lower()
            items = [c for c in items if c.burst_fingerprint.lower().startswith(fpfx)]
        if query.title_contains is not None and query.title_contains.strip() != "":
            needle = query.title_contains.strip().lower()
            items = [c for c in items if needle in c.title.lower()]
        if query.case_id_prefix is not None and query.case_id_prefix.strip() != "":
            pfx = query.case_id_prefix.strip().lower()
            items = [c for c in items if c.case_id.lower().startswith(pfx)]
        if query.trigger_operation_contains is not None and query.trigger_operation_contains.strip() != "":
            needle = query.trigger_operation_contains.strip().lower()
            items = [c for c in items if needle in c.trigger_operation.lower()]
        if query.xai_contains is not None and query.xai_contains.strip() != "":
            needle = query.xai_contains.strip().lower()
            items = [c for c in items if needle in c.xai_summary.lower()]
        if query.audit_contains is not None and query.audit_contains.strip() != "":
            needle = query.audit_contains.strip().lower()
            items = [c for c in items if any(needle in line.lower() for line in c.audit_log)]
        return items
