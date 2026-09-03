"""Автоматическая сборка связанного инцидента сразу после приёма событий.

Конвейер приёма группирует события ключами: подавление шума (актив + операция + окно) и
правила SOC-корреляции (`takt.domain.engines.alert_fatigue`). Обе группировки работают по
ключу, который событие делит с фоном, поэтому цепочка атаки распадается на десятки мелких
дел: на фикстуре INC-002 27 связанных событий давали 21 отдельное дело. Собрать из них
инцидент можно было только пивотом по отличительным сущностям — и только вручную,
утилитой вне интерфейса.

Этот use case выполняет первый шаг разбора автоматически и ровно в тех границах, которые
объявляет доменный движок `incident_pivot`: **надёжное ядро** по отличительным сущностям,
без транзитивного обхода. Расширение до уровня узла остаётся решением аналитика — обход по
узлам на реальном потоке вырождается и стягивает весь поток в одно дело.

Отличительной считается сущность, встречающаяся в принятом потоке не чаще
`distinctive_max_events` раз. Порог — не догадка. Замер на корпусе INC-002 (1030 событий,
из них 27 — цепочка), штатным путём, по каждому порогу отдельный прогон:

| Порог | Цепочка в собранном инциденте | Размер инцидента | Смешивание с фоном |
|---:|---|---:|---|
| 5 | 1 из 27 | 1 | нет |
| 8 | 14 из 27 | 14 | нет |
| **10–25** | **23 из 27** | **23** | **нет** |
| 40 | 24 из 27 | 221 | да |
| 80 | 27 из 27 | 272 | да |

Поставляется **12** — середина плато, на котором цепочка собирается полнее всего и ни одно
событие фона в инцидент не попадает. Ниже плато отличительных сущностей не набирается, выше
инцидент из 27 событий цепочки приходит вместе с 245 фоновыми и читается не лучше, чем
21 отдельное дело. Замер закреплён в `tests/test_auto_assemble_incidents.py`.

Оставшиеся 4 события цепочки отличительной сущности не несут: приписать их инциденту можно
было бы только расширением до уровня узла, а это второй шаг и решение аналитика.

**12 — не универсальная константа.** Проверено независимым внешним корпусом (EXT-001,
AIT Alert Data Set, не синтетика продукта): атака растянута на 18 часов, узлы и адреса
естественно встречаются 18–37 раз, и на пороге 12 сборка не даёт ни одного инцидента —
хотя вся выгрузка размечена одной цепочкой. Один глобальный порог не может одновременно
быть безопасным для короткой синтетической атаки и достаточным для многочасовой: подъём
до значения, связывающего EXT-001, ломает чистоту результата на INC-002. Поэтому порог —
параметр (`distinctive_max_events`), а не то, что можно один раз подобрать правильно.
Разбор — `docs/pt_techlab/correlation_quality.md`, замер —
`tests/test_auto_assemble_incidents_ext001.py`.

Узел (`host_id`) сидом не бывает: узел атаки делит активность с фоном, и это ровно то, что
движок относит ко второму шагу.

Границы продукта не двигаются: сборка — это группировка уже принятых событий, а не действие
и не вердикт. Идентификатор собранного инцидента выводится из состава сущностей, поэтому
повторный прогон на тех же данных даёт тот же инцидент, а не его копию.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol

from takt.application.system_defaults import default_hasher
from takt.application.use_cases.assemble_incident import (
    AssembleIncidentUseCase,
    CaseEventIndex,
    IncidentSeed,
)
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import NormalizedEvent
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.hasher import HasherPort

# Дела, которые ещё разбираются: закрытое дело пересобирать нечего.
_OPEN_STATUSES = frozenset({CaseStatus.NEW, CaseStatus.TRIAGE})

# Поля сущностей, пригодные в качестве отличительного признака инцидента.
# `host_id` намеренно отсутствует — см. модульную строку документации.
_SEED_FIELDS: tuple[tuple[str, str], ...] = (
    ("user_id", "user"),
    ("src_address", "address"),
    ("dst_address", "address"),
)

# Артефакты, которые по существу называют узел, а не отличительный объект: сидом они не
# бывают по той же причине, что и `host_id`.
_HOST_LIKE_ARTIFACTS = frozenset({"host"})

# Метка автоматической сборки в журнале дела.
_AUTO_MARKER = "incident assembled automatically after ingest"


class IncidentEventReadPort(Protocol):
    """Чтение принятых событий по идентификаторам. Реализуется хранилищем событий (L4)."""

    def events_by_ids(self, event_ids: list[str]) -> list[NormalizedEvent]: ...


@dataclass(frozen=True, slots=True)
class AssembledIncidentSummary:
    """Один собранный инцидент."""

    case_id: str
    seeds: tuple[str, ...]
    event_count: int
    source_case_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AutoAssemblyReport:
    """Итог прогона: что собрано и что осталось без отличительных сущностей."""

    incidents: tuple[AssembledIncidentSummary, ...]
    considered_cases: tuple[str, ...]
    skipped_cases: tuple[str, ...]

    @property
    def assembled_events(self) -> int:
        return sum(item.event_count for item in self.incidents)


@dataclass(slots=True)
class AutoAssembleIncidentsUseCase:
    """Собирает инциденты из дел конвейера, у которых есть срабатывания инвариантов."""

    assemble: AssembleIncidentUseCase
    repo: CaseRepositoryPort
    events: IncidentEventReadPort
    distinctive_max_events: int = 12
    hasher: HasherPort = field(default=default_hasher)
    # Счётчик встречаемости сущности не зависит от дела, а запрос к хранилищу стоит денег:
    # одна и та же учётная запись приходит сидом-кандидатом из каждого дела, где она есть.
    # `init=False` — это кэш прогона, а не настройка: снаружи его задавать нечем и незачем.
    _occurrences: dict[str, int] = field(default_factory=dict, repr=False, init=False)

    def execute(self, *, actor: str = "auto-assembly", now: datetime | None = None) -> AutoAssemblyReport:
        # Хранилище дел читается один раз на прогон. Раньше его обходили трижды плюс ещё по
        # разу на каждый собранный инцидент: 8000 дел и 40 инцидентов — 20 с на одни обходы.
        snapshot = self.repo.list_all()
        assemble = replace(self.assemble, case_index=CaseEventIndex.of(snapshot))
        considered: list[str] = []
        skipped: list[str] = []
        seed_groups: list[tuple[set[IncidentSeed], set[str], list[NormalizedEvent]]] = []
        previous = {
            case.case_id: set(case.normalized_event_ids)
            for case in self._previous_incidents(snapshot)
        }

        for case in self._seed_cases(snapshot):
            considered.append(case.case_id)
            seeds = self._distinctive_seeds(case)
            if not seeds:
                skipped.append(case.case_id)
                continue
            core = assemble.core_for(sorted(seeds, key=str))
            if not core:
                skipped.append(case.case_id)
                continue
            seed_groups.append((seeds, {event.event_id for event in core}, core))

        incidents: list[AssembledIncidentSummary] = []
        for seeds, event_ids in self._merge_overlapping(seed_groups):
            ordered = sorted(seeds, key=str)
            assembled = assemble.execute(
                case_id=self._incident_id(ordered),
                seeds=ordered,
                actor=actor,
                now=now,
            )
            assembled.case.append_audit(
                _AUTO_MARKER + f" seeds={len(ordered)} core={len(event_ids)}",
                assembled.case.created_at,
                actor=actor,
            )
            self.repo.save(assembled.case)
            incidents.append(
                AssembledIncidentSummary(
                    case_id=assembled.case.case_id,
                    seeds=tuple(str(seed) for seed in ordered),
                    event_count=assembled.total_events,
                    source_case_ids=assembled.source_case_ids,
                )
            )

        self._supersede(previous, incidents, actor=actor)
        return AutoAssemblyReport(
            incidents=tuple(incidents),
            considered_cases=tuple(considered),
            skipped_cases=tuple(skipped),
        )

    def _previous_incidents(self, snapshot: Iterable[Case]) -> list[Case]:
        return [case for case in snapshot if case.status in _OPEN_STATUSES and self._is_assembled(case)]

    def _supersede(
        self,
        previous: dict[str, set[str]],
        incidents: Sequence[AssembledIncidentSummary],
        *,
        actor: str,
    ) -> None:
        """Закрывает инцидент прошлого прогона, пересобранный в этом.

        Идентификатор выводится из состава сущностей, поэтому догрузка следующего источника
        меняет его: инцидент, собранный после EDR, и он же после NDR — разные карточки. Без
        этого шага очередь копила промежуточные редакции одного и того же инцидента.

        Признак пересборки — общее событие, а не вложенность состава. Состав меняется в обе
        стороны: с приходом NDR внутренний адрес перестаёт быть отличительным, сид отпадает,
        и новый инцидент оказывается **меньше** прежнего, а не больше. Внутри одного прогона
        инциденты по событиям не пересекаются (их ядра уже объединены), поэтому общее событие
        однозначно указывает на преемника; при пересечении с несколькими берётся наибольшее.

        Инцидент, ни одно событие которого в новую сборку не вошло, не трогается: он может
        быть тем, что аналитик уже разбирает.
        """
        fresh = {item.case_id for item in incidents}
        current: dict[str, set[str]] = {}
        for item in incidents:
            case = self.repo.get(item.case_id)
            if case is not None:
                current[item.case_id] = set(case.normalized_event_ids)
        for case_id, event_ids in previous.items():
            if case_id in fresh or not event_ids:
                continue
            overlaps = [(len(event_ids & ids), new_id) for new_id, ids in current.items() if event_ids & ids]
            if not overlaps:
                continue
            successor = max(overlaps, key=lambda pair: (pair[0], pair[1]))[1]
            stale = self.repo.get(case_id)
            if stale is None:
                continue
            stale.status = CaseStatus.MERGED
            stale.related_cases = list(dict.fromkeys([*stale.related_cases, successor]))
            stale.append_audit(
                f"superseded by reassembled incident {successor}", stale.created_at, actor=actor
            )
            self.repo.save(stale)

    # --- отбор дел и сущностей --------------------------------------------

    def _seed_cases(self, snapshot: Iterable[Case]) -> list[Case]:
        """Открытые дела конвейера со срабатыванием инварианта, кроме уже собранных.

        Признак — не «дело с высоким риском», а факт срабатывания: разбор начинается с
        того, что средство обнаружения или инвариант объявили аномалией, а не с балла.
        """
        return sorted(
            (
                case
                for case in snapshot
                if case.status in _OPEN_STATUSES
                and case.invariant_hit_records
                and not self._is_assembled(case)
            ),
            key=lambda case: case.case_id,
        )

    @staticmethod
    def _is_assembled(case: Case) -> bool:
        return any(_AUTO_MARKER in line for line in case.audit_log)

    def _distinctive_seeds(self, case: Case) -> set[IncidentSeed]:
        """Сущности событий дела, **на которых сработал инвариант**.

        Именно на которых, а не всего дела: подавление шума и SOC-корреляция собирают в одно
        дело события, связанные общим узлом или окном, и среди них есть штатная активность.
        Взяв сущности всего дела, сборка вытягивает вместе с цепочкой сотни фоновых событий —
        измерено на INC-002: 24 события цепочки и 602 фоновых в одном ядре.
        """
        triggered = list(dict.fromkeys(record.event_ref for record in case.invariant_hit_records))
        seeds: set[IncidentSeed] = set()
        for event in self.events.events_by_ids(triggered):
            for candidate in _candidate_seeds(event):
                if candidate in seeds:
                    continue
                if self._occurrences_of(candidate) <= self.distinctive_max_events:
                    seeds.add(candidate)
        return seeds

    def _occurrences_of(self, seed: IncidentSeed) -> int:
        key = str(seed)
        cached = self._occurrences.get(key)
        if cached is None:
            cached = self.assemble.occurrences(seed)
            self._occurrences[key] = cached
        return cached

    # --- объединение пересекающихся ядер ----------------------------------

    @staticmethod
    def _merge_overlapping(
        groups: Sequence[tuple[set[IncidentSeed], set[str], list[NormalizedEvent]]],
    ) -> list[tuple[set[IncidentSeed], set[str]]]:
        """Наборы сущностей, чьи ядра пересекаются, описывают один инцидент.

        Пересечение считается по событиям, а не по сущностям: два дела конвейера могут не
        делить ни одной сущности и всё равно собрать одно и то же ядро.
        """
        merged: list[tuple[set[IncidentSeed], set[str]]] = []
        for seeds, event_ids, _ in groups:
            current_seeds, current_events = set(seeds), set(event_ids)
            overlapping = [item for item in merged if item[1] & current_events]
            for item in overlapping:
                merged.remove(item)
                current_seeds |= item[0]
                current_events |= item[1]
            merged.append((current_seeds, current_events))
        return merged

    def _incident_id(self, seeds: Sequence[IncidentSeed]) -> str:
        """Идентификатор инцидента, выведенный из состава сущностей.

        Случайного идентификатора здесь быть не может: повторный прогон на тех же данных
        обязан дать тот же инцидент, а не его копию рядом с прежним.
        """
        material = "|".join(str(seed) for seed in seeds).encode("utf-8")
        return f"AUTO-{self.hasher.hash_bytes(material)[:12]}"


def _candidate_seeds(event: NormalizedEvent) -> list[IncidentSeed]:
    """Сущности события, которые в принципе могут быть отличительным признаком."""
    found: list[IncidentSeed] = []
    entities = event.entities
    if entities is not None:
        for field_name, kind in _SEED_FIELDS:
            value = str(getattr(entities, field_name, None) or "").strip()
            if value:
                found.append(IncidentSeed(kind, value))
    for artifact in event.artifacts:
        value = artifact.value.strip()
        if value and artifact.type.value not in _HOST_LIKE_ARTIFACTS:
            found.append(IncidentSeed("artifact", f"{artifact.type.value}:{value}"))
    return list(dict.fromkeys(found))
