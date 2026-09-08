"""Принадлежность доказательств при ручной корректировке состава дела.

Замечание, с которого начата работа (аудит «След смены», разрыв D01): проба split оставила
в дочернем деле только `e2`, но скопировала туда находку с `event_ids=[e1]` и её артефакт
`hash-e1`; у исходного дела наблюдение по-прежнему содержало оба события. Отдельный attach
принял `does-not-exist`. Прежние тесты attach/split проверяли состав событий и были зелёные —
принадлежность доказательств они не проверяли.

Последствие такой рассинхронизации — расследование и экспорт, содержащие доказательства
другого состава событий. Поэтому здесь проверяется не «операция отработала», а что после неё
каждое доказательство относится к событиям своего дела либо явно помечено историческим со
ссылкой на дело, где оно было записано.

Контракт, который держат эти проверки:

- находка идёт за своими событиями: все её события ушли — уходит и она, ни одного не ушло —
  остаётся;
- находка, чьи события разошлись по обоим делам, остаётся в исходном и помечается
  исторической: состава, о котором её писали, больше нет;
- отсоединение события не удаляет находку — оно снимает ссылку и помечает находку
  исторической, если ссылок не осталось: удалять запись аналитика нельзя;
- объединение переносит находки и артефакты источника в целевое дело вслед за событиями;
- события проверяются на существование, когда хранилище событий подключено;
- повтор запроса не создаёт второго дочернего дела и не удваивает перенос;
- ни одна операция не оставляет полусохранённого состояния.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from takt.application.use_cases.manual_correlation import ManualCorrelationCommand, ManualCorrelationUseCase
from takt.domain.entities.case import (
    Case,
    CaseArtifact,
    CaseStatus,
    Finding,
    InvariantHitRecord,
    Observation,
)
from takt.infrastructure.stores.memory import InMemoryCaseStore

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def _finding(finding_id: str, *event_ids: str, artifact: str = "") -> Finding:
    return Finding(
        finding_id=finding_id,
        text=f"находка {finding_id}",
        author="alice",
        created_at=NOW,
        event_ids=list(event_ids),
        artifacts=[CaseArtifact(type="hash", value=artifact)] if artifact else [],
    )


def _case(case_id: str, *events: str, findings: tuple[Finding, ...] = (), artifacts: tuple[str, ...] = ()) -> Case:
    records = [InvariantHitRecord("inv", event_id, NOW, 0.6, 1.0, False, []) for event_id in events]
    return Case(
        case_id=case_id,
        status=CaseStatus.NEW,
        title=case_id,
        risk_class="MEDIUM",
        risk_score=0.6,
        created_at=NOW,
        normalized_event_ids=list(events),
        burst_fingerprint=f"fp-{case_id}",
        invariant_hits=["inv"],
        invariant_hit_records=records,
        observations=[Observation(source="edr", ingest_trust=1.0, event_ids=list(events))],
        findings=list(findings),
        artifacts=[CaseArtifact(type="hash", value=value) for value in artifacts],
    )


def _use_case(repo: InMemoryCaseStore, events: tuple[str, ...] | None = None) -> ManualCorrelationUseCase:
    return ManualCorrelationUseCase(repo, events=_EventIndex(events) if events is not None else None)


class _EventIndex:
    """Минимальное хранилище событий: проверяет существование по идентификатору."""

    def __init__(self, known: tuple[str, ...]) -> None:
        self._known = set(known)

    def events_by_ids(self, event_ids: list[str]):
        return [object() for event_id in event_ids if event_id in self._known]


# --- split -----------------------------------------------------------------


def test_split_does_not_carry_a_finding_about_events_that_stayed() -> None:
    """То самое воспроизведение: в дочернем деле только e2, находка — про e1."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2", findings=(_finding("f-e1", "e1", artifact="hash-e1"),)))

    child = _use_case(repo).split(
        ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",)),
        clock=NOW,
    )

    assert child.normalized_event_ids == ["e2"]
    assert [item.finding_id for item in child.findings] == []
    assert [artifact.value for finding in child.findings for artifact in finding.artifacts] == []
    source = repo.get("src")
    assert source is not None
    assert [item.finding_id for item in source.findings] == ["f-e1"]


def test_split_moves_a_finding_together_with_its_events() -> None:
    """Находка идёт за своими событиями: иначе доказательство теряется вместе с делом."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2", findings=(_finding("f-e2", "e2", artifact="hash-e2"),)))

    child = _use_case(repo).split(
        ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",)),
        clock=NOW,
    )

    assert [item.finding_id for item in child.findings] == ["f-e2"]
    assert [artifact.value for finding in child.findings for artifact in finding.artifacts] == ["hash-e2"]
    source = repo.get("src")
    assert source is not None
    assert [item.finding_id for item in source.findings] == []


def test_split_marks_a_finding_that_spans_both_cases_as_historical() -> None:
    """Состава, о котором находку писали, больше нет — но удалять её нельзя."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2", findings=(_finding("f-both", "e1", "e2"),)))

    child = _use_case(repo).split(
        ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",)),
        clock=NOW,
    )

    assert [item.finding_id for item in child.findings] == []
    source = repo.get("src")
    assert source is not None
    kept = next(item for item in source.findings if item.finding_id == "f-both")
    assert kept.historical is True
    assert kept.origin_case_id == "src"


def test_split_leaves_the_source_observation_without_the_moved_events() -> None:
    """Наблюдение исходного дела по-прежнему содержало оба события."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2"))

    _use_case(repo).split(
        ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",)),
        clock=NOW,
    )

    source = repo.get("src")
    assert source is not None
    assert [item.event_ids for item in source.observations] == [["e1"]]


def test_split_does_not_hand_the_child_the_history_of_the_source() -> None:
    """Дочернее дело заводится сейчас: чужие решения и журнал ему не принадлежат."""
    repo = InMemoryCaseStore()
    source = _case("src", "e1", "e2")
    source.append_audit("решение исходного дела", NOW, actor="bob")
    repo.save(source)

    child = _use_case(repo).split(
        ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",)),
        clock=NOW,
    )

    assert not any("решение исходного дела" in line for line in child.audit_log)
    assert child.decision_records == []
    assert child.related_cases == ["src"]


def test_repeated_split_does_not_create_a_second_child() -> None:
    """Повтор запроса обязан иметь определённый результат, а не плодить дела."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2"))
    use_case = _use_case(repo)
    command = ManualCorrelationCommand("src", "отдельная активность", "alice", "split-1", event_ids=("e2",))

    first = use_case.split(command, clock=NOW)
    second = use_case.split(command, clock=NOW)

    assert second.case_id == first.case_id
    assert len(repo.list_all()) == 2


# --- attach / detach -------------------------------------------------------


def test_attach_rejects_an_event_the_product_does_not_know() -> None:
    """Проба приняла does-not-exist: дело получало ссылку в никуда."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1"))

    with pytest.raises(ValueError, match="unknown event"):
        _use_case(repo, events=("e1", "e2")).attach(
            ManualCorrelationCommand("src", "то же вторжение", "alice", "attach-1", event_id="does-not-exist"),
            clock=NOW,
        )

    source = repo.get("src")
    assert source is not None
    assert source.normalized_event_ids == ["e1"]


def test_attach_accepts_a_known_event() -> None:
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1"))

    result = _use_case(repo, events=("e1", "e2")).attach(
        ManualCorrelationCommand("src", "то же вторжение", "alice", "attach-1", event_id="e2"),
        clock=NOW,
    )

    assert result.normalized_event_ids == ["e1", "e2"]


def test_attach_without_an_event_store_keeps_working() -> None:
    """Хранилище событий подключено не в любой поставке; проверка условна и об этом молчит."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1"))

    result = _use_case(repo).attach(
        ManualCorrelationCommand("src", "то же вторжение", "alice", "attach-1", event_id="e2"),
        clock=NOW,
    )

    assert result.normalized_event_ids == ["e1", "e2"]


def test_detach_keeps_the_finding_but_drops_the_dangling_reference() -> None:
    """Ссылка на отсоединённое событие — висячая; сама запись аналитика остаётся."""
    repo = InMemoryCaseStore()
    repo.save(_case("src", "e1", "e2", findings=(_finding("f-e2", "e2"),)))

    result = _use_case(repo).detach(
        ManualCorrelationCommand("src", "ложное срабатывание", "alice", "detach-1", event_id="e2"),
        clock=NOW,
    )

    kept = next(item for item in result.findings if item.finding_id == "f-e2")
    assert kept.event_ids == []
    assert kept.historical is True
    assert kept.origin_case_id == "src"


# --- merge -----------------------------------------------------------------


def test_merge_carries_findings_and_artifacts_of_the_source() -> None:
    """События источника переходят в целевое дело — доказательства обязаны идти за ними."""
    repo = InMemoryCaseStore()
    repo.save(_case("target", "e1"))
    repo.save(_case("source", "e2", findings=(_finding("f-e2", "e2", artifact="hash-e2"),), artifacts=("hash-e2",)))

    merged = _use_case(repo).merge(
        ManualCorrelationCommand("target", "тот же инцидент", "alice", "merge-1", source_case_id="source"),
        clock=NOW,
    )

    assert [item.finding_id for item in merged.findings] == ["f-e2"]
    assert [item.value for item in merged.artifacts] == ["hash-e2"]
    moved = next(item for item in merged.findings if item.finding_id == "f-e2")
    assert moved.origin_case_id == "source", "происхождение перенесённой находки не сохранено"


def test_repeated_merge_does_not_double_the_evidence() -> None:
    repo = InMemoryCaseStore()
    repo.save(_case("target", "e1"))
    repo.save(_case("source", "e2", findings=(_finding("f-e2", "e2"),)))
    use_case = _use_case(repo)
    command = ManualCorrelationCommand("target", "тот же инцидент", "alice", "merge-1", source_case_id="source")

    use_case.merge(command, clock=NOW)
    merged = use_case.merge(command, clock=NOW)

    assert [item.finding_id for item in merged.findings] == ["f-e2"]


# --- атомарность -----------------------------------------------------------


class _FailingOnSecondSave(InMemoryCaseStore):
    """Хранилище, отказывающее на второй записи: имитация сбоя между сохранениями."""

    def __init__(self) -> None:
        super().__init__()
        self.saves = 0
        self.armed = False

    def save_all(self, cases) -> None:
        if self.armed:
            raise RuntimeError("хранилище недоступно")
        for case in cases:
            super().save(case)

    def save(self, case) -> None:
        if self.armed:
            self.saves += 1
            if self.saves > 1:
                raise RuntimeError("хранилище недоступно")
        super().save(case)


def test_merge_does_not_leave_a_half_saved_state() -> None:
    """Сбой между записями не должен оставлять источник закрытым, а цель — без событий."""
    repo = _FailingOnSecondSave()
    repo.save(_case("target", "e1"))
    repo.save(_case("source", "e2"))
    repo.armed = True

    with pytest.raises(RuntimeError):
        _use_case(repo).merge(
            ManualCorrelationCommand("target", "тот же инцидент", "alice", "merge-1", source_case_id="source"),
            clock=NOW,
        )

    target = repo.get("target")
    source = repo.get("source")
    assert target is not None and source is not None
    assert (target.normalized_event_ids, source.status) == (["e1"], CaseStatus.NEW)
