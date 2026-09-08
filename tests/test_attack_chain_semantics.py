"""Что реконструкция вправе назвать запуском, а что — только наблюдением.

Замечание, с которого начата работа (аудит «След смены», разрыв D05): событие `OBSERVED` с
заполненным `process_id` превращалось в шаг `process_spawn` — «запуск процесса», — независимо
от операции. Точка входа выбиралась эвристикой (первый процесс с неизвестным родителем либо
адрес источника), а окно называло результат «Точка входа» без указания границ доказательств.

Последствие: временная последовательность выглядит как доказанная цепочка запуска и
проникновения. Для доказательного пакета это хуже отсутствия реконструкции — там, где данные
позволяют сказать только «процесс наблюдался», сказано «процесс был запущен».

Контракт:

- запуском считается событие, операция которого о запуске говорит; остальное — наблюдение
  процесса;
- сетевым перемещением считается пара адресов; событие без пары остаётся вне шагов;
- неизвестный родитель обозначается неизвестным, а не подставляется пользователем или узлом;
- точка входа — гипотеза, и она помечена гипотезой; установленным фактом она становится
  только когда родитель процесса действительно наблюдался вне дела;
- у шага сохраняются все события-основания и диапазон доступной истории: по чему сделан
  вывод и в каких границах.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from takt.application.use_cases.reconstruct_chain import reconstruct_attack_chain
from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent

START = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def _event(
    event_id: str,
    *,
    operation: str = "OBSERVED",
    minute: int = 0,
    host: str | None = None,
    user: str | None = None,
    process: str | None = None,
    parent: str | None = None,
    src: str | None = None,
    dst: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=START + timedelta(minutes=minute),
        source=EventSource.EDR,
        protocol="test",
        operation=operation,
        payload_size=1,
        payload={},
        entities=EventEntities(
            host_id=host, user_id=user, process_id=process,
            parent_process_id=parent, src_address=src, dst_address=dst,
        ),
        ingest_trust=1.0,
    )


def _kinds(chain: dict) -> list[str]:
    return [step["kind"] for step in chain["steps"]]


def test_a_plain_observation_is_not_a_process_spawn() -> None:
    """То самое воспроизведение: OBSERVED с process_id становился запуском процесса."""
    chain = reconstruct_attack_chain([_event("e-1", operation="OBSERVED", process="p-1", host="ws-1")])

    assert _kinds(chain) == ["process_observed"]


def test_a_spawn_operation_is_a_spawn() -> None:
    """Запуск подтверждается операцией события, а не фактом заполненного поля процесса."""
    chain = reconstruct_attack_chain(
        [_event("e-1", operation="PROCESS_CREATE", process="p-1", parent="p-0", host="ws-1")]
    )

    assert _kinds(chain) == ["process_spawn"]
    assert chain["steps"][0]["from_entity"] == "p-0"


def test_an_unknown_parent_is_named_unknown_and_not_replaced_by_a_user() -> None:
    """Подстановка пользователя или узла вместо родителя выдаёт догадку за наблюдение."""
    chain = reconstruct_attack_chain(
        [_event("e-1", operation="PROCESS_CREATE", process="p-1", user="ivanov", host="ws-1")]
    )

    step = chain["steps"][0]
    assert step["from_entity"] == ""
    assert step["from_entity_known"] is False


def test_network_move_needs_a_pair_of_addresses() -> None:
    """Один адрес перемещением не является: направление из него не следует."""
    chain = reconstruct_attack_chain([_event("e-1", src="10.0.0.1")])

    assert _kinds(chain) == []


def test_entry_point_is_marked_as_a_hypothesis() -> None:
    """«Точка входа» без границы доказательств читается как установленный факт."""
    chain = reconstruct_attack_chain(
        [_event("e-1", operation="PROCESS_CREATE", process="p-1", host="ws-1")]
    )

    assert chain["entry_point_status"] == "hypothesis"
    assert chain["entry_point"] == "p-1"
    assert chain["entry_point_reason"]


def test_entry_point_is_undetermined_when_there_is_nothing_to_infer_it_from() -> None:
    """Первое событие дела точкой входа не является — оно просто первое по времени."""
    chain = reconstruct_attack_chain([_event("e-1", host="ws-1")])

    assert chain["entry_point_status"] == "undetermined"
    assert chain["entry_point"] == ""


def test_a_step_keeps_every_event_that_supports_it() -> None:
    """Одно ребро может наблюдаться много раз: по одному event_id его не проверить."""
    chain = reconstruct_attack_chain([
        _event("e-1", minute=0, src="10.0.0.1", dst="10.0.0.2"),
        _event("e-2", minute=1, src="10.0.0.1", dst="10.0.0.2"),
    ])

    assert len(chain["steps"]) == 1
    assert chain["steps"][0]["event_ids"] == ["e-1", "e-2"]


def test_the_chain_names_the_span_of_available_history() -> None:
    """Вывод сделан в границах дела: за их пределами реконструкция ничего не знает."""
    chain = reconstruct_attack_chain([
        _event("e-1", minute=0, host="ws-1"),
        _event("e-2", minute=30, host="ws-1"),
    ])

    assert chain["history"]["from"] == (START).isoformat()
    assert chain["history"]["to"] == (START + timedelta(minutes=30)).isoformat()
    assert chain["history"]["events"] == 2


def test_current_state_is_not_declared_from_the_last_step() -> None:
    """Последний шаг — последнее наблюдение, а не текущее присутствие злоумышленника."""
    chain = reconstruct_attack_chain([
        _event("e-1", minute=0, src="10.0.0.1", dst="10.0.0.2"),
    ])

    assert chain["last_observed"]["value"] == "10.0.0.2"
    assert chain["last_observed"]["observed_at"] == START.isoformat()


def test_reconstruction_is_deterministic() -> None:
    events = [
        _event("e-2", minute=1, operation="PROCESS_CREATE", process="p-2", parent="p-1", host="ws-1"),
        _event("e-1", minute=0, operation="PROCESS_CREATE", process="p-1", host="ws-1"),
    ]

    first = reconstruct_attack_chain(events)
    second = reconstruct_attack_chain(events)

    assert first == second
