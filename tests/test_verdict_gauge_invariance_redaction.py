"""T1. Калибровочная инвариантность вердикта к маскированию секретов.

`REDACTED_FIELD_NAMES` (`takt.infrastructure.importers.redaction`) — перечень полей, значения
которых не несут доказательной нагрузки: пароли, ключи сессий, cookie и материал SNMP,
восстановленные из трафика. Они маскируются коннектором до записи в `payload`, то есть до
хранилища дел, доказательного пакета и экспорта.

Отсюда требование: маскирование — калибровочная степень свободы процедуры, и вердикт обязан
быть относительно неё неподвижен.

    verdict(bundle) == verdict(redact(bundle))

Что именно сравнивается — см. `verdict_fingerprint` в `tests/conftest_variational.py`: класс и
балл риска, сработавшие инварианты, объяснение, качество данных. Идентификатор дела и отметка
создания исключены: их выдают порты, и они меняются между прогонами по определению.

Падение этого теста означает одно из двух, и оба чинятся не здесь: либо поле ошибочно отнесено
к `REDACTED_FIELD_NAMES` (оно доказательное, маскировать его нельзя), либо доменная логика
читает то, чего читать не должна. По регламенту задачи домен в обоих случаях не правится, а
конкретное поле выносится в отчёт.

Смежные сторожи: `tests/test_verdict_determinism_guard.py` (источник недетерминизма на уровне
импортов), `tests/test_domain_ast_policy.py` (время и uuid в домене).
"""

from __future__ import annotations

import pytest
from conftest_variational import GUARD_WEIGHTS, Scenario, scenarios, verdict_fingerprint

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.domain.entities.event import NormalizedEvent
from takt.infrastructure.importers.redaction import (
    REDACTED_FIELD_NAMES,
    REDACTED_MARKER,
    redact,
)


def _redacted_event(event: NormalizedEvent) -> NormalizedEvent:
    """Копия события с замаскированной полезной нагрузкой — как её записал бы коннектор."""
    return NormalizedEvent(
        event_id=event.event_id,
        observed_at=event.observed_at,
        source=event.source,
        protocol=event.protocol,
        operation=event.operation,
        payload_size=event.payload_size,
        payload=redact(dict(event.payload)),
    )


def _assess(scenario: Scenario, *, redacted: bool) -> dict[str, object]:
    use_case = AssessRiskUseCase(GUARD_WEIGHTS, plc_hosts=scenario.plc_hosts)
    event = _redacted_event(scenario.event) if redacted else scenario.event
    recent = [_redacted_event(e) for e in scenario.recent_events] if redacted else list(scenario.recent_events)
    result = use_case.execute(
        event,
        recent_events=recent,
        tickets=list(scenario.tickets),
        graph_edges=list(scenario.graph_edges),
        polling_intervals_us=scenario.polling_intervals_us,
        # Время подаётся явно и одинаково в обоих прогонах: здесь проверяется симметрия по
        # маскированию, а независимость от часов — предмет отдельного гварда (T3).
        clock=scenario.event.observed_at,
    )
    return verdict_fingerprint(result)


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
def test_verdict_is_invariant_under_redaction(scenario: Scenario) -> None:
    """Вердикт по замаскированному входу совпадает с вердиктом по исходному."""
    assert _assess(scenario, redacted=False) == _assess(scenario, redacted=True)


def test_corpus_actually_carries_secrets() -> None:
    """Страховка от вырождения: гвард бессмыслен, если маскировать в корпусе нечего.

    Без этой проверки удаление секретов из фикстур превратило бы T1 в сравнение входа с самим
    собой — тест остался бы зелёным, перестав что-либо проверять.
    """
    carrying = [
        s.name
        for s in scenarios()
        if REDACTED_FIELD_NAMES & set(s.event.payload)
    ]
    assert len(carrying) == len(scenarios()), (
        "в каждом сценарии корпуса должно быть хотя бы одно поле из REDACTED_FIELD_NAMES; "
        f"несут секреты только: {carrying}"
    )


def test_redaction_actually_changes_the_payload() -> None:
    """Вторая страховка: `redact` обязан менять нагрузку, иначе сравнение снова тождественно."""
    for scenario in scenarios():
        before = dict(scenario.event.payload)
        after = redact(before)
        assert after != before, f"{scenario.name}: маскирование ничего не изменило"
        assert REDACTED_MARKER in after.values(), f"{scenario.name}: маркер маскирования не проставлен"


def test_bundle_checksum_is_allowed_to_differ_after_redaction() -> None:
    """Агрегатное контрольное значение — не инвариант этой симметрии, и это осознанно.

    Замаскированный пакет физически другой: в нём вместо секрета стоит маркер. Контрольное
    значение обязано это отражать, иначе оно перестало бы удостоверять содержимое. Инвариантен
    здесь вердикт, а не байты пакета; неизменность контрольного значения проверяется по другой
    симметрии — независимости от момента выгрузки
    (`tests/test_forensic_bundle.py::test_root_hash_does_not_depend_on_the_moment_of_generation`).

    Тест закрепляет это различие явно, чтобы оно не выглядело недосмотром.
    """
    scenario = scenarios()[0]
    original = dict(scenario.event.payload)
    assert redact(original) != original
