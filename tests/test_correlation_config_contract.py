"""Контракт боевой конфигурации корреляции и разбора её правил.

Правила корреляции живут в `config/risk_weights.yaml`, а разбор молча отбрасывает правило,
которое не удалось прочитать. Это удобно на приёме и опасно в поставке: опечатка в имени
класса источника выключила бы SOC-корреляцию целиком, и прогон остался бы зелёным.

Отсюда две группы проверок: разбор (что именно считается непригодным правилом) и боевая
конфигурация (что мы поставляем и почему именно это).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.domain.engines.alert_fatigue import correlation_fingerprints, correlation_rules_from_config
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.security.sha256_hasher import Sha256HasherAdapter

CONFIG = Path(__file__).resolve().parent.parent / "config" / "risk_weights.yaml"
HASHER = Sha256HasherAdapter()

# Классы источников промышленного контура: ключом слияния для них остаются актив и операция,
# правила SOC-корреляции их не касаются.
INDUSTRIAL_SOURCES = frozenset({"plc_polling", "auth_logs", "service_desk"})


def _event(source: EventSource, *, host: str = "ws-1", user: str | None = None,
           dst: str | None = None, at: datetime | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e-1",
        observed_at=at or datetime(2026, 8, 17, 6, 0, tzinfo=UTC),
        source=source,
        protocol="test",
        operation="OBSERVED",
        payload_size=1,
        payload={},
        entities=EventEntities(host_id=host, user_id=user, dst_address=dst),
        artifacts=(EventArtifact(ArtifactType.HASH, "abc"),),
    )


# --------------------------------------------------------------------------- #
# Боевая конфигурация
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def shipped() -> dict:
    return load_risk_weights(CONFIG)


def test_soc_correlation_is_enabled_in_shipped_config(shipped) -> None:
    """Режим `legacy` означал, что правила корреляции не применяются вовсе."""
    assert str(shipped["correlation"]["mode"]).strip().lower() != "legacy"


def test_every_shipped_rule_is_parsed(shipped) -> None:
    """Ни одно правило не отброшено разбором: иначе корреляция тихо ослабла бы."""
    declared = shipped["correlation"]["keys"]
    parsed = correlation_rules_from_config(shipped["correlation"])
    assert len(parsed) == len(declared), (
        "разбор отбросил правила: " f"{ {row['name'] for row in declared} - {rule.name for rule in parsed} }"
    )


def test_shipped_rules_never_reach_the_industrial_pipeline(shipped) -> None:
    """Область применения правил задана явно и не включает промышленный контур."""
    for rule in correlation_rules_from_config(shipped["correlation"]):
        assert rule.sources, f"правило {rule.name} без области применения — оно попадёт на все источники"
        assert INDUSTRIAL_SOURCES.isdisjoint(rule.sources), f"правило {rule.name} задевает {rule.sources}"


def test_plc_polling_event_gets_no_correlation_keys(shipped) -> None:
    """Событие опроса ПЛК остаётся на ключе подавления шума, как и до включения корреляции."""
    rules = correlation_rules_from_config(shipped["correlation"])
    event = _event(EventSource.PLC_POLLING, user="operator", dst="plc-01")
    assert correlation_fingerprints(event, rules, hasher=HASHER) == []


def test_soc_event_gets_correlation_keys(shipped) -> None:
    rules = correlation_rules_from_config(shipped["correlation"])
    event = _event(EventSource.EDR, user="smirnov", dst="10.0.0.1")
    assert correlation_fingerprints(event, rules, hasher=HASHER)


# --------------------------------------------------------------------------- #
# Разбор правил
# --------------------------------------------------------------------------- #

def test_unknown_source_discards_the_rule_instead_of_widening_it() -> None:
    """Опечатка в классе источника не должна означать «правило для всех источников»."""
    parsed = correlation_rules_from_config(
        {"keys": [{"name": "typo", "fields": ["host_id"], "sources": ["edr", "edrr"]}]}
    )
    assert parsed == ()


def test_missing_sources_means_every_source() -> None:
    parsed = correlation_rules_from_config({"keys": [{"name": "all", "fields": ["host_id"]}]})
    assert parsed[0].sources == ()


def test_unknown_window_discards_the_rule() -> None:
    parsed = correlation_rules_from_config(
        {"keys": [{"name": "bad", "fields": ["host_id"], "bucket_sec": 60, "window": "rolling"}]}
    )
    assert parsed == ()


def test_calendar_window_gives_one_key_sliding_gives_two() -> None:
    """Скользящее окно снимает календарную границу: событие принадлежит и предыдущему окну."""
    calendar = correlation_rules_from_config(
        {"keys": [{"name": "host", "fields": ["host_id"], "bucket_sec": 600}]}
    )
    sliding = correlation_rules_from_config(
        {"keys": [{"name": "host", "fields": ["host_id"], "bucket_sec": 600, "window": "sliding"}]}
    )
    event = _event(EventSource.EDR)
    assert len(correlation_fingerprints(event, calendar, hasher=HASHER)) == 1
    assert len(correlation_fingerprints(event, sliding, hasher=HASHER)) == 2


def test_sliding_window_links_events_across_the_window_boundary() -> None:
    """Два события в двух минутах друг от друга не расходятся из-за ровной отметки времени."""
    rules = correlation_rules_from_config(
        {"keys": [{"name": "host", "fields": ["host_id"], "bucket_sec": 600, "window": "sliding"}]}
    )
    before = _event(EventSource.EDR, at=datetime(2026, 8, 17, 6, 9, tzinfo=UTC))
    after = _event(EventSource.EDR, at=datetime(2026, 8, 17, 6, 11, tzinfo=UTC))
    assert set(correlation_fingerprints(before, rules, hasher=HASHER)) & set(
        correlation_fingerprints(after, rules, hasher=HASHER)
    )


def test_calendar_window_splits_the_same_pair() -> None:
    """Тот же случай на календарном окне — граница разводит события по разным ключам."""
    rules = correlation_rules_from_config(
        {"keys": [{"name": "host", "fields": ["host_id"], "bucket_sec": 600}]}
    )
    before = _event(EventSource.EDR, at=datetime(2026, 8, 17, 6, 9, tzinfo=UTC))
    after = _event(EventSource.EDR, at=datetime(2026, 8, 17, 6, 11, tzinfo=UTC))
    assert not set(correlation_fingerprints(before, rules, hasher=HASHER)) & set(
        correlation_fingerprints(after, rules, hasher=HASHER)
    )
