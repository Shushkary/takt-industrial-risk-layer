"""Сопоставление вердиктов AIT-ADS с инвариантами ТАКТ.

Внешний корпус EXT-001 (AIT-ADS, сценарий `shaw`) грузился в продукт и не давал ни одного
срабатывания: предикаты SOC-инвариантов работают по объявленным вердиктам средств обнаружения
(`params.source_operations` в `config/invariants/<id>.yaml`), а имена правил AMiner и Wazuh там
объявлены не были. Все дела получали одинаковый низкий риск — тот же прецедент, что описан в
[`test_source_verdict_mapping.py`](test_source_verdict_mapping.py) для INC-002.

Здесь закреплено и то, что теперь срабатывает, и — так же явно — **то, что срабатывать не
должно**. Второе важнее: соблазн объявить вердиктом разведки любую ошибку 400 веб-сервера даёт
красивую витрину и поток ложных срабатываний, то есть ровно то, от чего продукт обещает избавить.

Основание сопоставления — разметка авторов корпуса (техника MITRE у каждого события), а не наше
толкование имени правила. Взяты только вердикты, чьё имя означает то же самое вне этого датасета.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.evaluator import collect_extended_invariants
from takt.infrastructure.config.invariant_catalog_yaml import (
    catalog_rule_specs,
    load_invariant_catalog_from_dir,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_DIR = _REPO_ROOT / "config" / "invariants"
_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "pt_techlab" / "ext_001"


@pytest.fixture(scope="module")
def rule_specs():
    return catalog_rule_specs(load_invariant_catalog_from_dir(_CATALOG_DIR))


def _event(operation: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e-1",
        observed_at=datetime(2026, 8, 21, 9, 0, tzinfo=UTC),
        source=EventSource.SIEM,
        protocol="tcp",
        operation=operation,
        payload_size=64,
        payload={},
    )


def _hits(operation: str, rule_specs) -> frozenset[str]:
    return frozenset(collect_extended_invariants(_event(operation), [], None, rule_specs=rule_specs))


@pytest.mark.parametrize(
    ("operation", "invariant"),
    [
        ("INSECURE_CONNECTION_ATTEMPT_SCAN", InvariantId.RECONNAISSANCE.value),
        ("MULTIPLE_WEB_SERVER_400_ERROR_CODES_FROM_SAME_SOURCE_IP", InvariantId.RECONNAISSANCE.value),
        ("ATTEMPT_TO_ACCESS_FORBIDDEN_DIRECTORY_INDEX", InvariantId.RECONNAISSANCE.value),
        ("NEW_CHARACTERS_IN_DNS_DOMAIN", InvariantId.C2_EXTERNAL_DNS.value),
    ],
)
def test_declared_verdict_fires_its_invariant(operation: str, invariant: str, rule_specs) -> None:
    assert invariant in _hits(operation, rule_specs), operation


@pytest.mark.parametrize(
    "operation",
    [
        # Одиночная 400 — рутина веб-сервера. В EXT-001 таких 32: объявив их разведкой,
        # мы получили бы витрину из ложных срабатываний.
        "WEB_SERVER_400_ERROR_CODE",
        # Новый адрес в журнале DNS — обычное дело при смене хостинга; 35 событий в EXT-001.
        "NEW_IP_ADDRESS_IN_DNS_LOGS",
        # Успешная аутентификация несёт в корпусе три разные техники в разных фазах:
        # само по себе имя операции не значит ничего конкретного.
        "DOVECOT_AUTHENTICATION_SUCCESS",
        # Родовое имя события IDS: в другом датасете за ним может стоять что угодно.
        "IDS_EVENT",
    ],
)
def test_ambiguous_verdict_fires_nothing(operation: str, rule_specs) -> None:
    assert _hits(operation, rule_specs) == frozenset(), operation


def test_mapping_actually_fires_on_the_external_corpus(rule_specs) -> None:
    """Проверка на самом корпусе: сопоставление не должно остаться теорией.

    Читаются те же файлы, что грузятся в продукт. Если конвертер или корпус изменятся так,
    что срабатываний не станет, тест это покажет.
    """
    fired: set[str] = set()
    for name, column in (("edr.csv", "event_type"), ("siem.csv", "rule_name")):
        path = _FIXTURE / name
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                fired |= _hits(row[column], rule_specs)

    assert InvariantId.RECONNAISSANCE.value in fired
    assert InvariantId.C2_EXTERNAL_DNS.value in fired


def test_fixture_is_present() -> None:
    """Фикстура — производная внешнего корпуса и хранится в репозитории целиком."""
    assert (_FIXTURE / "edr.csv").is_file()
    assert (_FIXTURE / "siem.csv").is_file()
    assert (_FIXTURE / "README_EXT-001.md").is_file()
