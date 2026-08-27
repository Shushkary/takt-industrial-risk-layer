"""Перевод классификаций стенда PT в фазы цепочки атаки.

Стенд PT фазу не передаёт: в схемах PT NAD (`nad_table_schemas.json`, 38 таблиц) колонки для
неё нет, а PT SIEM классифицирует инцидент категорией (`incident.category`, 34 значения в
таксономии сборки 27.0.859). Без перевода вкладка «Симуляция» на данных стенда пуста —
цепочка строится только из событий с разметкой фазы.

Здесь закреплено и то, что переводится, и — так же явно — **то, что переводиться не должно**.
Второе важнее: приписав фазу каждой категории, легко получить полную красивую цепочку на
витрине и ложные шаги в доказательном пакете. Тот же принцип, что в
[`test_ait_ads_source_mapping.py`](test_ait_ads_source_mapping.py) для вердиктов AIT-ADS.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takt.domain.entities.kill_chain import (
    PHASE_FIELD,
    PHASE_ORIGIN_FIELD,
    PHASE_REASON_FIELD,
    KillChainPhase,
)
from takt.infrastructure.config.source_phase_map_yaml import (
    default_source_phase_map_path,
    load_source_phase_map,
)
from takt.infrastructure.importers.source_phase import annotate_phase

_MAP = load_source_phase_map(default_source_phase_map_path())


@pytest.mark.parametrize(
    ("category", "phase"),
    [
        ("NetworkScan", KillChainPhase.RECON),
        ("BruteForce", KillChainPhase.INITIAL_ACCESS),
        ("Phishing", KillChainPhase.INITIAL_ACCESS),
        ("SecurityPerimeterBreach", KillChainPhase.INITIAL_ACCESS),
        ("BotNetCC", KillChainPhase.C2),
        ("BotNetNode", KillChainPhase.C2),
        ("SecurityBackdoorDetection", KillChainPhase.PERSISTENCE),
        ("DataLeakage", KillChainPhase.EXFILTRATION),
        ("DOSAttack", KillChainPhase.IMPACT),
        ("DoSDDoS", KillChainPhase.IMPACT),
        ("UnauthorizedDataChange", KillChainPhase.IMPACT),
        ("UnauthorizedDataDeletion", KillChainPhase.IMPACT),
    ],
)
def test_declared_category_translates_to_its_phase(category: str, phase: KillChainPhase) -> None:
    found = _MAP.phase_for_category(category)
    assert found is not None, category
    assert found[0] is phase


@pytest.mark.parametrize(
    "category",
    [
        # Наличие инструмента не говорит, запускали ли его и на каком шаге.
        "HackToolsDetection",
        # Компрометация — состояние, а не шаг цепочки.
        "HostOrSoftCompromising",
        # Обращение к вредоносному ресурсу бывает и доставкой, и управляющим каналом.
        "MaliciousResources",
        # Обход средств защиты отдельной фазы в модели ТАКТ не имеет.
        "ProtectionBypassing",
        # Нарушение прав ≠ эскалация привилегий.
        "PermissionViolation",
        # Уязвимость — свойство актива.
        "CriticalVulnerabilityDetection",
        # Эксплуатационные сбои атакой не являются.
        "ServiceMalfunction",
        "SoftwareMalfunction",
        "BackupMalfunction",
        "ProtectionMalfunction",
        # Организационные несоответствия.
        "PatchPolicyViolation",
        "SoftwareInstallationPolicyViolation",
        "ForbiddenServiceUsage",
        "Spam",
        "SoftwareSuspiciousActivity",
        # Находка антивируса — образец, а не состоявшийся запуск.
        "VirusDetection",
        "TrojanHorseDetection",
        "WormDetection",
        # Эксплуатация уязвимости в ATT&CK живёт в трёх тактиках сразу.
        "VulnerabilityExploitation",
        "UnauthorizedAccess",
        "UserCompromising",
        "Undefined",
    ],
)
def test_ambiguous_category_gets_no_phase(category: str) -> None:
    """Неоднозначная категория оставляет событие без фазы — и с объявленной причиной."""
    assert _MAP.phase_for_category(category) is None, category
    assert category in _MAP.refused, f"категория без объяснения отказа: {category}"


def test_every_mapped_category_exists_in_the_stand_taxonomy() -> None:
    """Переводится только то, что стенд действительно объявляет.

    Таксономия лежит вне репозитория (данные заказчика), поэтому при её отсутствии проверка
    пропускается: перечень значений закреплён в самом файле сопоставления.
    """
    taxonomy = Path(r"E:\TAKT\TAKT PT\Stend_PT\taxonomy.json")
    if not taxonomy.is_file():
        pytest.skip("таксономия стенда недоступна на этой машине")
    declared = set(json.loads(taxonomy.read_text(encoding="utf-8"))["incident.category"]["enum"])
    covered = set(_MAP.by_category) | set(_MAP.refused)

    unknown = sorted(covered - declared)
    assert not unknown, f"категорий нет в таксономии стенда: {unknown}"

    # Обратная сторона: категория без решения — это молчаливый отказ, который никто не
    # принимал. Событие с ней просто не попадёт в цепочку, и понять почему будет негде.
    undecided = sorted(declared - covered)
    assert not undecided, f"категории стенда без решения: {undecided}"


def test_source_markup_wins_over_translation() -> None:
    """Фаза от источника не перезаписывается переводом категории.

    Событие, где фазу назвал сам источник, — более сильное утверждение, чем вывод из
    классификации, и подменять его нельзя.
    """
    payload = annotate_phase({"attack_phase": "recon", "incident.category": "DataLeakage"})

    assert payload[PHASE_FIELD] == "recon"
    assert PHASE_ORIGIN_FIELD not in payload


def test_translated_phase_carries_its_origin() -> None:
    """Выведенная фаза всегда несёт, откуда она взялась и на каком основании."""
    payload = annotate_phase({"incident": {"category": "NetworkScan"}})

    assert payload[PHASE_FIELD] == "recon"
    assert payload[PHASE_ORIGIN_FIELD] == "incident.category=NetworkScan"
    assert "разведк" in payload[PHASE_REASON_FIELD].lower()


def test_unknown_category_leaves_the_event_without_phase() -> None:
    """Незнакомая категория не даёт фазы: продукт не додумывает за источник."""
    payload = annotate_phase({"incident.category": "SomethingBrandNew"})

    assert PHASE_FIELD not in payload
    assert PHASE_ORIGIN_FIELD not in payload


def test_mapping_reasons_are_stated_for_every_row() -> None:
    """Каждая строка перевода объяснена: таблицу показывают при сертификации."""
    for category, (_phase, reason) in _MAP.by_category.items():
        assert len(reason.strip()) >= 20, category
    for category, reason in _MAP.refused.items():
        assert len(reason.strip()) >= 20, category
