"""Сопоставление вердиктов вышестоящей автоматики с инвариантами ТАКТ.

Прецедент: предикаты искали промышленные поля (`asset_id`, `function_code`, флаг
`lateral_movement` в payload), которых в событиях SOC нет. На демонстрационной фикстуре
INC-002 из 1030 событий не срабатывал ни один SOC-инвариант: все 122 кейса получали
одинаковый LOW по единственному нерелевантному `new_node_airgap`.

ТАКТ разбирает инцидент после средств обнаружения: NDR отдаёт `verdict`, SIEM — `rule_name`,
импортёры кладут их в `operation`. Какой вердикт означает какой инвариант — объявляется в
`config/invariants/<id>.yaml` полем `params.source_operations`, а не зашивается в предикат.

Смежное: `tests/test_invariant_catalog_yaml.py` (схема каталога),
`docs/risk_scale_calibration.md` (почему балл всё равно не доходит до HIGH).
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import InvariantId
from takt.domain.invariants.rule_predicates import PREDICATE_REGISTRY
from takt.domain.invariants.rule_spec import InvariantRuleSpec
from takt.infrastructure.config.invariant_catalog_yaml import load_invariant_catalog_from_dir

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_DIR = _REPO_ROOT / "config" / "invariants"


def _event(operation: str, *, payload: dict | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e-1",
        observed_at=datetime(2026, 8, 17, 6, 0, tzinfo=UTC),
        source=EventSource.NDR,
        protocol="tcp",
        operation=operation,
        payload_size=10,
        payload=payload or {},
    )


def _spec(invariant_id: str, operations: list[str] | None = None) -> InvariantRuleSpec:
    params = {"source_operations": operations} if operations is not None else {}
    return InvariantRuleSpec(
        id=invariant_id,
        block_key="topology",
        context_window_events=5,
        experimental=False,
        params=params,
        predicate_ref=f"builtin:{invariant_id}",
        inputs=(),
        severity_curve=None,
    )


def _fires(invariant_id: str, operation: str, operations: list[str] | None) -> bool:
    predicate = PREDICATE_REGISTRY[invariant_id]
    spec = _spec(invariant_id, operations)
    return bool(predicate(_event(operation), [], _Ctx(), spec))


class _Ctx:
    """Контекст предикатов: для проверяемых правил значимых полей нет."""

    allowed_function_codes = None
    iec104_disallowed_type_ids = ()
    protocol_tier = None
    auth_fail_window = 20
    auth_fail_threshold = 5


@pytest.mark.parametrize(
    ("invariant_id", "operation"),
    [
        (InvariantId.C2_EXTERNAL_DNS.value, "C2_SUSPECT"),
        (InvariantId.C2_EXTERNAL_DNS.value, "SUSPICIOUS_OUTBOUND"),
        (InvariantId.LATERAL_MOVEMENT.value, "LATERAL_SUSPECT"),
        (InvariantId.LATERAL_MOVEMENT.value, "REMOTE_EXEC_WMI"),
        (InvariantId.RECONNAISSANCE.value, "SCAN_SUSPECT"),
        (InvariantId.OUT_OF_SHIFT_ACCESS.value, "CODE_REPO_WRITE_OFFHOURS"),
    ],
)
def test_declared_verdict_fires_invariant(invariant_id: str, operation: str) -> None:
    """Вердикт, объявленный в каталоге, поднимает соответствующий инвариант."""
    catalog = load_invariant_catalog_from_dir(_CATALOG_DIR)
    declared = next(r for r in catalog.records if r.id == invariant_id)
    assert operation in [item.upper() for item in declared.params.get("source_operations", [])], (
        f"{operation} не объявлен в config/invariants/{invariant_id}.yaml"
    )
    assert _fires(invariant_id, operation, list(declared.params["source_operations"]))


def test_unrelated_verdict_does_not_fire() -> None:
    """Фоновые операции не поднимают инвариант: сопоставление точное, не по подстроке."""
    for operation in ("ALLOWED", "LOGON_SUCCESS", "PROCESS_START", "BUILD_OK", "POLL"):
        assert not _fires(InvariantId.C2_EXTERNAL_DNS.value, operation, ["C2_SUSPECT"])
        assert not _fires(InvariantId.LATERAL_MOVEMENT.value, operation, ["LATERAL_SUSPECT"])


def test_mapping_is_case_insensitive_and_trimmed() -> None:
    assert _fires(InvariantId.RECONNAISSANCE.value, "SCAN_SUSPECT", ["  scan_suspect  "])


def test_existing_industrial_behaviour_is_preserved() -> None:
    """Прежние признаки продолжают работать и без объявленных вердиктов."""
    # Блоклист доменов C2.
    assert _fires(InvariantId.C2_EXTERNAL_DNS.value, "ANY", None) is False
    predicate = PREDICATE_REGISTRY[InvariantId.C2_EXTERNAL_DNS.value]
    spec = _spec(InvariantId.C2_EXTERNAL_DNS.value)
    assert predicate(_event("ANY", payload={"dns_query": "panel.onion"}), [], _Ctx(), spec)
    # Флаг от внешнего SIEM.
    predicate = PREDICATE_REGISTRY[InvariantId.LATERAL_MOVEMENT.value]
    spec = _spec(InvariantId.LATERAL_MOVEMENT.value)
    assert predicate(_event("ANY", payload={"lateral_movement": True}), [], _Ctx(), spec)
    # Подстроки операций разведки.
    assert _fires(InvariantId.RECONNAISSANCE.value, "PORT_SCAN_TCP", None)


def test_catalog_rejects_mapping_on_unrelated_invariant(tmp_path: Path) -> None:
    """Сопоставление вердиктов допустимо не для любого правила."""
    dst = tmp_path / "inv"
    shutil.copytree(_CATALOG_DIR, dst)
    target = dst / "blind_command.yaml"
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    data["params"] = {"source_operations": ["WRITE_COIL"]}
    target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="source_operations are only supported"):
        load_invariant_catalog_from_dir(dst)


@pytest.mark.parametrize("bad", [[], ["  "], [1], ["C2_SUSPECT", "c2_suspect"]])
def test_catalog_rejects_malformed_mapping(tmp_path: Path, bad: list) -> None:
    dst = tmp_path / "inv"
    shutil.copytree(_CATALOG_DIR, dst)
    target = dst / "reconnaissance.yaml"
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    data["params"] = {"source_operations": bad}
    target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError):
        load_invariant_catalog_from_dir(dst)


def test_repository_catalog_declares_soc_verdicts() -> None:
    """В поставляемом каталоге сопоставление есть — иначе поток SOC снова станет невидимым."""
    catalog = load_invariant_catalog_from_dir(_CATALOG_DIR)
    mapped = {
        r.id: [item.upper() for item in r.params.get("source_operations", [])]
        for r in catalog.records
        if r.params.get("source_operations")
    }
    assert set(mapped) == {
        InvariantId.C2_EXTERNAL_DNS.value,
        InvariantId.LATERAL_MOVEMENT.value,
        InvariantId.RECONNAISSANCE.value,
        InvariantId.OUT_OF_SHIFT_ACCESS.value,
    }
    assert "C2_SUSPECT" in mapped[InvariantId.C2_EXTERNAL_DNS.value]


def test_protocol_escalation_needs_both_protocols_known() -> None:
    """Неизвестный протокол не считается низшим уровнем.

    Прежде `tiers.get(proto, 0)` давал неизвестному протоколу уровень 0, и обычная
    последовательность потоков DNS -> HTTPS на одном узле читалась как эскалация: на
    корпусе Netflow срабатывание получал штатный трафик.
    """
    predicate = PREDICATE_REGISTRY[InvariantId.PROTOCOL_ESCALATION.value]
    spec = _spec(InvariantId.PROTOCOL_ESCALATION.value)

    def flow(protocol: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=f"e-{protocol}",
            observed_at=datetime(2026, 8, 17, 6, 0, tzinfo=UTC),
            source=EventSource.NETWORK,
            protocol=protocol,
            operation="ALLOWED",
            payload_size=10,
            payload={"asset_id": "ws-17"},
        )

    # DNS в таблице уровней отсутствует — сравнивать не с чем.
    assert predicate(flow("HTTPS"), [flow("DNS")], _Ctx(), spec) == []
    # Оба протокола известны и разрыв больше одного уровня — срабатывание остаётся.
    assert predicate(flow("SMB"), [flow("MODBUS")], _Ctx(), spec) == [spec.id]
