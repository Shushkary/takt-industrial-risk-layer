from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.invariants.catalog import INVARIANT_RECORDS, InvariantId
from takt.domain.invariants.evaluator import InvariantContext, InvariantRuleOverrides, collect_extended_invariants
from takt.domain.invariants.rule_spec import InvariantRuleSpec, default_predicate_builtin_ref
from takt.infrastructure.config.invariant_catalog_yaml import (
    catalog_experimental_invariant_ids,
    catalog_rule_overrides,
    expected_yaml_blobs_from_domain_catalog,
    load_invariant_catalog_from_dir,
)


def test_repo_invariant_yaml_dir_loads() -> None:
    project_root = Path(__file__).resolve().parents[1]
    cat = load_invariant_catalog_from_dir(project_root / "config" / "invariants")
    assert len(cat.records) == len(InvariantId)
    assert cat.max_context_window_events() == 24


def test_expected_blobs_match_record_count() -> None:
    blobs = expected_yaml_blobs_from_domain_catalog()
    assert len(blobs) == len(INVARIANT_RECORDS)
    for r in INVARIANT_RECORDS:
        assert f"{r.id}.yaml" in blobs


def test_loader_rejects_unknown_id(tmp_path: Path) -> None:
    bad = tmp_path / "evil.yaml"
    bad.write_text(
        "id: not_a_real_invariant\n"
        "block_key: x\n"
        'block_label_ru: ""\n'
        'title_ru: ""\n'
        "context_window_events: 5\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown invariant id"):
        load_invariant_catalog_from_dir(tmp_path)


def test_loader_rejects_params_on_non_brute(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    dst = tmp_path / "inv"
    shutil.copytree(project_root / "config" / "invariants", dst)
    blind = dst / "blind_command.yaml"
    data = yaml.safe_load(blind.read_text(encoding="utf-8"))
    data["params"] = {"auth_fail_threshold": 2}
    blind.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="only supported for brute_force"):
        load_invariant_catalog_from_dir(dst)


def _fail_ev(eid: str, n: int) -> NormalizedEvent:
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    return NormalizedEvent(
        event_id=eid,
        observed_at=t0,
        source=EventSource.PLC_POLLING,
        protocol="MODBUS",
        operation=f"LOGIN_FAIL_{n}",
        payload_size=1,
        payload={"asset_id": "plc-z"},
    )


def test_brute_force_context_window_slices_recent_for_predicate(tmp_path: Path) -> None:
    """`context_window_events` обрезает хвост `recent` до оценки brute_force."""
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def _ev(eid: str, op: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=eid,
            observed_at=t0,
            source=EventSource.PLC_POLLING,
            protocol="MODBUS",
            operation=op,
            payload_size=1,
            payload={"asset_id": "plc-z"},
        )

    ev = _ev("cur", "LOGIN_FAIL")
    long_recent = [_ev(f"p{i}", "LOGIN_FAIL") for i in range(10)]
    # «Старые» фейлы + два нефейла у конца: в окне из 2 событий хвоста не хватает до порога 3
    recent = [*long_recent[:8], _ev("ok1", "OK"), _ev("ok2", "OK")]
    spec = InvariantRuleSpec(
        id=InvariantId.BRUTE_FORCE.value,
        block_key="identity",
        context_window_events=2,
        experimental=False,
        params={},
        predicate_ref=default_predicate_builtin_ref(InvariantId.BRUTE_FORCE.value),
        inputs=(),
        severity_curve=None,
    )
    ctx = InvariantContext(auth_fail_window=50, auth_fail_threshold=3)
    assert InvariantId.BRUTE_FORCE.value not in collect_extended_invariants(
        ev,
        recent,
        ctx,
        rule_specs=(spec,),
    )
    # То же окно, но последние два события снова фейлы — в срезе 2+текущее даёт 3 фейла
    recent2 = [*long_recent[:8], _ev("f1", "LOGIN_FAIL"), _ev("f2", "LOGIN_FAIL")]
    assert InvariantId.BRUTE_FORCE.value in collect_extended_invariants(
        ev,
        recent2,
        ctx,
        rule_specs=(spec,),
    )


def test_brute_force_auth_fail_threshold_in_yaml_changes_detection(tmp_path: Path) -> None:
    """Порог из `config/invariants/brute_force.yaml` меняет срабатывание без правки Python."""
    project_root = Path(__file__).resolve().parents[1]
    dst = tmp_path / "inv"
    shutil.copytree(project_root / "config" / "invariants", dst)
    bf = dst / "brute_force.yaml"
    data = yaml.safe_load(bf.read_text(encoding="utf-8"))
    data["params"] = {"auth_fail_threshold": 2}
    bf.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    cat = load_invariant_catalog_from_dir(dst)
    ovr = catalog_rule_overrides(cat)
    assert ovr.brute_force_auth_fail_threshold == 2

    recent = [_fail_ev("r1", 1), _fail_ev("r2", 2)]
    ev = _fail_ev("w1", 3)
    ctx = InvariantContext(auth_fail_threshold=5)
    assert InvariantId.BRUTE_FORCE.value in collect_extended_invariants(ev, recent, ctx, rule_overrides=ovr)
    assert InvariantId.BRUTE_FORCE.value not in collect_extended_invariants(ev, recent, ctx, rule_overrides=None)
    assert InvariantId.BRUTE_FORCE.value not in collect_extended_invariants(
        ev,
        recent,
        ctx,
        rule_overrides=InvariantRuleOverrides(),
    )


def test_catalog_experimental_invariant_ids_from_yaml(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    dst = tmp_path / "inv"
    shutil.copytree(project_root / "config" / "invariants", dst)
    pd = dst / "polling_period_doubling_suspect.yaml"
    data = yaml.safe_load(pd.read_text(encoding="utf-8"))
    data["experimental"] = True
    pd.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    cat = load_invariant_catalog_from_dir(dst)
    assert catalog_experimental_invariant_ids(cat) == frozenset({"polling_period_doubling_suspect"})
