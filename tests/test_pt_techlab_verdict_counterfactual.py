"""Задача 5 (PROMPT_FIX_pt_techlab.md): структурированный машиночитаемый контрфакт вердикта.

Контрфакт вердикта легитимности наряда теперь несёт те же фактические данные
в машиночитаемом виде (перечень невыполненных условий, расхождения с делом,
утверждающая сторона, допустимое окно, актив/операция/исполнитель), помимо
текстовой формы для карточки оператора. Текст собирается из структуры, а не
параллельно ей. См. prompt, Задача 5.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from takt.application.use_cases.manual_permit import (
    AttachManualPermitUseCase,
    VerdictCounterfactual,
)
from takt.domain.entities.case import Case, CaseStatus, ManualPermit
from takt.domain.engines import xai as xai_module
from takt.infrastructure.export.forensic_bundle import (
    ZipForensicBundleBuilder,
    ZipForensicBundleVerifier,
)
from takt.infrastructure.export.gossopka import case_to_gossopka_card
from takt.infrastructure.stores.sqlite_case_mapper import (
    _deserialize_manual_permits,
    _serialize_manual_permits,
)


_CT = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
_CASE_ASSET = "plc-01"
_CASE_OP = "WRITE_COIL"
_CASE_CLS = "управляющее воздействие"


def _verdict(**over: object) -> object:
    base = dict(
        case_asset=_CASE_ASSET,
        case_operation=_CASE_OP,
        case_action_class=_CASE_CLS,
        case_operator_id="",
        case_created_at=_CT,
        permit_asset=_CASE_ASSET,
        permit_operation=_CASE_OP,
        permit_action_class=_CASE_CLS,
        executor="",
        approver="",
        valid_from="2026-01-01T09:00:00+00:00",
        valid_to="2026-01-01T11:00:00+00:00",
        document_status="утверждён",
        restrictions="",
        work_order_number="WO-1",
    )
    base.update(over)
    return AttachManualPermitUseCase._verdict(**base)  # noqa: SLF001 (test hook)


def _case_with_permit(permit: ManualPermit) -> Case:
    return Case(
        case_id="cf-1",
        status=CaseStatus.TRIAGE,
        title="t",
        risk_class="HIGH",
        risk_score=0.8,
        created_at=_CT,
        normalized_event_ids=["e1"],
        burst_fingerprint="fp",
        invariant_hits=["blind_command"],
        dq_score=0.9,
        dq_partial=False,
        last_event_source="x",
        manual_permits=[permit],
    )


def test_structured_counterfactual_legitimate() -> None:
    result = _verdict(
        executor="Иванов И.И.",
        approver="Петров П.П.",
        work_order_number="WO-LEGIT",
    )
    assert result.verdict == "legitimate"
    assert result.confidence == 0.95
    cf = VerdictCounterfactual.from_dict(result.counterfactual_struct)
    assert cf.verdict == "legitimate"
    assert cf.unmet_conditions == ()
    assert cf.mismatches == ()
    assert cf.sanctioning_party == "Петров П.П."
    assert cf.admissible_window == "2026-01-01T09:00:00+00:00..2026-01-01T11:00:00+00:00"
    assert cf.required_document == "WO-LEGIT"


def test_structured_counterfactual_undetermined_org_incomplete() -> None:
    result = _verdict()  # executor/approver empty -> org context incomplete
    assert result.verdict == "undetermined"
    assert result.confidence == 0.7
    cf = VerdictCounterfactual.from_dict(result.counterfactual_struct)
    assert set(cf.unmet_conditions) == {"исполнитель", "утверждающий"}
    # Текст строится из структуры, а не параллельно ей.
    assert all(cond in result.rationale for cond in cf.unmet_conditions)
    assert all(cond in result.counterfactual for cond in cf.unmet_conditions)


def test_structured_counterfactual_illegitimate() -> None:
    result = _verdict(
        case_operator_id="op-1",
        permit_asset="plc-99",
        executor="op-1",
        approver="Петров П.П.",
        work_order_number="WO-ILL",
    )
    assert result.verdict == "illegitimate"
    assert result.confidence == 0.65
    cf = VerdictCounterfactual.from_dict(result.counterfactual_struct)
    assert len(cf.mismatches) == 1
    m = cf.mismatches[0]
    assert m["field"] == "asset"
    assert m["expected"] == "plc-01"
    assert m["actual"] == "plc-99"
    assert "актив наряда" in result.rationale


def test_counterfactual_struct_persists_round_trip() -> None:
    struct = {
        "verdict": "undetermined",
        "unmet_conditions": ["исполнитель"],
        "mismatches": [],
        "required_document": "WO-1",
        "sanctioning_party": None,
        "admissible_window": None,
        "asset": "plc-01",
        "operation": "WRITE_COIL",
        "action_class": "управляющее воздействие",
        "executor": None,
        "restrictions_present": None,
    }
    permit = ManualPermit(
        permit_id="p1",
        case_id="c1",
        work_order_number="WO-1",
        actor="actor-1",
        created_at=_CT,
        asset_id="plc-01",
        operation="WRITE_COIL",
        action_class="управляющее воздействие",
        verdict="undetermined",
        confidence=0.7,
        rationale="r",
        counterfactual="cf",
        counterfactual_struct=struct,
    )
    back = _deserialize_manual_permits(_serialize_manual_permits([permit]))
    assert back[0].counterfactual_struct == struct


def test_forensic_bundle_includes_structured_counterfactual_and_bumped_version() -> None:
    struct = {
        "verdict": "illegitimate",
        "unmet_conditions": [],
        "mismatches": [{"field": "asset", "expected": "plc-01", "actual": "plc-99"}],
        "required_document": "WO-1",
        "sanctioning_party": None,
        "admissible_window": None,
        "asset": "plc-99",
        "operation": "WRITE_COIL",
        "action_class": "управляющее воздействие",
        "executor": None,
        "restrictions_present": None,
    }
    permit = ManualPermit(
        permit_id="p1",
        case_id="cf-1",
        work_order_number="WO-1",
        actor="actor-1",
        created_at=_CT,
        asset_id="plc-99",
        operation="WRITE_COIL",
        action_class="управляющее воздействие",
        verdict="illegitimate",
        confidence=0.65,
        rationale="r",
        counterfactual="cf",
        counterfactual_struct=struct,
    )
    _meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case_with_permit(permit),
        generated_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC),
    )
    with ZipFile(BytesIO(raw)) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        case_payload = json.loads(zf.read("case.json").decode("utf-8"))
    # Задача 5: инкремент версии схемы доказательного пакета.
    assert manifest["format_version"] == "0.2"
    mp = case_payload["manual_permits"][0]
    assert mp["counterfactual_struct"]["verdict"] == "illegitimate"
    assert mp["counterfactual_struct"]["mismatches"][0]["field"] == "asset"
    # Пакет остаётся валидным.
    assert ZipForensicBundleVerifier().verify_bundle(raw).ok is True


def test_forensic_bundle_backward_compatible_with_old_format_version() -> None:
    # Ранее выпущенные пакеты (format_version "0.1") остаются валидными по своей версии:
    # верификатор не привязан к конкретной версии схемы.
    permit = ManualPermit(
        permit_id="p1",
        case_id="cf-1",
        work_order_number="WO-1",
        actor="actor-1",
        created_at=_CT,
        asset_id="plc-01",
        operation="WRITE_COIL",
        action_class="управляющее воздействие",
        verdict="legitimate",
        confidence=0.95,
        rationale="r",
        counterfactual="cf",
        counterfactual_struct={},
    )
    _meta, raw = ZipForensicBundleBuilder().build_case_bundle(
        _case_with_permit(permit),
        generated_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC),
    )
    out = BytesIO()
    with ZipFile(BytesIO(raw)) as src, ZipFile(out, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "manifest.json":
                manifest = json.loads(data.decode("utf-8"))
                manifest["format_version"] = "0.1"
                data = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            zi = ZipInfo(name)
            zi.compress_type = ZIP_DEFLATED
            dst.writestr(zi, data)
    result = ZipForensicBundleVerifier().verify_bundle(out.getvalue())
    assert result.ok is True


def test_gossopka_export_includes_structured_counterfactual() -> None:
    struct = {
        "verdict": "illegitimate",
        "unmet_conditions": [],
        "mismatches": [{"field": "asset", "expected": "plc-01", "actual": "plc-99"}],
        "required_document": "WO-1",
        "sanctioning_party": None,
        "admissible_window": None,
        "asset": "plc-99",
        "operation": "WRITE_COIL",
        "action_class": "управляющее воздействие",
        "executor": None,
        "restrictions_present": None,
    }
    permit = ManualPermit(
        permit_id="p1",
        case_id="cf-1",
        work_order_number="WO-1",
        actor="actor-1",
        created_at=_CT,
        asset_id="plc-99",
        operation="WRITE_COIL",
        action_class="управляющее воздействие",
        verdict="illegitimate",
        confidence=0.65,
        rationale="r",
        counterfactual="cf",
        counterfactual_struct=struct,
    )
    card = case_to_gossopka_card(_case_with_permit(permit), generated_at=_CT)
    mp = card["evidence"]["manual_permits"][0]
    assert "counterfactual_struct" in mp
    assert mp["counterfactual_struct"]["verdict"] == "illegitimate"


def test_minimalism_unmet_conditions_are_necessary_and_sufficient() -> None:
    # Базовый наряд: актив/операция совпадают, но нет исполнителя и утверждающего.
    base = _verdict()
    assert base.verdict == "undetermined"
    base_cf = VerdictCounterfactual.from_dict(base.counterfactual_struct)
    listed = set(base_cf.unmet_conditions)
    assert listed == {"исполнитель", "утверждающий"}

    # Достаточность: выполнение всех перечисленных условий меняет вердикт на legitimate.
    full = _verdict(executor="Иванов И.И.", approver="Петров П.П.")
    assert full.verdict == "legitimate"
    assert full.verdict != base.verdict

    # Необходимость: каждое перечисленное условие, если его убрать из полного набора,
    # возвращает вердикт в не-legitimate. Условие, выполнение которого ничего не меняет,
    # в перечне лишнее.
    for cond in listed:
        over = {"executor": "Иванов И.И.", "approver": "Петров П.П."}
        if cond == "исполнитель":
            over["executor"] = ""
        elif cond == "утверждающий":
            over["approver"] = ""
        v = _verdict(**over)
        assert v.verdict != "legitimate", f"condition {cond!r} is not load-bearing"


def test_minimalism_window_condition_is_load_bearing() -> None:
    # Окно работ вне события -> условие окна в перечне невыполненных.
    v = _verdict(
        executor="Иванов И.И.",
        approver="Петров П.П.",
        valid_from="2026-01-01T12:00:00+00:00",
        valid_to="2026-01-01T13:00:00+00:00",
    )
    assert v.verdict == "undetermined"
    cf = VerdictCounterfactual.from_dict(v.counterfactual_struct)
    assert cf.unmet_conditions  # непусто, содержит причину окна
    # Исправление окна -> legitimate.
    fixed = _verdict(
        executor="Иванов И.И.",
        approver="Петров П.П.",
        valid_from="2026-01-01T09:00:00+00:00",
        valid_to="2026-01-01T11:00:00+00:00",
    )
    assert fixed.verdict == "legitimate"


def test_verdict_counterfactual_separate_from_xai_cf_map() -> None:
    # Контрфакт ВЕРДИКТА (manual_permit) не должен сливаться с объяснением РИСКА
    # (xai._CF_MAP). Разные источники и назначения (Задача 5).
    import takt.application.use_cases.manual_permit as mp_module

    assert hasattr(xai_module, "_CF_MAP")
    assert not hasattr(mp_module, "_CF_MAP")
    assert hasattr(mp_module, "VerdictCounterfactual")
