from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from takt.domain.entities.case import Case, CaseStatus
from takt.domain.invariants.evaluator import InvariantContext, invariant_context_from_config
from takt.infrastructure.config.settings_helpers import trust_by_source_from_weights
from takt.infrastructure.export.siem_webhook import post_case_to_webhook_sync
from takt.infrastructure.security.webhook_allowlist import assert_egress_ips_allowed, require_allowed_siem_url


def test_invariant_context_iec_from_config():
    cfg = {"invariants": {"iec104_disallowed_type_ids": [9, 21]}}
    ctx = invariant_context_from_config(cfg)
    assert ctx.iec104_disallowed_type_ids == frozenset({9, 21})


def test_invariant_context_iec_empty_list_yields_none():
    cfg = {"invariants": {"iec104_disallowed_type_ids": []}}
    ctx = invariant_context_from_config(cfg)
    assert ctx.iec104_disallowed_type_ids is None


def test_invariant_context_empty_config():
    assert invariant_context_from_config(None) == InvariantContext()
    assert invariant_context_from_config({}) == InvariantContext()


def test_invariant_context_inv_not_dict():
    ctx = invariant_context_from_config({"invariants": "broken"})
    assert ctx.allowed_function_codes is None


def test_invariant_context_protocol_tiers_uppercased():
    cfg = {"invariants": {"protocol_tiers": {"modbus": 1, "SMB": 5}}}
    ctx = invariant_context_from_config(cfg)
    assert ctx.protocol_tier == {"MODBUS": 1, "SMB": 5}


def test_invariant_context_from_yaml_section():
    cfg = {
        "invariants": {
            "allowed_function_codes": ["3", "4"],
            "payload_drift_ratio": 0.3,
            "auth_fail_threshold": 3,
        }
    }
    ctx = invariant_context_from_config(cfg)
    assert isinstance(ctx, InvariantContext)
    assert ctx.allowed_function_codes == frozenset({"3", "4"})
    assert ctx.payload_drift_ratio == 0.3
    assert ctx.auth_fail_threshold == 3


def test_trust_by_source_from_config_section():
    cfg = {
        "ingest_trust": {
            "by_source": {
                "plc_polling": 1.0,
                "auth_logs": 0.92,
                "bad": "x",
            }
        }
    }
    m = trust_by_source_from_weights(cfg)
    assert m == {"plc_polling": 1.0, "auth_logs": 0.92}
    only_invalid = trust_by_source_from_weights(
        {"ingest_trust": {"by_source": {"a": object(), "b": []}}}
    )
    assert only_invalid is None
    blank_keys_only = trust_by_source_from_weights(
        {"ingest_trust": {"by_source": {"": 0.5, "  \t  ": 0.9}}}
    )
    assert blank_keys_only is None
    assert trust_by_source_from_weights({}) is None
    assert trust_by_source_from_weights({"ingest_trust": {}}) is None
    assert trust_by_source_from_weights({"ingest_trust": {"by_source": {}}}) is None


def test_webhook_loopback_default():
    require_allowed_siem_url("http://127.0.0.1:8010/ingest", [])
    require_allowed_siem_url("http://localhost:9090/x", [])


def test_webhook_blocks_external_without_prefix():
    with pytest.raises(ValueError):
        require_allowed_siem_url("http://198.51.100.2/webhook", [])


def test_webhook_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="http/https"):
        require_allowed_siem_url("ftp://127.0.0.1/out", [])


def test_webhook_prefix_list():
    require_allowed_siem_url("https://siem.corp/intake", ["https://siem.corp"])
    with pytest.raises(ValueError):
        require_allowed_siem_url("https://evil.com/x", ["https://siem.corp"])


def test_webhook_rejects_attacker_suffix_host_siem_corp() -> None:
    """Чеклист Спринт 1: https://siem.corp.attacker.com не проходит при правиле https://siem.corp (не prefix-string)."""
    with pytest.raises(ValueError, match="не соответствует"):
        require_allowed_siem_url(
            "https://siem.corp.attacker.com/hook",
            ["https://siem.corp"],
        )


def test_webhook_loopback_http_rejected_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "prod")
    with pytest.raises(ValueError, match="https"):
        require_allowed_siem_url("http://127.0.0.1/x", [])


def test_egress_blocks_private_ips_in_prod() -> None:
    with pytest.raises(ValueError, match="prod"):
        assert_egress_ips_allowed(["10.1.1.1"], profile="prod")
    with pytest.raises(ValueError, match="prod"):
        assert_egress_ips_allowed(["127.0.0.1"], profile="prod")


def test_egress_airgap_internal_webhook_bypass_allows_rfc1918(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_PROFILE", "airgap")
    monkeypatch.setenv("TAKT_ALLOW_INTERNAL_WEBHOOK", "1")
    assert_egress_ips_allowed(["10.1.1.1"], profile="prod")


def test_egress_airgap_without_flag_still_blocks_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAKT_PROFILE", "airgap")
    monkeypatch.delenv("TAKT_ALLOW_INTERNAL_WEBHOOK", raising=False)
    with pytest.raises(ValueError, match="prod"):
        assert_egress_ips_allowed(["10.1.1.1"], profile="prod")


def test_webhook_resolve_once_across_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock, patch

    monkeypatch.setenv("TAKT_SECURITY_PROFILE", "dev")
    hits: list[int] = []

    def res(h: str, p: int) -> list[str]:
        hits.append(1)
        return ["127.0.0.1"]

    case = Case(
        case_id="c-webhook",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = lambda: None

    with patch("takt.infrastructure.export.siem_webhook.httpx.Client") as Client:
        inst = MagicMock()
        Client.return_value.__enter__.return_value = inst
        inst.post.side_effect = [httpx.ConnectError("x"), httpx.ConnectError("x"), ok]
        post_case_to_webhook_sync(case, "http://127.0.0.1/hook", resolve_fn=res, retries=3)
    assert len(hits) == 1
    assert inst.post.call_count == 3
