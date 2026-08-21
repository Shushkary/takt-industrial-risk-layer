from __future__ import annotations

import json
from pathlib import Path

import yaml


def test_grafana_dashboard_json_valid_and_contains_business_metrics() -> None:
    root = Path(__file__).resolve().parents[1]
    dashboard_path = root / "deploy" / "monitoring" / "grafana" / "takt-business-observability-dashboard.json"
    payload = json.loads(dashboard_path.read_text(encoding="utf-8"))
    assert payload["title"] == "TAKT Business Observability"
    all_expr: list[str] = []
    for panel in payload.get("panels", []):
        for target in panel.get("targets", []):
            expr = str(target.get("expr", ""))
            if expr:
                all_expr.append(expr)
    joined = "\n".join(all_expr)
    assert "takt_business_risk_score" in joined
    assert "takt_business_invariant_hits_total" in joined
    assert "takt_business_dq_degraded_ratio" in joined
    assert "takt_business_event_to_case_latency_seconds_bucket" in joined
    assert "takt_business_case_merges_total" in joined
    # Разрыв G-4 (`docs/customer_value_map.md`): дашборд обязан отвечать на вопрос клиента
    # «стало ли лучше», а не только на вопрос эксплуатации «жив ли конвейер».
    assert "takt_business_case_to_decision_seconds_bucket" in joined
    assert "takt_business_verdicts_total" in joined
    assert "takt_business_undet_resolved_total" in joined
    assert "takt_business_forensic_bundles_total" in joined


def test_prometheus_alert_rules_yaml_valid_and_references_business_metrics() -> None:
    root = Path(__file__).resolve().parents[1]
    rules_path = (
        root / "deploy" / "monitoring" / "prometheus" / "alerts.business-observability.rules.yml"
    )
    payload = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    groups = payload.get("groups")
    assert isinstance(groups, list) and groups
    rules = groups[0].get("rules", [])
    expr_joined = "\n".join(str(rule.get("expr", "")) for rule in rules)
    assert "takt_business_dq_degraded_ratio" in expr_joined
    assert "takt_business_event_to_case_latency_seconds_bucket" in expr_joined
    assert "takt_business_risk_score" in expr_joined
