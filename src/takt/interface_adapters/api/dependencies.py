from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from fastapi import FastAPI

_T = TypeVar("_T")


def require(value: _T | None, name: str) -> _T:
    """Обязательная зависимость роутера — или отказ с именем той, которой не хватило.

    Возвращает значение, а не проверяет молча: дальше по коду тип уже сужен, и обращение к
    `None` становится невозможным по построению. Прежняя сборная проверка
    `any(item is None for item in (...))` давала тот же отказ на старте, но не сужала тип и
    не называла недостающую зависимость.
    """
    if value is None:
        raise RuntimeError(f"router dependency is required: {name}")
    return value

"""FastAPI dependency boundary for the API layer.

Sprint 1 starts with this module as the stable import target for dependency
extraction. Runtime wiring still lives in `app.py` until routers are moved one
group at a time under the OpenAPI snapshot.
"""


@dataclass(frozen=True)
class ApiContext:
    app: FastAPI
    repo: Any
    baseline: Any
    clock: Any
    package_version: str
    root: Path
    gzip_minimum_size_bytes: int
    export_full_max: int
    event_window_max: int
    ingest_batch_max: int
    case_list_max_limit: int
    case_list_default_sort: str
    build_revision_from_env: Callable[[], str | None]
    openapi_server_entries_from_env: Callable[[], list[dict[str, str]]]
    forensic_crypto_mode: Callable[[], str]
    forensic_strict_missing: Callable[[], list[str]]
    demo_edges: list[Any]
    jump_host: str
    plc_hosts: set[str]
    backtest_uc: Any | None = None
    audit_ledger_facade: Any | None = None
    forensic_uc: Any | None = None
    forensic_verify_uc: Any | None = None
    forensic_export_facade: Any | None = None
    export_facade: Any | None = None
    audit_engagement_uc: Any | None = None
    compliance_report_uc: Any | None = None
    forensic_readiness_uc: Any | None = None
    evidence_checklist_uc: Any | None = None
    remediation_uc: Any | None = None
    remediation_list_uc: Any | None = None
    compliance_facade: Any | None = None
    cases_query_service: Any | None = None
    offset_limit_link_header: Callable[..., str | None] | None = None
    case_to_detail: Callable[[Any], Any] | None = None
    decision_brief_to_detail: Callable[[Any], Any] | None = None
    domain_case_from_detail: Callable[[Any], Any] | None = None
    coerce_event_source: Callable[[str | None], Any] | None = None
    manual_permit_uc: Any | None = None
    formal_verdict_confirmation_uc: Any | None = None
    decision_uc: Any | None = None
    case_actions_facade: Any | None = None
    manual_permit_to_detail: Callable[[Any], Any] | None = None
    formal_verdict_record_to_detail: Callable[[Any], Any] | None = None
    manual_correlation_uc: Any | None = None
    case_findings_uc: Any | None = None
    decoder_service: Any | None = None
    assess_from_plc_demo_body: Callable[[Any], Any] | None = None
    assess_event_ingest_body: Callable[..., Any] | None = None
    assess_event_batch_body: Callable[..., Any] | None = None
    assess_syslog_rfc5424_body: Callable[..., Any] | None = None
    assess_snmp_trap_body: Callable[..., Any] | None = None
    assess_netflow_body: Callable[..., Any] | None = None
    assess_ipfix_body: Callable[..., Any] | None = None
