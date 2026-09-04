"""Контракт между слоем доставки и слоем сценариев.

Роутеры получают зависимости отсюда, а не собирают их сами и не достают из глобального
`app.state`. Поля названы теми типами, которые в них кладутся: до этого почти весь контракт
был `Any`, и шов L3 → L2 существовал структурно, но ничего не удерживал — опечатка в имени
метода сценария доходила до боя, а mypy молчал.

Необязательные поля (`| None`) — это порядок сборки, а не необязательность зависимости:
`create_app` собирает контекст одним вызовом, а часть сценариев к этому моменту может быть
не поднята (нет extra, не задано окружение). Роутер разворачивает такое поле через
`require`, и отказ называет недостающую зависимость.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from fastapi import FastAPI

from takt.application.use_cases.audit_engagement import ManageAuditEngagementUseCase
from takt.application.use_cases.audit_ledger_facade import AuditLedgerFacade
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.build_forensic_bundle import BuildForensicBundleUseCase
from takt.application.use_cases.case_actions_facade import CaseActionsFacade
from takt.application.use_cases.case_decision import SubmitCaseDecisionUseCase
from takt.application.use_cases.case_findings import CaseFindingsUseCase
from takt.application.use_cases.cases_query_service import CasesQueryService
from takt.application.use_cases.compliance_facade import ComplianceFacade
from takt.application.use_cases.compliance_report import (
    BuildCaseEvidenceChecklistUseCase,
    BuildComplianceDataQualityReportUseCase,
    BuildForensicReadinessReportUseCase,
)
from takt.application.use_cases.enrichment import LocalDecoderService
from takt.application.use_cases.export_facade import ExportFacade
from takt.application.use_cases.forensic_export_facade import ForensicExportFacade
from takt.application.use_cases.formal_verdict_confirmation import ConfirmFormalVerdictUseCase
from takt.application.use_cases.manual_correlation import ManualCorrelationUseCase
from takt.application.use_cases.manual_permit import AttachManualPermitUseCase
from takt.application.use_cases.remediation import (
    ListRemediationAttemptsUseCase,
    RecordRemediationAttemptUseCase,
)
from takt.application.use_cases.verify_forensic_bundle import VerifyForensicBundleUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.event import EventSource
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort
from takt.infrastructure.config.invariant_catalog_yaml import InvariantCatalogFromYaml

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


@dataclass(frozen=True)
class ApiContext:
    app: FastAPI

    # Хранилища и время — доменными портами, а не конкретными реализациями: роутер не должен
    # знать, память под ним или SQLite.
    repo: CaseRepositoryPort
    baseline: ExpectedBehaviorPort
    clock: SystemClockPort

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
    demo_edges: Sequence[GraphEdge]
    jump_host: str
    plc_hosts: set[str]

    # Конфигурация, которую роутеры раньше доставали из глобального `app.state`. Зависимость
    # приходит инъекцией, а не поиском в общем мешке: иначе у слоя доставки два независимых
    # канала за одним и тем же и ни одного проверяемого контракта.
    # `app.state` остаётся — через него до тех же объектов добираются точки входа CLI
    # (`takt.tools`) и `lifespan`, у которых `ApiContext` нет.
    trust_by_source: Mapping[str, float]
    invariant_catalog: InvariantCatalogFromYaml
    siem_webhook_prefixes: Sequence[str]

    # Веса оценки риска правятся из окна (`PUT /config/risk-weights`), поэтому версия берётся
    # вызовом, а не значением: снимок на старте после первой же правки называл бы в отчёте
    # разметки набор, против которого отчёт уже не посчитан.
    risk_weights_version: Callable[[], str]
    risk_weights: MutableMapping[str, Any]
    risk_weights_path: Path

    # Сценарии и фасады слоя приложения.
    backtest_uc: RunBacktestUseCase | None = None
    audit_ledger_facade: AuditLedgerFacade | None = None
    forensic_uc: BuildForensicBundleUseCase | None = None
    forensic_verify_uc: VerifyForensicBundleUseCase | None = None
    forensic_export_facade: ForensicExportFacade | None = None
    export_facade: ExportFacade | None = None
    audit_engagement_uc: ManageAuditEngagementUseCase | None = None
    compliance_report_uc: BuildComplianceDataQualityReportUseCase | None = None
    forensic_readiness_uc: BuildForensicReadinessReportUseCase | None = None
    evidence_checklist_uc: BuildCaseEvidenceChecklistUseCase | None = None
    remediation_uc: RecordRemediationAttemptUseCase | None = None
    remediation_list_uc: ListRemediationAttemptsUseCase | None = None
    compliance_facade: ComplianceFacade | None = None
    cases_query_service: CasesQueryService | None = None
    manual_permit_uc: AttachManualPermitUseCase | None = None
    formal_verdict_confirmation_uc: ConfirmFormalVerdictUseCase | None = None
    decision_uc: SubmitCaseDecisionUseCase | None = None
    case_actions_facade: CaseActionsFacade | None = None
    manual_correlation_uc: ManualCorrelationUseCase | None = None
    case_findings_uc: CaseFindingsUseCase | None = None
    decoder_service: LocalDecoderService | None = None

    # Преобразователи «доменная сущность ↔ схема ответа» и разбор тел запросов. Аргументы и
    # результаты — схемы `pydantic` слоя доставки, поэтому здесь они остаются `Any`: назвать
    # их точнее значило бы затащить схемы в этот модуль и замкнуть импорт на роутеры.
    offset_limit_link_header: Callable[..., str | None] | None = None
    case_to_detail: Callable[[Any], Any] | None = None
    decision_brief_to_detail: Callable[[Any], Any] | None = None
    domain_case_from_detail: Callable[[Any], Any] | None = None
    coerce_event_source: Callable[[str | None], EventSource] | None = None
    manual_permit_to_detail: Callable[[Any], Any] | None = None
    formal_verdict_record_to_detail: Callable[[Any], Any] | None = None
    assess_from_plc_demo_body: Callable[[Any], Any] | None = None
    assess_event_ingest_body: Callable[..., Any] | None = None
    assess_event_batch_body: Callable[..., Any] | None = None
    assess_syslog_rfc5424_body: Callable[..., Any] | None = None
    assess_snmp_trap_body: Callable[..., Any] | None = None
    assess_netflow_body: Callable[..., Any] | None = None
    assess_ipfix_body: Callable[..., Any] | None = None
