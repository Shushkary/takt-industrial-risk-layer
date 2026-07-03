from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from takt.interface_adapters.api.schemas.cases import AssessResponse

_INGEST_BATCH_MAX = 100


class AssessRequest(BaseModel):
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    operator_id: str = ""
    payload_size: int = 128
    observed_at: str = "2026-04-30T22:15:00+00:00"
    persist_case: bool = Field(
        default=True,
        description="Сохранять ли кейс в хранилище и добавлять событие в общее окно контекста.",
    )


class EventIngestBody(BaseModel):
    """Полноценный ingest в L1 + ProcessEvent (обогащение, IEC-подсказки, assess)."""

    observed_at: str
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    operator_id: str = ""
    payload_size: int = 128
    source: str | None = Field(
        default=None,
        description="auth_logs | network_events | plc_polling | service_desk | unknown",
    )
    event_id: str | None = None
    payload: dict[str, Any] | None = None


class IntegrationIngestBody(BaseModel):
    observed_at: str
    protocol: str = "MODBUS"
    operation: str = Field(examples=["ADMIN_LOGIN"])
    asset_id: str = "plc-01"
    operator_id: str = ""
    payload_size: int = 128
    event_id: str | None = None
    payload: dict[str, Any] | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)


class SyslogRfc5424IngestBody(BaseModel):
    observed_at: str
    protocol: str = "SYSLOG_RFC5424"
    operation: str = "SYSLOG_EVENT"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    message: str = Field(default="", max_length=8192)
    hostname: str = Field(default="", max_length=255)
    app_name: str = Field(default="", max_length=128)
    procid: str = Field(default="", max_length=64)
    msgid: str = Field(default="", max_length=64)
    severity: int | None = Field(default=None, ge=0, le=7)
    facility: int | None = Field(default=None, ge=0, le=23)
    structured_data: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None


class SnmpTrapIngestBody(BaseModel):
    observed_at: str
    protocol: str = "SNMP_TRAP"
    operation: str = "SNMP_TRAP"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    trap_oid: str = Field(default="", max_length=255)
    version: str = Field(default="v2c", max_length=16)
    community: str = Field(default="", max_length=128)
    agent_addr: str = Field(default="", max_length=64)
    varbinds: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None


class NetflowIngestBody(BaseModel):
    observed_at: str
    protocol: str = "NETFLOW"
    operation: str = "NETFLOW_FLOW"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    exporter_ip: str = Field(default="", max_length=64)
    src_ip: str = Field(default="", max_length=64)
    dst_ip: str = Field(default="", max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    flow_start: str = ""
    flow_end: str = ""
    payload: dict[str, Any] | None = None


class IpfixIngestBody(BaseModel):
    observed_at: str
    protocol: str = "IPFIX"
    operation: str = "IPFIX_FLOW"
    asset_id: str = "network-device"
    payload_size: int = 128
    event_id: str | None = None
    collector: str = Field(default="gateway", max_length=128)
    integration_ref: str = Field(default="", max_length=256)
    exporter_ip: str = Field(default="", max_length=64)
    src_ip: str = Field(default="", max_length=64)
    dst_ip: str = Field(default="", max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    template_id: int | None = Field(default=None, ge=0)
    observation_domain_id: int | None = Field(default=None, ge=0)
    payload: dict[str, Any] | None = None


class EventBatchBody(BaseModel):
    events: list[EventIngestBody] = Field(min_length=1, max_length=_INGEST_BATCH_MAX)


class BatchAssessResponse(BaseModel):
    results: list[AssessResponse]
    count: int
