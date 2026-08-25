from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from takt.application.use_cases.process_event import ProcessEventUseCase, ProcessOutcome
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.case import Case, RawEvidenceRef
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.domain.ports.case_repository import CaseRepositoryPort


@dataclass(slots=True)
class PreparedIngestEvent:
    event: NormalizedEvent
    raw_payload: bytes
    source: EventSource
    note: str


class RecentEventStorePort(Protocol):
    def add_recent_event(self, event: NormalizedEvent, *, max_events: int) -> None: ...
    def list_recent_events(self, *, limit: int) -> list[NormalizedEvent]: ...


@dataclass(slots=True)
class IngestAssessmentFacade:
    process: ProcessEventUseCase
    repo: CaseRepositoryPort
    event_window: list[NormalizedEvent]
    event_window_max: int
    graph_edges: Sequence[GraphEdge]
    polling_intervals_us: Sequence[float]
    raw_row_to_normalized: Callable[..., NormalizedEvent]
    recent_event_store: RecentEventStorePort | None = None

    def assess_normalized_event(
        self,
        event: NormalizedEvent,
        *,
        persist_case: bool = True,
        raw_evidence_ref: RawEvidenceRef | None = None,
        trust_by_source: Mapping[str, float] | None = None,
    ) -> ProcessOutcome:
        recent = self._take_recent(self.process.recent_context_event_count)
        out = self.process.execute(
            event,
            persist=persist_case,
            recent_events=recent,
            tickets=[],
            graph_edges=list(self.graph_edges),
            polling_intervals_us=self.polling_intervals_us,
            clock=event.observed_at,
            trust_by_source=trust_by_source,
        )
        if raw_evidence_ref is not None:
            self.attach_raw_evidence(out.case, raw_evidence_ref, persist_case=persist_case)
        if persist_case:
            if self.recent_event_store is not None:
                self.recent_event_store.add_recent_event(event, max_events=self.event_window_max)
            else:
                self.event_window.append(event)
                self._trim_event_window()
        return out

    def build_raw_evidence_ref(
        self,
        *,
        raw_payload: bytes,
        source: str,
        event_id: str,
        captured_at: datetime,
        media_type: str = "application/json",
        note: str = "",
    ) -> RawEvidenceRef:
        sha = hashlib.sha256(raw_payload).hexdigest()
        return RawEvidenceRef(
            evidence_id=f"{event_id or 'event'}-{sha[:16]}",
            source=source,
            media_type=media_type,
            captured_at=captured_at,
            payload_b64=base64.b64encode(raw_payload).decode("ascii"),
            sha256=sha,
            size_bytes=len(raw_payload),
            event_id=event_id,
            note=note,
        )

    def normalized_event_from_ingest_body(
        self,
        body: Any,
        *,
        source: EventSource,
    ) -> NormalizedEvent:
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "operator_id": getattr(body, "operator_id", ""),
            "payload_size": str(body.payload_size),
        }
        payload = getattr(body, "payload", None)
        if payload:
            row.update(payload)
        return self.raw_row_to_normalized(row, source=source, event_id=getattr(body, "event_id", None))

    def normalized_event_from_plc_demo_body(self, body: Any) -> NormalizedEvent:
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "operator_id": body.operator_id,
            "payload_size": str(body.payload_size),
        }
        return self.raw_row_to_normalized(row, source=EventSource.PLC_POLLING)

    def prepared_integration_body(self, body: Any, *, source: EventSource) -> PreparedIngestEvent:
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "operator_id": body.operator_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.payload:
            row.update(body.payload)
        event = self.raw_row_to_normalized(row, source=source, event_id=body.event_id)
        return PreparedIngestEvent(
            event=event,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            source=source,
            note=f"integration_ingest:{source.value}",
        )

    def prepared_integration_row(
        self,
        *,
        row: dict[str, Any],
        source: EventSource,
        event_id: str | None,
        raw_payload: bytes,
        note: str,
    ) -> PreparedIngestEvent:
        event = self.raw_row_to_normalized(row, source=source, event_id=event_id)
        return PreparedIngestEvent(event=event, raw_payload=raw_payload, source=source, note=note)

    def prepared_event_ingest_body(
        self,
        body: Any,
        *,
        raw_payload: bytes,
        source: EventSource,
        note: str = "events_ingest",
    ) -> PreparedIngestEvent:
        event = self.normalized_event_from_ingest_body(body, source=source)
        return PreparedIngestEvent(event=event, raw_payload=raw_payload, source=source, note=note)

    def prepared_syslog_rfc5424_body(self, body: Any) -> PreparedIngestEvent:
        row: dict[str, Any] = {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }
        facility, severity = self.parse_syslog_priority(body.message)
        row["syslog_severity"] = body.severity if body.severity is not None else severity
        row["syslog_facility"] = body.facility if body.facility is not None else facility
        if body.hostname:
            row["syslog_hostname"] = body.hostname
        if body.app_name:
            row["syslog_app_name"] = body.app_name
        if body.procid:
            row["syslog_procid"] = body.procid
        if body.msgid:
            row["syslog_msgid"] = body.msgid
        if body.structured_data:
            row["syslog_structured_data"] = body.structured_data
        if body.message:
            row["syslog_message"] = body.message
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.payload:
            row.update(body.payload)
        return self.prepared_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:syslog_rfc5424",
        )

    def prepared_snmp_trap_body(self, body: Any) -> PreparedIngestEvent:
        row: dict[str, Any] = self._base_network_row(body)
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        if body.trap_oid:
            row["snmp_trap_oid"] = body.trap_oid
        if body.version:
            row["snmp_version"] = body.version
        if body.community:
            row["snmp_community"] = body.community
        if body.agent_addr:
            row["snmp_agent_addr"] = body.agent_addr
        if body.varbinds:
            row["snmp_varbinds"] = body.varbinds
        if body.payload:
            row.update(body.payload)
        return self.prepared_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:snmp_trap",
        )

    def prepared_netflow_body(self, body: Any) -> PreparedIngestEvent:
        row = self._base_network_row(body)
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        self._append_flow_fields(row, body)
        if body.flow_start:
            row["flow_start"] = body.flow_start
        if body.flow_end:
            row["flow_end"] = body.flow_end
        if body.payload:
            row.update(body.payload)
        return self.prepared_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:netflow",
        )

    def prepared_ipfix_body(self, body: Any) -> PreparedIngestEvent:
        row = self._base_network_row(body)
        if body.integration_ref:
            row["integration_ref"] = body.integration_ref
        self._append_flow_fields(row, body)
        if body.template_id is not None:
            row["ipfix_template_id"] = body.template_id
        if body.observation_domain_id is not None:
            row["ipfix_observation_domain_id"] = body.observation_domain_id
        if body.payload:
            row.update(body.payload)
        return self.prepared_integration_row(
            row=row,
            source=EventSource.NETWORK,
            event_id=body.event_id,
            raw_payload=body.model_dump_json(exclude_none=True).encode("utf-8"),
            note="integration_ingest:ipfix",
        )

    def assess_ingest_body(
        self,
        body: Any,
        *,
        raw_payload: bytes,
        source: EventSource,
        trust_by_source: Mapping[str, float] | None = None,
        note: str = "events_ingest",
    ) -> ProcessOutcome:
        event = self.normalized_event_from_ingest_body(body, source=source)
        raw_ref = self.build_raw_evidence_ref(
            raw_payload=raw_payload,
            source=source.value,
            event_id=event.event_id,
            captured_at=event.observed_at,
            note=note,
        )
        return self.assess_normalized_event(event, raw_evidence_ref=raw_ref, trust_by_source=trust_by_source)

    @staticmethod
    def parse_syslog_priority(message: str) -> tuple[int | None, int | None]:
        if not message.startswith("<"):
            return None, None
        end = message.find(">")
        if end <= 1:
            return None, None
        token = message[1:end]
        if not token.isdigit():
            return None, None
        pri = int(token, 10)
        return pri // 8, pri % 8

    def attach_raw_evidence(self, case: Case, ref: RawEvidenceRef, *, persist_case: bool) -> None:
        for existing in case.raw_evidence_refs:
            if existing.sha256 == ref.sha256 and existing.event_id == ref.event_id and existing.source == ref.source:
                return
        case.raw_evidence_refs.append(ref)
        case.append_audit(f"raw evidence captured evidence_id={ref.evidence_id} sha256={ref.sha256}", ref.captured_at)
        if persist_case:
            self.repo.save(case)

    def _take_recent(self, n: int) -> list[NormalizedEvent]:
        if n <= 0:
            return []
        if self.recent_event_store is not None:
            return self.recent_event_store.list_recent_events(limit=n)
        return list(self.event_window[-n:])

    def _trim_event_window(self) -> None:
        overflow = len(self.event_window) - self.event_window_max
        if overflow > 0:
            del self.event_window[:overflow]

    @staticmethod
    def _base_network_row(body: Any) -> dict[str, Any]:
        return {
            "timestamp": body.observed_at,
            "protocol": body.protocol,
            "operation": body.operation,
            "asset_id": body.asset_id,
            "payload_size": str(body.payload_size),
            "collector": body.collector,
        }

    @staticmethod
    def _append_flow_fields(row: dict[str, Any], body: Any) -> None:
        if body.exporter_ip:
            row["flow_exporter_ip"] = body.exporter_ip
        if body.src_ip:
            row["flow_src_ip"] = body.src_ip
        if body.dst_ip:
            row["flow_dst_ip"] = body.dst_ip
        if body.src_port is not None:
            row["flow_src_port"] = body.src_port
        if body.dst_port is not None:
            row["flow_dst_port"] = body.dst_port
        if body.bytes is not None:
            row["flow_bytes"] = body.bytes
        if body.packets is not None:
            row["flow_packets"] = body.packets
        if body.protocol_number is not None:
            row["flow_protocol_number"] = body.protocol_number
