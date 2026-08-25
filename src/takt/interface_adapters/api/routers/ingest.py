from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from takt.infrastructure.http.idempotency import idempotency_record_success, idempotent_json_response_or_none
from takt.interface_adapters.api.dependencies import ApiContext, require
from takt.interface_adapters.api.schemas.cases import AssessResponse
from takt.interface_adapters.api.schemas.ingest import (
    AssessRequest,
    BatchAssessResponse,
    EventBatchBody,
    EventIngestBody,
    IpfixIngestBody,
    NetflowIngestBody,
    SnmpTrapIngestBody,
    SyslogRfc5424IngestBody,
)


def register_ingest_routes(ctx: ApiContext) -> None:
    app = ctx.app
    # Схемы — импортом: из аннотации параметра FastAPI строит разбор тела и OpenAPI, а
    # переменная в аннотации типом не является. Обработчики остаются в контексте.
    assess_from_plc_demo_body = require(ctx.assess_from_plc_demo_body, "assess_from_plc_demo_body")
    assess_event_ingest_body = require(ctx.assess_event_ingest_body, "assess_event_ingest_body")
    assess_event_batch_body = require(ctx.assess_event_batch_body, "assess_event_batch_body")
    assess_syslog_rfc5424_body = require(ctx.assess_syslog_rfc5424_body, "assess_syslog_rfc5424_body")
    assess_snmp_trap_body = require(ctx.assess_snmp_trap_body, "assess_snmp_trap_body")
    assess_netflow_body = require(ctx.assess_netflow_body, "assess_netflow_body")
    assess_ipfix_body = require(ctx.assess_ipfix_body, "assess_ipfix_body")

    @app.post("/assess", response_model=AssessResponse, tags=["Ingest"])
    def assess(body: AssessRequest):
        return assess_from_plc_demo_body(body)

    @app.post("/assess/demo", response_model=AssessResponse, tags=["Ingest"], deprecated=True)
    def assess_demo(body: AssessRequest):
        return assess_from_plc_demo_body(body)

    @app.post("/events", response_model=AssessResponse, tags=["Ingest"])
    async def ingest_event(request: Request):
        raw = await request.body()
        idem = getattr(app.state, "idempotency_store", None)
        replay = idempotent_json_response_or_none(request=request, raw_body=raw, store=idem)
        if replay is not None:
            payload, _ = replay
            return JSONResponse(content=payload, headers={"X-Idempotent-Replayed": "true"})
        try:
            body = EventIngestBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        out = assess_event_ingest_body(body, raw_payload=raw)
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out

    @app.post("/integrations/ingest/syslog/rfc5424", response_model=AssessResponse, tags=["Ingest"])
    def ingest_syslog_rfc5424(body: SyslogRfc5424IngestBody):
        return assess_syslog_rfc5424_body(body)

    @app.post("/integrations/ingest/snmp/trap", response_model=AssessResponse, tags=["Ingest"])
    def ingest_snmp_trap(body: SnmpTrapIngestBody):
        return assess_snmp_trap_body(body)

    @app.post("/integrations/ingest/netflow", response_model=AssessResponse, tags=["Ingest"])
    def ingest_netflow(body: NetflowIngestBody):
        return assess_netflow_body(body)

    @app.post("/integrations/ingest/ipfix", response_model=AssessResponse, tags=["Ingest"])
    def ingest_ipfix(body: IpfixIngestBody):
        return assess_ipfix_body(body)

    @app.post("/events/batch", response_model=BatchAssessResponse, tags=["Ingest"])
    async def ingest_batch(request: Request):
        raw = await request.body()
        idem = getattr(app.state, "idempotency_store", None)
        replay = idempotent_json_response_or_none(request=request, raw_body=raw, store=idem)
        if replay is not None:
            payload, _ = replay
            return JSONResponse(content=payload, headers={"X-Idempotent-Replayed": "true"})
        try:
            body = EventBatchBody.model_validate_json(raw)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
        results = assess_event_batch_body(body)
        out = BatchAssessResponse(results=results, count=len(results))
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out
