from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from takt.infrastructure.http.idempotency import idempotency_record_success, idempotent_json_response_or_none
from takt.interface_adapters.api.dependencies import ApiContext


def register_ingest_routes(ctx: ApiContext) -> None:
    app = ctx.app
    if any(
        item is None
        for item in (
            ctx.assess_request_model,
            ctx.assess_response_model,
            ctx.event_ingest_body_model,
            ctx.syslog_rfc5424_ingest_body_model,
            ctx.snmp_trap_ingest_body_model,
            ctx.netflow_ingest_body_model,
            ctx.ipfix_ingest_body_model,
            ctx.event_batch_body_model,
            ctx.batch_assess_response_model,
            ctx.assess_from_plc_demo_body,
            ctx.assess_event_ingest_body,
            ctx.assess_event_batch_body,
            ctx.assess_syslog_rfc5424_body,
            ctx.assess_snmp_trap_body,
            ctx.assess_netflow_body,
            ctx.assess_ipfix_body,
        )
    ):
        raise RuntimeError("ingest dependencies are required")

    AssessRequest = ctx.assess_request_model
    AssessResponse = ctx.assess_response_model
    EventIngestBody = ctx.event_ingest_body_model
    SyslogRfc5424IngestBody = ctx.syslog_rfc5424_ingest_body_model
    SnmpTrapIngestBody = ctx.snmp_trap_ingest_body_model
    NetflowIngestBody = ctx.netflow_ingest_body_model
    IpfixIngestBody = ctx.ipfix_ingest_body_model
    EventBatchBody = ctx.event_batch_body_model
    BatchAssessResponse = ctx.batch_assess_response_model

    @app.post("/assess", response_model=AssessResponse, tags=["Ingest"])
    def assess(body: AssessRequest):
        return ctx.assess_from_plc_demo_body(body)

    @app.post("/assess/demo", response_model=AssessResponse, tags=["Ingest"], deprecated=True)
    def assess_demo(body: AssessRequest):
        return ctx.assess_from_plc_demo_body(body)

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
        out = ctx.assess_event_ingest_body(body, raw_payload=raw)
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out

    @app.post("/integrations/ingest/syslog/rfc5424", response_model=AssessResponse, tags=["Ingest"])
    def ingest_syslog_rfc5424(body: SyslogRfc5424IngestBody):
        return ctx.assess_syslog_rfc5424_body(body)

    @app.post("/integrations/ingest/snmp/trap", response_model=AssessResponse, tags=["Ingest"])
    def ingest_snmp_trap(body: SnmpTrapIngestBody):
        return ctx.assess_snmp_trap_body(body)

    @app.post("/integrations/ingest/netflow", response_model=AssessResponse, tags=["Ingest"])
    def ingest_netflow(body: NetflowIngestBody):
        return ctx.assess_netflow_body(body)

    @app.post("/integrations/ingest/ipfix", response_model=AssessResponse, tags=["Ingest"])
    def ingest_ipfix(body: IpfixIngestBody):
        return ctx.assess_ipfix_body(body)

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
        results = ctx.assess_event_batch_body(body)
        out = BatchAssessResponse(results=results, count=len(results))
        idempotency_record_success(
            request=request,
            raw_body=raw,
            store=idem,
            response_json=out.model_dump_json(),
        )
        return out
