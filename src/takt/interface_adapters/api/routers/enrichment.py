from __future__ import annotations

from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.enrichment import DecodeBody, DecodeResponse, DecodedValueOut


def register_enrichment_routes(ctx: ApiContext) -> None:
    app = ctx.app
    decoder = ctx.decoder_service
    if decoder is None:
        raise RuntimeError("decoder service is required")

    @app.post("/enrichment/decode", response_model=DecodeResponse, tags=["Enrichment"])
    def decode_artifact(body: DecodeBody) -> DecodeResponse:
        return DecodeResponse(
            input=body.value,
            decodings=[
                DecodedValueOut(kind=item.kind, value=item.value, success=item.success, error=item.error)
                for item in decoder.decode(body.value)
            ],
        )
