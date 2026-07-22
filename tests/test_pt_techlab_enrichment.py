from __future__ import annotations

from fastapi.testclient import TestClient

from takt.application.use_cases.enrichment import LocalDecoderService
from takt.interface_adapters.api.main import create_app


def test_local_decoder_decodes_base64_url_and_hex_without_network() -> None:
    decoder = LocalDecoderService()

    result = {item.kind: item for item in decoder.decode("cG93ZXJzaGVsbA%3D%3D")}
    assert result["url"].success is True
    assert result["url"].value == "cG93ZXJzaGVsbA=="

    base64_result = {item.kind: item for item in decoder.decode("cG93ZXJzaGVsbA==")}
    assert base64_result["base64"].success is True
    assert base64_result["base64"].value == "powershell"

    hex_result = {item.kind: item for item in decoder.decode("706f7765727368656c6c")}
    assert hex_result["hex"].success is True
    assert hex_result["hex"].value == "powershell"


def test_enrichment_decode_endpoint_is_local_and_structured() -> None:
    client = TestClient(create_app())

    response = client.post("/enrichment/decode", json={"value": "706f7765727368656c6c"})

    assert response.status_code == 200
    body = response.json()
    assert body["input"] == "706f7765727368656c6c"
    assert {"kind": "hex", "value": "powershell", "success": True, "error": ""} in body["decodings"]
