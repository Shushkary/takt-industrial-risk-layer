from __future__ import annotations

import base64
import binascii
from urllib.parse import unquote_plus

from takt.domain.ports.enrichment import DecodedValue


class LocalDecoderService:
    def __init__(self, *, max_output_chars: int = 8192) -> None:
        self._max_output_chars = max(1, max_output_chars)

    def decode(self, value: str) -> list[DecodedValue]:
        text = value.strip()
        return [
            self._base64(text),
            self._url(text),
            self._hex(text),
        ]

    def _clip(self, value: str) -> str:
        if len(value) <= self._max_output_chars:
            return value
        return value[: self._max_output_chars]

    def _base64(self, value: str) -> DecodedValue:
        try:
            padded = value + ("=" * (-len(value) % 4))
            raw = base64.b64decode(padded, validate=True)
            return DecodedValue("base64", self._clip(raw.decode("utf-8", errors="replace")), True)
        except (binascii.Error, ValueError) as exc:
            return DecodedValue("base64", "", False, str(exc))

    def _url(self, value: str) -> DecodedValue:
        decoded = unquote_plus(value)
        if decoded == value:
            return DecodedValue("url", "", False, "no URL-encoded sequences")
        return DecodedValue("url", self._clip(decoded), True)

    def _hex(self, value: str) -> DecodedValue:
        candidate = value.removeprefix("0x").replace(" ", "")
        if len(candidate) < 2 or len(candidate) % 2:
            return DecodedValue("hex", "", False, "hex input must contain an even number of digits")
        try:
            raw = bytes.fromhex(candidate)
            return DecodedValue("hex", self._clip(raw.decode("utf-8", errors="replace")), True)
        except ValueError as exc:
            return DecodedValue("hex", "", False, str(exc))
