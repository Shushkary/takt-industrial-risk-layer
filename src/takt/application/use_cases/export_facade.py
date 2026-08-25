from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort


@dataclass(frozen=True, slots=True)
class BinaryExportResponse:
    content: bytes
    media_type: str
    headers: dict[str, str]


class ExportFacade:
    def __init__(
        self,
        *,
        repo: CaseRepositoryPort,
        clock: SystemClockPort,
        render_case_pdf: Callable[..., bytes],
        render_decision_brief_pdf: Callable[..., bytes],
        post_case_to_webhook_sync: Callable[..., int],
        post_case_to_webhook: Callable[..., Awaitable[int]],
        case_to_siem_payload: Callable[..., Any],
        case_to_gossopka_card: Callable[..., dict[str, Any]],
        case_to_gossopka_transport_payload: Callable[..., dict[str, Any]],
        case_to_gossopka_official_card: Callable[..., dict[str, Any]],
        case_to_gossopka_official_transport_payload: Callable[..., dict[str, Any]],
        require_allowed_siem_url: Callable[..., None],
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._render_case_pdf = render_case_pdf
        self._render_decision_brief_pdf = render_decision_brief_pdf
        self._post_case_to_webhook_sync = post_case_to_webhook_sync
        self._post_case_to_webhook = post_case_to_webhook
        self._case_to_siem_payload = case_to_siem_payload
        self._case_to_gossopka_card = case_to_gossopka_card
        self._case_to_gossopka_transport_payload = case_to_gossopka_transport_payload
        self._case_to_gossopka_official_card = case_to_gossopka_official_card
        self._case_to_gossopka_official_transport_payload = case_to_gossopka_official_transport_payload
        self._require_allowed_siem_url = require_allowed_siem_url
        self._siem_async_semaphore = asyncio.Semaphore(8)

    def export_pdf(self, *, case_id: str, unicode_font_path: str | None = None) -> BinaryExportResponse:
        case = self._get_case(case_id)
        generated_at = self._pdf_generated_at(case)
        pdf_bytes = self._render_case_pdf(
            case,
            generated_at=generated_at,
            unicode_font_path=unicode_font_path,
        )
        sha = hashlib.sha256(pdf_bytes).hexdigest()
        generated_at_text = generated_at.isoformat(timespec="seconds")
        if case.pdf_last_sha256 != sha or case.pdf_last_generated_at != generated_at_text:
            case.pdf_last_sha256 = sha
            case.pdf_last_generated_at = generated_at_text
            case.append_audit(f"pdf exported sha256={sha}", generated_at)
            self._repo.save(case)
        return BinaryExportResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="takt-case-{case_id}.pdf"',
                "X-TAKT-PDF-SHA256": sha,
            },
        )

    def export_decision_brief_pdf(
        self, *, case_id: str, unicode_font_path: str | None = None
    ) -> BinaryExportResponse:
        """Сводка для ЛПР одним листом.

        В отличие от паспорта инцидента, состояние дела не меняется: сводка — производный
        документ, её выгрузка не является событием жизненного цикла и в журнал не пишется.
        Момент формирования берётся из тех же часов, поэтому один и тот же кейс даёт один и
        тот же документ в пределах секунды.
        """
        case = self._get_case(case_id)
        generated_at = self._pdf_generated_at(case)
        content = self._render_decision_brief_pdf(
            case,
            generated_at=generated_at,
            unicode_font_path=unicode_font_path,
        )
        return BinaryExportResponse(
            content=content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="takt-decision-brief-{case_id}.pdf"',
                "X-TAKT-PDF-SHA256": hashlib.sha256(content).hexdigest(),
            },
        )

    def siem_payload(self, case_id: str) -> Any:
        return self._case_to_siem_payload(self._get_case(case_id))

    def gossopka_card(self, case_id: str) -> dict[str, Any]:
        return self._case_to_gossopka_card(self._get_case(case_id), generated_at=self._clock.now_utc())

    def gossopka_transport(self, *, case_id: str, exchange_mode: str = "pull_http_json") -> dict[str, Any]:
        return self._case_to_gossopka_transport_payload(
            self._get_case(case_id),
            generated_at=self._clock.now_utc(),
            exchange_mode=exchange_mode.strip() or "pull_http_json",
        )

    def gossopka_official_card(self, case_id: str) -> dict[str, Any]:
        return self._case_to_gossopka_official_card(self._get_case(case_id), generated_at=self._clock.now_utc())

    def gossopka_official_transport(self, *, case_id: str, exchange_mode: str = "pull_http_json") -> dict[str, Any]:
        return self._case_to_gossopka_official_transport_payload(
            self._get_case(case_id),
            generated_at=self._clock.now_utc(),
            exchange_mode=exchange_mode.strip() or "pull_http_json",
        )

    def forward_siem_sync(
        self,
        *,
        case_id: str,
        target_url: str,
        allowed_prefixes: list[str],
        retries: int,
        backoff_sec: float,
    ) -> int:
        case = self._get_case(case_id)
        self._require_allowed_siem_url(target_url, allowed_prefixes)
        return self._post_case_to_webhook_sync(
            case,
            target_url.strip(),
            retries=retries,
            backoff_sec=backoff_sec,
        )

    async def forward_siem_async(
        self,
        *,
        case_id: str,
        target_url: str,
        allowed_prefixes: list[str],
        retries: int,
        backoff_sec: float,
    ) -> int:
        case = self._get_case(case_id)
        self._require_allowed_siem_url(target_url, allowed_prefixes)
        async with self._siem_async_semaphore:
            return await self._post_case_to_webhook(
                case,
                target_url.strip(),
                retries=retries,
                backoff_sec=backoff_sec,
            )

    def _get_case(self, case_id: str) -> Any:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError("case not found")
        return case

    def _pdf_generated_at(self, case: Any) -> datetime:
        if case.pdf_last_sha256 and case.pdf_last_generated_at:
            try:
                return datetime.fromisoformat(str(case.pdf_last_generated_at).replace("Z", "+00:00"))
            except ValueError:
                pass
        return self._clock.now_utc()
