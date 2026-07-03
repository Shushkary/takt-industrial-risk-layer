from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from takt.application.use_cases.export_facade import ExportFacade
from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.memory import InMemoryCaseStore


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 5, 22, 12, 0, tzinfo=timezone.utc)


def test_siem_async_forward_is_bounded_by_semaphore() -> None:
    repo = InMemoryCaseStore()
    repo.save(
        Case(
            case_id="bounded-1",
            status=CaseStatus.NEW,
            title="t",
            risk_class="LOW",
            risk_score=0.1,
            created_at=datetime(2026, 5, 22, 12, 0, tzinfo=timezone.utc),
        )
    )
    active = 0
    max_active = 0

    async def fake_post(*args, **kwargs) -> int:  # noqa: ANN002, ANN003
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return 202

    facade = ExportFacade(
        repo=repo,
        clock=_Clock(),
        render_case_pdf=lambda *args, **kwargs: b"%PDF",
        post_case_to_webhook_sync=lambda *args, **kwargs: 204,
        post_case_to_webhook=fake_post,
        case_to_siem_payload=lambda *args, **kwargs: {},
        case_to_gossopka_card=lambda *args, **kwargs: {},
        case_to_gossopka_transport_payload=lambda *args, **kwargs: {},
        case_to_gossopka_official_card=lambda *args, **kwargs: {},
        case_to_gossopka_official_transport_payload=lambda *args, **kwargs: {},
        require_allowed_siem_url=lambda *args, **kwargs: None,
    )
    facade._siem_async_semaphore = asyncio.Semaphore(1)

    async def run() -> list[int]:
        return await asyncio.gather(
            *[
                facade.forward_siem_async(
                    case_id="bounded-1",
                    target_url="http://127.0.0.1/ingest",
                    allowed_prefixes=["http://127.0.0.1/"],
                    retries=1,
                    backoff_sec=0.0,
                )
                for _ in range(3)
            ]
        )

    assert asyncio.run(run()) == [202, 202, 202]
    assert max_active == 1
