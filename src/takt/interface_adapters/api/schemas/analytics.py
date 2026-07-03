from __future__ import annotations

from pydantic import BaseModel


class BacktestFixtureResponse(BaseModel):
    events_processed: int
    cases_created: int
    merges: int
    risk_class_histogram: dict[str, int]
