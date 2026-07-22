from __future__ import annotations

import csv
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures" / "pt_techlab"


def test_sprint0_fixture_is_parseable_and_balanced() -> None:
    expected = {"edr.csv": 2, "siem.csv": 2, "ndr.csv": 2, "ot.csv": 2}
    for name, count in expected.items():
        with (FIXTURES / name).open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        assert len(rows) == count
        assert all(row.get("incident_id") for row in rows)
        assert sum(row["incident_id"] == "INC-001" for row in rows) == 1
