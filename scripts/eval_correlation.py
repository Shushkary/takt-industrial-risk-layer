from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from takt.domain.engines.alert_fatigue import correlation_fingerprints, correlation_rules_from_config
from takt.domain.engines.correlation_quality import connected_groups, pairwise_correlation_metrics
from takt.domain.entities.event import ArtifactType, EventArtifact, EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.security.sha256_hasher import Sha256HasherAdapter

_hasher = Sha256HasherAdapter()

DEFAULT_RULES = correlation_rules_from_config({"keys": [
    {"name": "host", "fields": ["host_id"], "bucket_sec": 600, "priority": 10},
    {"name": "hash", "fields": ["artifact:hash"], "priority": 20},
]})


def evaluate(path: Path) -> dict[str, float | int]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    keys: dict[str, list[str]] = {}
    expected: dict[str, str] = {}
    for row in rows:
        artifacts = (EventArtifact(ArtifactType.HASH, row["hash"]),) if row.get("hash") else ()
        event = NormalizedEvent(
            event_id=row["event_id"], observed_at=datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00")),
            source=EventSource(row["source"]), protocol="fixture", operation="OBSERVED", payload_size=0, payload=row,
            entities=EventEntities(host_id=row.get("host_id")), artifacts=artifacts,
        )
        keys[event.event_id] = correlation_fingerprints(event, DEFAULT_RULES, hasher=_hasher)
        expected[event.event_id] = row["incident_id"]
    metrics = pairwise_correlation_metrics(expected, connected_groups(keys))
    return {
        "events": len(rows), "true_positive": metrics.true_positive,
        "false_positive": metrics.false_positive, "false_negative": metrics.false_negative,
        "pairwise_precision": metrics.precision, "pairwise_recall": metrics.recall,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=Path("tests/fixtures/pt_techlab/correlation/scenarios.json"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.fixture), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
