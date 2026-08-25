from __future__ import annotations

from datetime import UTC, datetime

from takt.domain.engines.alert_fatigue import correlation_fingerprints, correlation_rules_from_config
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.security.sha256_hasher import Sha256HasherAdapter

_hasher = Sha256HasherAdapter()


def _event(*, source: EventSource, host: str, hash_value: str, minute: int = 1) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"{source.value}-{minute}",
        observed_at=datetime(2026, 6, 1, 9, minute, tzinfo=UTC),
        source=source,
        protocol="test",
        operation="OBSERVED",
        payload_size=1,
        payload={},
        entities=EventEntities(host_id=host),
        artifacts=(EventArtifact(ArtifactType.HASH, hash_value),),
    )


def test_cross_source_host_and_hash_produce_equal_candidates() -> None:
    rules = correlation_rules_from_config(
        {"keys": [
            {"name": "host", "fields": ["host_id"], "bucket_sec": 600, "priority": 10},
            {"name": "hash", "fields": ["artifact:hash"], "priority": 20},
        ]}
    )
    edr = _event(source=EventSource.EDR, host="WS-17", hash_value="ABC")
    ndr = _event(source=EventSource.NDR, host="ws-17", hash_value="abc")
    assert correlation_fingerprints(edr, rules, hasher=_hasher) == correlation_fingerprints(ndr, rules, hasher=_hasher)
    assert len(correlation_fingerprints(edr, rules, hasher=_hasher)) == 2


def test_hash_rule_correlates_independently_of_host() -> None:
    rules = correlation_rules_from_config({"keys": [{"name": "hash", "fields": ["artifact:hash"]}]})
    first = _event(source=EventSource.EDR, host="ws-a", hash_value="abc")
    second = _event(source=EventSource.SIEM, host="ws-b", hash_value="ABC")
    assert correlation_fingerprints(first, rules, hasher=_hasher) == correlation_fingerprints(second, rules, hasher=_hasher)


def test_invalid_or_incomplete_rules_do_not_create_keys() -> None:
    event = _event(source=EventSource.EDR, host="ws-a", hash_value="abc")
    rules = correlation_rules_from_config(
        {"keys": [
            {"fields": ["not_a_field"]},
            {"name": "needs-user", "fields": ["user_id", "host_id"]},
        ]}
    )
    assert correlation_fingerprints(event, rules, hasher=_hasher) == []
