"""Слияние кейсов: миграция v0.7.x и поглощение при корреляции на приёме событий."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from datetime import UTC, datetime

from takt.domain.engines.alert_fatigue import case_bucket_burst_fingerprint
from takt.domain.engines.risk_engine import worst_risk_class
from takt.domain.entities.case import Case, CaseStatus, InvariantHitRecord, Observation


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def migration_group_key(case: Case, bucket_sec: int) -> tuple[str, str, int]:
    aid = (case.primary_asset_id or "").strip().lower() or "_"
    op = (case.trigger_operation or "").strip().upper() or "_"
    bucket = int(_utc(case.created_at).timestamp() // bucket_sec)
    return aid, op, bucket


def merge_open_cases_group_v070(group: Sequence[Case], *, bucket_sec: int) -> tuple[Case, list[str]]:
    """
    Объединяет **открытые** кейсы одной группы (уже отфильтрованы по ключу миграции).
    Возвращает выживший кейс и список **case_id** для удаления из БД.
    """
    if len(group) < 2:
        raise ValueError("merge_open_cases_group_v070 expects at least 2 cases")
    ordered = sorted(group, key=lambda c: (_utc(c.created_at), c.case_id))
    survivor = deepcopy(ordered[0])
    dead_ids = [c.case_id for c in ordered[1:]]
    others = ordered[1:]

    all_cases = ordered
    survivor.risk_score = max(c.risk_score for c in all_cases)
    rcls = survivor.risk_class
    for c in others:
        rcls = worst_risk_class(rcls, c.risk_class)
    survivor.risk_class = rcls

    seen_ids: list[str] = []
    for c in all_cases:
        for eid in c.normalized_event_ids:
            if eid not in seen_ids:
                seen_ids.append(eid)
    survivor.normalized_event_ids = seen_ids

    survivor.invariant_hits = sorted(frozenset().union(*(frozenset(c.invariant_hits) for c in all_cases)))

    hit_keys: set[tuple[str, str]] = set()
    merged_records: list[InvariantHitRecord] = []
    for c in all_cases:
        for r in c.invariant_hit_records:
            k = (r.invariant_id, r.event_ref)
            if k in hit_keys:
                continue
            hit_keys.add(k)
            merged_records.append(r)
    survivor.invariant_hit_records = merged_records
    survivor.manual_permits = [p for c in all_cases for p in c.manual_permits]

    by_src: dict[str, Observation] = {}
    for c in all_cases:
        for o in c.observations:
            if o.source not in by_src:
                by_src[o.source] = Observation(source=o.source, ingest_trust=o.ingest_trust, event_ids=[])
            cur = by_src[o.source]
            cur.ingest_trust = max(cur.ingest_trust, o.ingest_trust)
            for eid in o.event_ids:
                if eid not in cur.event_ids:
                    cur.event_ids.append(eid)
    survivor.observations = list(by_src.values())

    best_dq = ordered[0]
    for c in others:
        if c.risk_score > best_dq.risk_score or (
            c.risk_score == best_dq.risk_score and _utc(c.created_at) > _utc(best_dq.created_at)
        ):
            best_dq = c
    survivor.dq_score = best_dq.dq_score
    survivor.dq_partial = best_dq.dq_partial
    survivor.dq_reasons = list(best_dq.dq_reasons)

    latest = max(all_cases, key=lambda c: (_utc(c.created_at), c.case_id))
    survivor.last_event_source = latest.last_event_source
    survivor.xai_summary = max(all_cases, key=lambda c: c.risk_score).xai_summary

    n = len(seen_ids)
    base_title = survivor.title
    if "] " in base_title:
        base_title = base_title.split("] ", 1)[-1]
    survivor.title = f"[x{n}] {base_title}"

    ts_note = _utc(survivor.created_at)
    survivor.append_audit(f"migration v0.7.0 merged cases: {', '.join(dead_ids)}", ts_note)
    for c in others:
        survivor.audit_log.extend(c.audit_log)

    bs = bucket_sec if bucket_sec >= 1 else 300
    survivor.burst_fingerprint = case_bucket_burst_fingerprint(
        primary_asset_id=survivor.primary_asset_id,
        trigger_operation=survivor.trigger_operation,
        created_at=survivor.created_at,
        bucket_sec=bs,
    )
    return survivor, dead_ids


def absorb_correlated_case(
    survivor: Case,
    absorbed: Case,
    *,
    fingerprint: str,
    clock: datetime,
) -> None:
    """Переносит содержимое `absorbed` в `survivor` при корреляции на приёме событий.

    Событие может совпасть сразу с несколькими открытыми делами — например, узел совпал с
    одним делом, а хеш файла с другим. Это и означает, что дела описывают одну цепочку:
    связывающее их событие уже принято. Пока такое пересечение только записывалось ссылкой
    `related_cases`, цепочка атаки оставалась разложенной по десяткам мелких дел, и собрать
    её мог лишь аналитик вручную.

    Правило старшинства не меняется: выживает дело правила с высшим приоритетом, остальные
    получают статус **MERGED** и ссылку на выжившее — состав дела прослеживается по журналу
    в обе стороны, ни одно событие и ни одно срабатывание не теряется.

    Обе карточки изменяются на месте; сохранение — за вызывающим слоем. Порядок записи
    значим: поглощённое дело сохраняется первым, иначе индекс ключей корреляции остаётся
    за ним, а выжившее дело по этим ключам больше не находится.
    """
    if survivor.case_id == absorbed.case_id:
        return

    survivor.normalized_event_ids = list(
        dict.fromkeys([*survivor.normalized_event_ids, *absorbed.normalized_event_ids])
    )
    survivor.invariant_hits = sorted(frozenset(survivor.invariant_hits) | frozenset(absorbed.invariant_hits))

    seen_hits = {(record.invariant_id, record.event_ref) for record in survivor.invariant_hit_records}
    for record in absorbed.invariant_hit_records:
        key = (record.invariant_id, record.event_ref)
        if key in seen_hits:
            continue
        seen_hits.add(key)
        survivor.invariant_hit_records.append(deepcopy(record))

    by_source = {observation.source: observation for observation in survivor.observations}
    for observation in absorbed.observations:
        current = by_source.get(observation.source)
        if current is None:
            survivor.observations.append(deepcopy(observation))
            by_source[observation.source] = survivor.observations[-1]
            continue
        current.ingest_trust = max(current.ingest_trust, observation.ingest_trust)
        for event_id in observation.event_ids:
            if event_id not in current.event_ids:
                current.event_ids.append(event_id)

    survivor.correlation_fingerprints = list(
        dict.fromkeys([*survivor.correlation_fingerprints, *absorbed.correlation_fingerprints])
    )
    survivor.correlation_evidence.extend(deepcopy(absorbed.correlation_evidence))
    survivor.manual_permits.extend(deepcopy(absorbed.manual_permits))
    survivor.findings.extend(deepcopy(absorbed.findings))

    known_artifacts = {(item.type, item.value) for item in survivor.artifacts}
    for artifact in absorbed.artifacts:
        if (artifact.type, artifact.value) in known_artifacts:
            continue
        known_artifacts.add((artifact.type, artifact.value))
        survivor.artifacts.append(deepcopy(artifact))

    known_evidence = {item.sha256 for item in survivor.raw_evidence_refs}
    for evidence in absorbed.raw_evidence_refs:
        if evidence.sha256 in known_evidence:
            continue
        known_evidence.add(evidence.sha256)
        survivor.raw_evidence_refs.append(deepcopy(evidence))

    if absorbed.risk_score > survivor.risk_score:
        survivor.risk_score = absorbed.risk_score
        survivor.risk_class = absorbed.risk_class
    elif absorbed.risk_score == survivor.risk_score:
        survivor.risk_class = worst_risk_class(survivor.risk_class, absorbed.risk_class)

    if not survivor.primary_asset_id and absorbed.primary_asset_id:
        survivor.primary_asset_id = absorbed.primary_asset_id

    survivor.related_cases = list(dict.fromkeys([*survivor.related_cases, absorbed.case_id]))
    survivor.append_audit(
        f"absorbed correlated case {absorbed.case_id} by {fingerprint}", clock
    )

    absorbed.status = CaseStatus.MERGED
    absorbed.related_cases = list(dict.fromkeys([*absorbed.related_cases, survivor.case_id]))
    absorbed.append_audit(
        f"merged into correlated case {survivor.case_id} by {fingerprint}", clock
    )
