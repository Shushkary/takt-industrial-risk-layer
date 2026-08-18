"""Фикстура INC-002 — компрометация конвейера сборки через фишинг.

Проверяются три вещи: целостность самой фикстуры, корректность её чтения
штатными импортёрами и сборка инцидента пивотом по сущностям
(`takt.domain.engines.incident_pivot`).

Сценарий и контракт данных: `tests/fixtures/pt_techlab/inc_002/README_INC-002.md`
и `data_contract_INC-002.md`.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.domain.engines.incident_pivot import (
    PivotKey,
    assemble_by_pivot,
    entity_keys,
    expand_to_hosts,
)
from takt.infrastructure.importers.nad_events import NadEventSourceReader
from takt.infrastructure.importers.soc_csv import (
    CsvEventSourceReader,
    map_edr,
    map_ndr,
    map_ot,
    map_siem,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pt_techlab" / "inc_002"

# Ожидаемый объём фикстуры (детерминированная генерация, seed=42).
EXPECTED_COUNTS = {"edr": 531, "siem": 240, "ndr": 227, "ot": 32}
EXPECTED_TOTAL = 1030
CHAIN_SIZE = 27
CHAIN_ID = "INC-002"
DISTRACTORS = {"BG-ADMIN", "BG-SCAN", "BG-BACKUP"}
ALLOWED_LABELS = {CHAIN_ID, "BACKGROUND"} | DISTRACTORS

TIME_COLUMN = {"edr": "timestamp", "siem": "event_time", "ndr": "start_time", "ot": "timestamp"}
MAPPERS = {"edr": map_edr, "siem": map_siem, "ndr": map_ndr, "ot": map_ot}

# Сущности, характерные именно для INC-002: скомпрометированные учётные записи,
# инфраструктура C2 и объекты релизного конвейера.
CHAIN_PIVOTS = frozenset({
    PivotKey.of("user_id", "smirnov"),
    PivotKey.of("user_id", "svc_build"),
    PivotKey.of("dst_address", "185.220.101.34"),
    PivotKey.of("artifact:domain", "cdn-metrics.example-analytics.com"),
    PivotKey.of("host_id", "artifact:app-setup.msi"),
    PivotKey.of("host_id", "pipeline:release-prod"),
})

# Узлы, до которых аналитик расширяет разбор на втором шаге.
PIVOT_HOSTS = ("ws-17", "build-srv-01")


def _rows(name: str) -> list[dict[str, str]]:
    with (FIXTURES / f"{name}.csv").open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _events(name: str):
    return list(CsvEventSourceReader(FIXTURES / f"{name}.csv", MAPPERS[name]))


def _all_events():
    return [event for name in MAPPERS for event in _events(name)]


def _label(event) -> str:
    return str(event.payload.get("incident_id") or "")


# --------------------------------------------------------------------------- #
# Целостность фикстуры
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("name", "expected"), sorted(EXPECTED_COUNTS.items()))
def test_fixture_row_counts(name: str, expected: int) -> None:
    assert len(_rows(name)) == expected


def test_fixture_total_is_1030_events() -> None:
    assert sum(len(_rows(name)) for name in EXPECTED_COUNTS) == EXPECTED_TOTAL


@pytest.mark.parametrize("name", sorted(EXPECTED_COUNTS))
def test_timestamps_are_iso8601_utc_and_sorted(name: str) -> None:
    column = TIME_COLUMN[name]
    moments = []
    for row in _rows(name):
        raw = row[column]
        assert raw.endswith("Z"), f"{name}: время без суффикса UTC: {raw}"
        moment = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        moments.append(moment)
    assert moments == sorted(moments), f"{name}: строки не отсортированы по времени"


@pytest.mark.parametrize("name", sorted(EXPECTED_COUNTS))
def test_incident_labels_are_known(name: str) -> None:
    labels = {row["incident_id"] for row in _rows(name)}
    assert labels <= ALLOWED_LABELS, f"{name}: неизвестные метки {labels - ALLOWED_LABELS}"


def test_no_plaintext_passwords_anywhere_in_fixture() -> None:
    """Ни одно поле пароля в фикстуре не содержит открытого значения.

    Проверяются именно значения полей: имя правила `PASSWORD_CHANGE` в SIEM —
    легитимные данные и под запрет не подпадает.
    """
    masked = {"***REDACTED***", "[redacted]"}

    for path in sorted(FIXTURES.glob("*.ndjson")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            credentials = json.loads(line).get("credentials")
            if isinstance(credentials, dict) and credentials.get("password") is not None:
                assert credentials["password"] in masked, (
                    f"{path.name}:{line_number}: пароль не замаскирован"
                )

    for path in sorted(FIXTURES.glob("*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            secret_columns = [
                column for column in (reader.fieldnames or [])
                if "password" in column.lower() or "secret" in column.lower()
            ]
            assert not secret_columns, f"{path.name}: колонка с секретом {secret_columns}"


def test_chain_has_27_events_across_four_sources() -> None:
    events = _all_events()
    assert len(events) == EXPECTED_TOTAL, "импортёры теряют события фикстуры"
    chain = [event for event in events if _label(event) == CHAIN_ID]
    assert len(chain) == CHAIN_SIZE
    assert Counter(str(event.source) for event in chain) == {
        "edr": 10, "ndr": 8, "siem": 7, "ot": 2,
    }


# --------------------------------------------------------------------------- #
# Чтение импортёрами
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("name", "expected"), sorted(EXPECTED_COUNTS.items()))
def test_importers_read_every_row(name: str, expected: int) -> None:
    """Ни одна строка не отбрасывается: новые indicator_type и CI-активы поддержаны."""
    assert len(_events(name)) == expected


def test_ci_assets_and_new_indicator_types_are_preserved() -> None:
    ot_events = [event for event in _events("ot") if _label(event) == CHAIN_ID]
    assets = {event.entities.host_id for event in ot_events}
    assert assets == {"artifact:app-setup.msi", "pipeline:release-prod"}
    assert {event.protocol for event in ot_events} == {"CI_PIPELINE"}

    siem_chain = [event for event in _events("siem") if _label(event) == CHAIN_ID]
    kinds = {artifact.type.value for event in siem_chain for artifact in event.artifacts}
    assert {"spn", "repo"} <= kinds, "новые типы артефактов не сохранились"


def test_nad_ndjson_is_read_and_password_is_masked() -> None:
    events = list(NadEventSourceReader(FIXTURES / "nad_sample.ndjson"))
    assert len(events) == 12

    first = events[0]
    assert first.event_id == "nad-0001"
    assert first.entities.host_id == "ws-17"
    assert first.entities.dst_address == "185.220.101.34"
    assert first.payload_size == 2226
    domains = {a.value for a in first.artifacts if a.type.value == "domain"}
    assert "cdn-metrics.example-analytics.com" in domains

    for event in events:
        payload = json.dumps(event.payload, ensure_ascii=False)
        credentials = event.payload.get("credentials")
        if isinstance(credentials, dict) and "password" in credentials:
            assert credentials["password"] == "[redacted]"
        assert "P@ss" not in payload


# --------------------------------------------------------------------------- #
# Сборка инцидента пивотом
# --------------------------------------------------------------------------- #

def test_pivot_core_is_precise_and_excludes_all_background() -> None:
    """Ядро по отличительным сущностям: только события инцидента, без фона.

    25 из 27: два сетевых потока (SMB ws-17 -> build-srv-01 и HTTPS к git-srv-01)
    отличительных признаков не несут — их узлы и внутренние адреса встречаются в
    фоновом трафике. Они присоединяются на втором шаге.
    """
    events = _all_events()
    core = assemble_by_pivot(events, CHAIN_PIVOTS)
    labels = Counter(_label(event) for event in core)

    assert set(labels) == {CHAIN_ID}, f"в ядро попал фон: {dict(labels)}"
    assert labels[CHAIN_ID] == 25
    assert core == sorted(core, key=lambda event: (event.observed_at, event.event_id))


def test_pivot_core_covers_every_attack_phase() -> None:
    """Ядро охватывает весь путь: фишинг -> C2 -> kerberoasting -> lateral -> CI."""
    core = assemble_by_pivot(_all_events(), CHAIN_PIVOTS)
    operations = {event.operation for event in core}
    for expected in (
        "PROCESS_START",              # фишинг и запуск нагрузки
        "C2_SUSPECT",                 # управляющий канал по DoH
        "KERBEROS_TGS_RC4",           # kerberoasting
        "REMOTE_EXEC_WMI",            # горизонтальное перемещение
        "ARTIFACT_HASH_MISMATCH",     # подмена артефакта сборки
        "UNSIGNED_ARTIFACT_PUSH",     # неподписанная сборка в релиз
        "CODE_REPO_WRITE_OFFHOURS",   # запись в репозиторий вне окна работ
    ):
        assert expected in operations, f"фаза {expected} не попала в ядро"


def test_pivot_chain_connects_expected_entities() -> None:
    """Цепочка ведёт smirnov -> ws-17 -> svc_build -> build-srv-01 -> release-prod."""
    core = assemble_by_pivot(_all_events(), CHAIN_PIVOTS)
    keys = {key for event in core for key in entity_keys(event)}
    for field, value in (
        ("user_id", "smirnov"),
        ("host_id", "ws-17"),
        ("user_id", "svc_build"),
        ("host_id", "build-srv-01"),
        ("host_id", "pipeline:release-prod"),
    ):
        assert PivotKey.of(field, value) in keys, f"нет сущности {field}={value}"


def test_host_pivot_completes_chain_without_touching_distractors() -> None:
    """Второй шаг добирает оставшиеся потоки и не втягивает отвлекающие сценарии.

    Вместе с ними приходит легитимная активность тех же узлов в окне инцидента —
    это ожидаемо и отсеивается аналитиком. Принципиально другое: BG-ADMIN,
    BG-SCAN и BG-BACKUP, специально похожие на атаку, не попадают вовсе.
    """
    events = _all_events()
    core = assemble_by_pivot(events, CHAIN_PIVOTS)
    expanded = expand_to_hosts(events, core, PIVOT_HOSTS)
    labels = Counter(_label(event) for event in expanded)

    assert labels[CHAIN_ID] == CHAIN_SIZE, "цепочка собрана не полностью"
    assert DISTRACTORS.isdisjoint(labels), f"втянуты отвлекающие сценарии: {dict(labels)}"
    # Легитимный фон тех же узлов допустим, но не должен доминировать.
    assert labels["BACKGROUND"] < labels[CHAIN_ID]
