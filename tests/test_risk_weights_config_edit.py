"""Правка весов оценки риска из окна: файл, проверки, маршруты API.

Веса — конфигурация, а не состояние обучаемой модели, и правит их человек. До сих пор
единственным способом была правка `config/risk_weights.yaml` на сервере; окно даёт тот же
набор в форме, но не другой механизм: тот же файл, та же метка версии, та же роль.

Главное, что здесь закреплено:

- **Комментарии файла переживают правку.** В `risk_weights.yaml` записано, почему пороги
  именно такие; перезапись через `yaml.safe_dump` стёрла бы объяснение молча.
- **Версия поднимается всегда.** Иначе два разных набора весов назывались бы в отчёте
  разметки одинаково, и предложение изменить правило потеряло бы привязку.
- **Правка — административная операция.** Веса меняют оценку всех последующих дел.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml

from takt.infrastructure.config.weights_writer import (
    WeightsRewriteError,
    next_version,
    rewrite_risk_weights,
    validate,
)

_CONFIG = Path(__file__).resolve().parents[1] / "config" / "risk_weights.yaml"

_BALANCED = {"rhythm": 0.22, "graph": 0.22, "context": 0.18, "user": 0.18, "data_quality": 0.20}
_THRESHOLDS = {"critical": 0.85, "high": 0.65, "medium": 0.40}


def test_weights_must_sum_to_one() -> None:
    """Балл риска — доля шкалы 0..1: при другой сумме пороги перестают быть процентами шкалы."""
    with pytest.raises(WeightsRewriteError, match="сумма весов"):
        validate({**_BALANCED, "rhythm": 0.50}, _THRESHOLDS)


def test_thresholds_must_grow() -> None:
    """Порог «высокого» выше «критического» сделал бы класс критического недостижимым."""
    with pytest.raises(WeightsRewriteError, match="по возрастанию"):
        validate(_BALANCED, {"critical": 0.50, "high": 0.65, "medium": 0.40})


def test_weight_out_of_range_is_refused() -> None:
    with pytest.raises(WeightsRewriteError, match="вне диапазона"):
        validate({**_BALANCED, "rhythm": -0.02, "graph": 0.46}, _THRESHOLDS)


def test_version_grows_within_the_month() -> None:
    assert next_version("2026.09.1", date(2026, 9, 3)) == "2026.09.2"
    assert next_version("2026.09.9", date(2026, 9, 30)) == "2026.09.10"


def test_version_restarts_in_a_new_month() -> None:
    assert next_version("2026.09.4", date(2026, 10, 1)) == "2026.10.1"
    assert next_version("", date(2026, 10, 1)) == "2026.10.1"


def test_rewrite_keeps_every_comment_of_the_real_config() -> None:
    """Файл объясняет, откуда взялись числа; правка одного числа не должна стирать разбор."""
    source = _CONFIG.read_text(encoding="utf-8")
    comments = [line for line in source.split("\n") if line.lstrip().startswith("#")]

    result = rewrite_risk_weights(
        source,
        weights={"rhythm": 0.30, "graph": 0.20, "context": 0.18, "user": 0.12, "data_quality": 0.20},
        thresholds={"critical": 0.90, "high": 0.60, "medium": 0.30},
        version="2026.09.2",
    )

    assert [line for line in result.split("\n") if line.lstrip().startswith("#")] == comments


def test_rewrite_changes_only_the_named_keys() -> None:
    """Остальная конфигурация — корреляция, хранилище, инварианты — остаётся как была."""
    source = _CONFIG.read_text(encoding="utf-8")
    before = yaml.safe_load(source)

    after = yaml.safe_load(
        rewrite_risk_weights(
            source,
            weights={"rhythm": 0.30, "graph": 0.20, "context": 0.18, "user": 0.12, "data_quality": 0.20},
            thresholds={"critical": 0.90, "high": 0.60, "medium": 0.30},
            version="2026.09.2",
        )
    )

    assert after["rhythm"] == 0.30
    assert after["user"] == 0.12
    assert after["risk_class_thresholds"] == {"critical": 0.90, "high": 0.60, "medium": 0.30}
    assert after["version"] == "2026.09.2"

    changed = {"rhythm", "graph", "context", "user", "data_quality", "risk_class_thresholds", "version"}
    for key, value in before.items():
        if key not in changed:
            assert after[key] == value, key


def test_rewrite_refuses_a_set_it_cannot_validate() -> None:
    """Частично применённая правка оставила бы файл в наборе, которого никто не назначал."""
    source = _CONFIG.read_text(encoding="utf-8")
    with pytest.raises(WeightsRewriteError):
        rewrite_risk_weights(
            source,
            weights={"rhythm": 0.9, "graph": 0.9, "context": 0.9, "user": 0.9, "data_quality": 0.9},
            thresholds=_THRESHOLDS,
            version="2026.09.2",
        )


# --- Маршруты API ----------------------------------------------------------


def _client_on_copy(tmp_path: Path, monkeypatch, keys_env: str):
    """Приложение поверх копии конфигурации: боевой файл тесты не правят."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    copy = tmp_path / "risk_weights.yaml"
    copy.write_text(_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setenv("TAKT_CONFIG", str(copy))
    monkeypatch.setenv("TAKT_API_KEYS", keys_env)
    monkeypatch.delenv("TAKT_API_KEY", raising=False)
    return TestClient(create_app()), copy


_ADMIN_KEY = "adm-secret-key-32chars-long!!!"
_L2_KEY = "l2-secret-key-32chars-long!!!!!"
_KEYS = f"{_ADMIN_KEY}:carol:admin,{_L2_KEY}:dave:analyst_l2"


def _body(**over) -> dict:
    payload = {
        "weights": dict(_BALANCED),
        "thresholds": dict(_THRESHOLDS),
        "reason": "калибровка после разбора смены",
    }
    payload.update(over)
    return payload


def test_read_returns_the_active_set_and_its_version(tmp_path: Path, monkeypatch) -> None:
    client, copy = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    answer = client.get("/config/risk-weights", headers={"X-TAKT-API-Key": _L2_KEY})

    assert answer.status_code == 200
    data = answer.json()
    on_disk = yaml.safe_load(copy.read_text(encoding="utf-8"))
    assert data["version"] == on_disk["version"]
    assert data["weights"]["rhythm"] == on_disk["rhythm"]
    assert data["thresholds"]["critical"] == on_disk["risk_class_thresholds"]["critical"]
    assert data["config_path"].endswith("risk_weights.yaml")


def test_write_needs_the_administrator_role(tmp_path: Path, monkeypatch) -> None:
    """Правка меняет оценку всех последующих дел — это настройка продукта, а не шаг разбора."""
    client, _ = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    answer = client.put("/config/risk-weights", json=_body(), headers={"X-TAKT-API-Key": _L2_KEY})

    assert answer.status_code == 403


def test_write_raises_the_configuration_version(tmp_path: Path, monkeypatch) -> None:
    """Без поднятия версии два разных набора назывались бы в отчёте разметки одинаково."""
    client, copy = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    before = yaml.safe_load(copy.read_text(encoding="utf-8"))["version"]

    answer = client.put(
        "/config/risk-weights",
        json=_body(weights={"rhythm": 0.30, "graph": 0.20, "context": 0.18, "user": 0.12, "data_quality": 0.20}),
        headers={"X-TAKT-API-Key": _ADMIN_KEY},
    )

    assert answer.status_code == 200
    after = yaml.safe_load(copy.read_text(encoding="utf-8"))
    assert after["version"] != before
    assert after["rhythm"] == 0.30
    assert answer.json()["version"] == after["version"]


def test_written_set_is_visible_at_once(tmp_path: Path, monkeypatch) -> None:
    """Правка без перезапуска: иначе окно показывало бы один набор, а оценка шла бы по другому."""
    client, _ = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    client.put(
        "/config/risk-weights",
        json=_body(thresholds={"critical": 0.90, "high": 0.60, "medium": 0.30}),
        headers={"X-TAKT-API-Key": _ADMIN_KEY},
    )

    data = client.get("/config/risk-weights", headers={"X-TAKT-API-Key": _ADMIN_KEY}).json()
    assert data["thresholds"] == {"critical": 0.90, "high": 0.60, "medium": 0.30}


def test_unbalanced_set_is_refused_and_the_file_stays_as_it_was(tmp_path: Path, monkeypatch) -> None:
    client, copy = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    before = copy.read_text(encoding="utf-8")

    answer = client.put(
        "/config/risk-weights",
        json=_body(weights={"rhythm": 0.50, "graph": 0.22, "context": 0.18, "user": 0.18, "data_quality": 0.20}),
        headers={"X-TAKT-API-Key": _ADMIN_KEY},
    )

    assert answer.status_code == 422
    assert copy.read_text(encoding="utf-8") == before


def test_reason_is_required(tmp_path: Path, monkeypatch) -> None:
    """По журналу должно быть видно, кто и зачем менял веса."""
    client, _ = _client_on_copy(tmp_path, monkeypatch, _KEYS)
    answer = client.put(
        "/config/risk-weights",
        json=_body(reason=""),
        headers={"X-TAKT-API-Key": _ADMIN_KEY},
    )

    assert answer.status_code == 422


def test_two_decimal_values_keep_their_shape(tmp_path: Path) -> None:
    """`0.20` не превращается в `0.2`: в столбце весов разнобой в разрядах читается как случайные числа."""
    source = _CONFIG.read_text(encoding="utf-8")
    result = rewrite_risk_weights(source, weights=_BALANCED, thresholds=_THRESHOLDS, version="2026.09.2")

    assert "data_quality: 0.20" in result
    assert "  medium: 0.40" in result


def test_line_endings_survive_the_edit(tmp_path: Path) -> None:
    """Иначе правка одного числа показывает в `git diff` весь файл как изменённый."""
    from takt.infrastructure.config.weights_writer import read_source, write_source

    crlf = tmp_path / "crlf.yaml"
    with crlf.open("w", encoding="utf-8", newline="") as target:
        target.write(_CONFIG.read_text(encoding="utf-8").replace("\n", "\r\n"))

    source, newline = read_source(crlf)
    assert newline == "\r\n"
    write_source(crlf, rewrite_risk_weights(source, weights=_BALANCED, thresholds=_THRESHOLDS, version="2026.09.2"), newline)

    raw = crlf.read_bytes()
    assert b"\r\n" in raw
    assert raw.count(b"\n") == raw.count(b"\r\n")
