from __future__ import annotations

import pytest

from takt.infrastructure.config.weights_loader import load_risk_weights


def test_load_risk_weights_file_not_found(tmp_path) -> None:
    missing = tmp_path / "missing.yaml"
    with pytest.raises(FileNotFoundError, match="not found"):
        load_risk_weights(missing)


def test_load_risk_weights_valid_mapping(tmp_path) -> None:
    p = tmp_path / "risk.yaml"
    p.write_text("rhythm: 0.2\ncontext: 0.3\n", encoding="utf-8")
    d = load_risk_weights(p)
    assert d == {"rhythm": 0.2, "context": 0.3}


@pytest.mark.parametrize(
    "content",
    [
        "[1, 2, 3]",
        "null",
        "plain_string",
    ],
)
def test_load_risk_weights_rejects_non_mapping(tmp_path, content: str) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_risk_weights(p)


def test_load_risk_weights_validates_known_fields(tmp_path) -> None:
    p = tmp_path / "bad-shape.yaml"
    p.write_text(
        "rhythm: 0.2\ngraph: 0.2\ncontext: 0.2\nuser: 0.2\ndata_quality: 0.2\nstorage:\n  backend: sqlite\n  sqlite_path: 123\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="validation error"):
        load_risk_weights(p)

