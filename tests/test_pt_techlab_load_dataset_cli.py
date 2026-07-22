from __future__ import annotations

from pathlib import Path

from takt.tools import load_dataset


def test_cli_streams_fixture_through_ingest(monkeypatch, capsys) -> None:
    fixture = Path(__file__).parent / "fixtures" / "pt_techlab" / "edr.csv"

    class Facade:
        def __init__(self) -> None:
            self.ids: list[str] = []

        def assess_normalized_event(self, event, **kwargs) -> None:
            self.ids.append(event.event_id)

    facade = Facade()
    state = type("State", (), {"trust_by_source": {"edr": 0.8}, "ingest_facade": facade})()
    app = type("App", (), {"state": state})()
    monkeypatch.setattr(load_dataset, "create_app", lambda: app)

    assert load_dataset.run(source="edr", path=fixture, progress_every=1) == 0
    assert facade.ids == ["edr-001", "edr-002"]
    assert "complete source=edr processed=2 failed=0" in capsys.readouterr().out
