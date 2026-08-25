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


def _facade_app(monkeypatch, trust: dict[str, float]):
    """Подменённое приложение: фасад приёма записывает то, с чем его позвали."""

    class Facade:
        def __init__(self) -> None:
            self.events: list = []
            self.kwargs: list[dict] = []

        def assess_normalized_event(self, event, **kwargs) -> None:
            self.events.append(event)
            self.kwargs.append(kwargs)

    facade = Facade()
    state = type("State", (), {"trust_by_source": trust, "ingest_facade": facade})()
    app = type("App", (), {"state": state})()
    monkeypatch.setattr(load_dataset, "create_app", lambda: app)
    return facade


def test_cli_reads_the_nad_ndjson_export(monkeypatch, capsys) -> None:
    """Выгрузка PT NAD приходит построчным NDJSON, а не CSV.

    Читатель выгрузки в продукте был, а точки входа для него не было: на стенде это
    выяснилось бы в момент, когда данные уже выгружены и нужно их принять.
    """
    fixture = Path(__file__).parent / "fixtures" / "pt_techlab" / "inc_002" / "nad_sample.ndjson"

    facade = _facade_app(monkeypatch, {"ndr": 0.9})
    assert load_dataset.run(source="nad", path=fixture, progress_every=1) == 0

    assert facade.events, "ни одного события из выгрузки не принято"
    assert {event.source.value for event in facade.events} == {"ndr"}
    assert f"complete source=nad processed={len(facade.events)} failed=0" in capsys.readouterr().out


def test_trust_is_keyed_by_the_source_class_not_by_the_cli_name(monkeypatch) -> None:
    """Имя в командной строке — формат выгрузки, доверие настраивается по классу события.

    Выгрузка NAD приходит в класс `ndr`, файл потоков, прочитанный как Netflow, — в
    `network_events`. Пока доверие передавалось под именем из командной строки, для этих
    двух источников оно не находилось и молча подменялось значением по умолчанию.
    """
    fixture = Path(__file__).parent / "fixtures" / "pt_techlab" / "inc_002" / "nad_sample.ndjson"

    configured = {"ndr": 0.9, "edr": 0.8}
    facade = _facade_app(monkeypatch, configured)
    assert load_dataset.run(source="nad", path=fixture, progress_every=0) == 0

    assert facade.kwargs, "фасад приёма не вызывался"
    for kwargs in facade.kwargs:
        assert kwargs["trust_by_source"] == configured


def test_nad_is_offered_among_the_sources() -> None:
    """Источник виден в справке команды, иначе о нём узнают только из кода."""
    parser = load_dataset.build_parser()
    action = next(item for item in parser._actions if item.dest == "source")
    assert "nad" in action.choices
