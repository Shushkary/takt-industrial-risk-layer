from pathlib import Path

p = Path(__file__).resolve().parents[1] / "tests" / "test_api.py"
t = p.read_text(encoding="utf-8")
old = """    monkeypatch.setattr(\"takt.interface_adapters.api.main.load_risk_weights\", fake_load)
    client = TestClient(create_app())
        h = client.get(\"/health\").json()
    assert h[\"export_pdf_unicode_font_configured\"] is True"""
new = """    monkeypatch.setattr(\"takt.interface_adapters.api.main.load_risk_weights\", fake_load)
    h = TestClient(create_app()).get(\"/health\").json()
    assert h[\"export_pdf_unicode_font_configured\"] is True"""
if old not in t:
    raise SystemExit("pattern not found")
p.write_text(t.replace(old, new, 1), encoding="utf-8")
print("fixed")
