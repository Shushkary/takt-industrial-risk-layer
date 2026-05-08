from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "close_operational_tails.py"
    spec = importlib.util.spec_from_file_location("ops_tail_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_close_operational_tails_writes_evidence_markdown(tmp_path: Path) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    out = tmp_path / "evidence.md"
    rc = run(db, out, apply_migrate=True)
    assert rc == 0
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Operational tails evidence" in text
    assert "backup_path:" in text
    assert "migrate_done: `true`" in text
    assert "forensic_verify_ok: `true`" in text
    assert "forensic_signing_unavailable: `false`" in text
    assert "gossopka_official_ok: `true`" in text
    assert "audit_engagement_api_ok: `true`" in text
