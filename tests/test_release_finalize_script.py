from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "release_finalize.py"
    spec = importlib.util.spec_from_file_location("release_finalize_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_release_finalize_generates_evidence_and_fills_prod_ready(tmp_path: Path) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="HMAC (TAKT_FORENSIC_HMAC_SECRET)",
    )
    assert rc == 0
    assert evidence.is_file()
    text = prod.read_text(encoding="utf-8")
    assert "_(заполнить)_" not in "\n".join([ln for ln in text.splitlines() if ln.startswith(("| 5.", "| 6.", "| 7.", "| 8."))])


def test_release_finalize_fails_if_policy_violated(tmp_path: Path) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="_(заполнить)_",
    )
    assert rc == 2


def test_release_finalize_strict_fails_when_sbom_missing(tmp_path: Path) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[1]
    sbom = repo_root / "dist" / "sbom.cyclonedx.json"
    backup = sbom.with_suffix(".json.bak_test")
    try:
        if sbom.exists():
            if backup.exists():
                backup.unlink()
            sbom.rename(backup)
        rc = run(
            db,
            evidence,
            prod,
            apply_migrate=True,
            forensic_mode="HMAC (TAKT_FORENSIC_HMAC_SECRET)",
            strict=True,
            strict_generate_sbom=False,
        )
        assert rc == 2
    finally:
        if backup.exists():
            if sbom.exists():
                sbom.unlink()
            backup.rename(sbom)


def test_release_finalize_fails_when_forensic_signing_unavailable_is_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            raise RuntimeError("signer unavailable")
        if str(url).endswith("/verify"):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"ok": True})
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2


def test_release_finalize_reports_forensic_signing_unavailable_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            raise RuntimeError("signer unavailable")
        if str(url).endswith("/verify"):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"ok": True})
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "release_reason=pre-release smoke failed: forensic_signing_unavailable is true" in out


def test_release_finalize_reports_forensic_verify_failure_when_signing_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _load_run()
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def _fake_post(url, json, timeout):
        if str(url).endswith("/sign"):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "algorithm": "GOST-R-34.10-2012",
                    "signature": "BASE64SIG",
                    "key_id": "kzp-1",
                },
            )
        if str(url).endswith("/verify"):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"ok": True})
        raise AssertionError("unexpected URL")

    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    monkeypatch.setattr("takt.infrastructure.security.root_hash_signature.httpx.post", _fake_post)
    monkeypatch.setattr(
        "takt.infrastructure.export.forensic_bundle.ZipForensicBundleVerifier.verify_bundle",
        lambda self, raw: SimpleNamespace(
            ok=False,
            case_id="",
            root_hash_sha256="",
            signature_status="external_gost2012_detached",
            checked_items=0,
            issues=(),
        ),
    )

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "release_reason=pre-release smoke failed: forensic_verify_ok is not true" in out


def test_release_finalize_reports_audit_engagement_failure_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "release_finalize.py"
    spec = importlib.util.spec_from_file_location("release_finalize_script_for_reason", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = module.run
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "- gossopka_official_ok: `true`",
                "- forensic_signing_unavailable: `false`",
                "- forensic_verify_ok: `true`",
                "- audit_engagement_api_ok: `false`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "_required_artifact_paths", lambda root: [])

    def _fake_loader(script_name: str, function_name: str):
        if script_name == "close_operational_tails.py":
            return lambda db_path, evidence_path, *, apply_migrate: 0
        if script_name == "fill_prod_ready_from_evidence.py":
            return lambda evidence_path, prod_ready_path, *, forensic_mode="": 0
        if script_name == "validate_prod_ready.py":
            return lambda prod_ready_path: 0
        raise AssertionError(f"unexpected loader request: {script_name}:{function_name}")

    monkeypatch.setattr(module, "_load_script_function", _fake_loader)

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "release_reason=pre-release smoke failed: audit_engagement_api_ok is not true" in out


def test_release_finalize_prioritizes_forensic_signing_unavailable_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "release_finalize.py"
    spec = importlib.util.spec_from_file_location("release_finalize_script_for_priority", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = module.run
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "- gossopka_official_ok: `true`",
                "- forensic_signing_unavailable: `true`",
                "- forensic_verify_ok: `false`",
                "- audit_engagement_api_ok: `false`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "_required_artifact_paths", lambda root: [])

    def _fake_loader(script_name: str, function_name: str):
        if script_name == "close_operational_tails.py":
            return lambda db_path, evidence_path, *, apply_migrate: 0
        if script_name == "fill_prod_ready_from_evidence.py":
            return lambda evidence_path, prod_ready_path, *, forensic_mode="": 0
        if script_name == "validate_prod_ready.py":
            return lambda prod_ready_path: 0
        raise AssertionError(f"unexpected loader request: {script_name}:{function_name}")

    monkeypatch.setattr(module, "_load_script_function", _fake_loader)

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "release_reason=pre-release smoke failed: forensic_signing_unavailable is true" in out


def test_release_finalize_reports_gossopka_failure_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "release_finalize.py"
    spec = importlib.util.spec_from_file_location("release_finalize_script_for_gossopka", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = module.run
    db = tmp_path / "ops.db"
    evidence = tmp_path / "evidence.md"
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "- gossopka_official_ok: `false`",
                "- forensic_signing_unavailable: `false`",
                "- forensic_verify_ok: `true`",
                "- audit_engagement_api_ok: `true`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "_required_artifact_paths", lambda root: [])

    def _fake_loader(script_name: str, function_name: str):
        if script_name == "close_operational_tails.py":
            return lambda db_path, evidence_path, *, apply_migrate: 0
        if script_name == "fill_prod_ready_from_evidence.py":
            return lambda evidence_path, prod_ready_path, *, forensic_mode="": 0
        if script_name == "validate_prod_ready.py":
            return lambda prod_ready_path: 0
        raise AssertionError(f"unexpected loader request: {script_name}:{function_name}")

    monkeypatch.setattr(module, "_load_script_function", _fake_loader)

    rc = run(
        db,
        evidence,
        prod,
        apply_migrate=True,
        forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)",
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "release_reason=pre-release smoke failed: gossopka_official_ok is not true" in out
