from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "fill_prod_ready_from_evidence.py"
    spec = importlib.util.spec_from_file_location("fill_prod_ready_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_fill_prod_ready_from_evidence_updates_target_fields(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.md"
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "## Ready-to-copy fields",
                "- backup_path: `dist/backup.sqlite`",
                "- migrate_done: `true`",
                "- smoke_case_id: `abc12345`",
                "- forensic_verify_ok: `true`",
                "- forensic_signing_unavailable: `false`",
                "- gossopka_official_ok: `true`",
                "- audit_engagement_api_ok: `true`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
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

    run = _load_run()
    rc = run(evidence, prod, forensic_mode="external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)")
    assert rc == 0
    text = prod.read_text(encoding="utf-8")
    assert "## 2) Manual input required (4 поля)" in text
    assert "`dist/backup.sqlite`" in text
    assert "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | `true` |" in text
    assert (
        "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | "
        "`external (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)` |"
    ) in text
    assert (
        "case_id=abc12345; gossopka_official_ok=true; forensic_signing_unavailable=false; "
        "forensic_verify_ok=true; audit_engagement_api_ok=true"
    ) in text


def test_fill_prod_ready_from_evidence_uses_fallbacks_for_missing_fields(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.md"
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "## Ready-to-copy fields",
                "- backup_path: ``",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
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

    run = _load_run()
    rc = run(evidence, prod, forensic_mode="")
    assert rc == 0
    text = prod.read_text(encoding="utf-8")
    assert "| 5. Backup БД выполнен (путь к backup) | `N/A` |" in text
    assert "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | `unknown` |" in text
    assert (
        "| 8. Smoke-check после выкладки (ссылка/лог) | "
        "`case_id=; gossopka_official_ok=; forensic_signing_unavailable=; forensic_verify_ok=; "
        "audit_engagement_api_ok=` |"
    ) in text


def test_fill_prod_ready_normalizes_absolute_backup_path(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.md"
    backup = tmp_path / "dist" / "ops.backup.sqlite"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_text("", encoding="utf-8")
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "## Ready-to-copy fields",
                f"- backup_path: `{backup}`",
                "- migrate_done: `true`",
                "- smoke_case_id: `abc12345`",
                "- forensic_verify_ok: `true`",
                "- forensic_signing_unavailable: `false`",
                "- gossopka_official_ok: `true`",
                "- audit_engagement_api_ok: `true`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    prod = tmp_path / "docs" / "releases" / "prod_ready.md"
    prod.parent.mkdir(parents=True, exist_ok=True)
    prod.write_text(
        "\n".join(
            [
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    run = _load_run()
    rc = run(evidence, prod, forensic_mode="HMAC (TAKT_FORENSIC_HMAC_SECRET)")
    assert rc == 0
    text = prod.read_text(encoding="utf-8")
    assert "| 5. Backup БД выполнен (путь к backup) | `dist/ops.backup.sqlite` |" in text


def test_fill_prod_ready_detects_gost_strict_mode_from_env(
    tmp_path: Path, monkeypatch
) -> None:
    evidence = tmp_path / "evidence.md"
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "## Ready-to-copy fields",
                "- backup_path: `dist/backup.sqlite`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.setenv("TAKT_FORENSIC_SIGN_URL", "https://crypto.example/sign")
    monkeypatch.setenv("TAKT_FORENSIC_VERIFY_URL", "https://crypto.example/verify")
    run = _load_run()
    rc = run(evidence, prod, forensic_mode="")
    assert rc == 0
    text = prod.read_text(encoding="utf-8")
    assert (
        "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | "
        "`gost_strict (TAKT_FORENSIC_SIGN_URL + TAKT_FORENSIC_VERIFY_URL)` |"
    ) in text


def test_fill_prod_ready_marks_gost_strict_as_misconfigured_when_signer_env_missing(
    tmp_path: Path, monkeypatch
) -> None:
    evidence = tmp_path / "evidence.md"
    evidence.write_text(
        "\n".join(
            [
                "# Operational tails evidence (x)",
                "## Ready-to-copy fields",
                "- backup_path: `dist/backup.sqlite`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TAKT_FORENSIC_CRYPTO_MODE", "gost_strict")
    monkeypatch.delenv("TAKT_FORENSIC_SIGN_URL", raising=False)
    monkeypatch.delenv("TAKT_FORENSIC_VERIFY_URL", raising=False)
    run = _load_run()
    rc = run(evidence, prod, forensic_mode="")
    assert rc == 0
    text = prod.read_text(encoding="utf-8")
    assert (
        "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | "
        "`gost_strict (misconfigured: missing sign/verify env)` |"
    ) in text
