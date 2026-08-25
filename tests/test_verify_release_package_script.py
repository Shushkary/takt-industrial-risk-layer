from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import warnings
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location("verify_release_package_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def _load_run_zip():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location("verify_release_package_script_zip", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_zip


def _load_main():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location("verify_release_package_script_main", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def _load_module(module_name: str = "verify_release_package_script_module"):
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_build_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "build_release_package.py"
    spec = importlib.util.spec_from_file_location("build_release_package_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_verify_release_package_ok_and_detects_tamper(tmp_path: Path) -> None:
    build_run = _load_build_run()
    verify_run = _load_run()
    db = tmp_path / "ops.db"
    package_root = tmp_path / "dist"
    docs = tmp_path / "docs" / "releases"
    docs.mkdir(parents=True, exist_ok=True)
    prod = docs / "prod_ready.md"
    readiness = docs / "readiness.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 РїРѕР»СЏ)",
                "| 5. Backup Р‘Р” РІС‹РїРѕР»РЅРµРЅ (РїСѓС‚СЊ Рє backup) | _(Р·Р°РїРѕР»РЅРёС‚СЊ)_ |",
                "| 6. `db_migrate.py` РІС‹РїРѕР»РЅРµРЅ (РІРµСЂСЃРёСЏ СЃС…РµРјС‹/РІС‹РІРѕРґ) | _(Р·Р°РїРѕР»РЅРёС‚СЊ)_ |",
                "| 7. Р РµР¶РёРј forensic РїРѕРґРїРёСЃРё РІ prod (`mvp` РёР»Рё `gost_strict` + env) | _(Р·Р°РїРѕР»РЅРёС‚СЊ)_ |",
                "| 8. Smoke-check РїРѕСЃР»Рµ РІС‹РєР»Р°РґРєРё (СЃСЃС‹Р»РєР°/Р»РѕРі) | _(Р·Р°РїРѕР»РЅРёС‚СЊ)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    readiness.write_text("# readiness\n", encoding="utf-8")
    rc = build_run(
        db,
        package_root=package_root,
        prod_ready=prod,
        readiness=readiness,
        apply_migrate=True,
        strict=False,
        strict_generate_sbom=False,
    )
    assert rc == 0
    package_dir = next(p for p in package_root.iterdir() if p.is_dir() and p.name.startswith("release-package-"))
    assert verify_run(package_dir) == 0

    evidence = package_dir / "operational_tails_evidence.md"
    evidence.write_text(evidence.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
    assert verify_run(package_dir) == 2


def test_verify_release_package_zip_ok_and_detects_tamper(tmp_path: Path) -> None:
    build_run = _load_build_run()
    verify_zip = _load_run_zip()
    db = tmp_path / "ops.db"
    package_root = tmp_path / "dist"
    docs = tmp_path / "docs" / "releases"
    docs.mkdir(parents=True, exist_ok=True)
    prod = docs / "prod_ready.md"
    readiness = docs / "readiness.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 Р С—Р С•Р В»РЎРЏ)",
                "| 5. Backup Р вЂР вЂќ Р Р†РЎвЂ№Р С—Р С•Р В»Р Р…Р ВµР Р… (Р С—РЎС“РЎвЂљРЎРЉ Р С” backup) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 6. `db_migrate.py` Р Р†РЎвЂ№Р С—Р С•Р В»Р Р…Р ВµР Р… (Р Р†Р ВµРЎР‚РЎРѓР С‘РЎРЏ РЎРѓРЎвЂ¦Р ВµР СРЎвЂ№/Р Р†РЎвЂ№Р Р†Р С•Р Т‘) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 7. Р В Р ВµР В¶Р С‘Р С forensic Р С—Р С•Р Т‘Р С—Р С‘РЎРѓР С‘ Р Р† prod (`mvp` Р С‘Р В»Р С‘ `gost_strict` + env) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 8. Smoke-check Р С—Р С•РЎРѓР В»Р Вµ Р Р†РЎвЂ№Р С”Р В»Р В°Р Т‘Р С”Р С‘ (РЎРѓРЎРѓРЎвЂ№Р В»Р С”Р В°/Р В»Р С•Р С–) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    readiness.write_text("# readiness\n", encoding="utf-8")
    rc = build_run(
        db,
        package_root=package_root,
        prod_ready=prod,
        readiness=readiness,
        apply_migrate=True,
        strict=False,
        strict_generate_sbom=False,
    )
    assert rc == 0
    package_dir = next(p for p in package_root.iterdir() if p.is_dir() and p.name.startswith("release-package-"))
    package_zip = package_dir.with_suffix(".zip")
    assert verify_zip(package_zip) == 0

    tampered_dir = tmp_path / "tampered"
    shutil.copytree(package_dir, tampered_dir)
    evidence = tampered_dir / "operational_tails_evidence.md"
    evidence.write_text(evidence.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
    tampered_zip = tmp_path / "tampered.zip"
    with ZipFile(tampered_zip, "w", ZIP_DEFLATED) as zf:
        for path in tampered_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(tampered_dir))
    assert verify_zip(tampered_zip) == 2


def test_verify_release_package_rejects_manifest_path_escape(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "evidence.md").write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["../outside.txt"],
        "sha256": {"../outside.txt": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_invalid_manifest_json(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "manifest.json").write_text("{not json\n", encoding="utf-8")

    assert verify_run(package_dir) == 2


def test_verify_release_package_zip_rejects_path_escape(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "bad.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"included_files":["evidence.md"],"sha256":{}}\n')
        zf.writestr("../outside.txt", "outside\n")

    assert verify_zip(package_zip) == 2


def test_verify_release_package_zip_rejects_invalid_manifest_json(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "invalid-manifest.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", "{not json\n")

    assert verify_zip(package_zip) == 2


def test_verify_release_package_zip_rejects_invalid_zip_file(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "not-a-zip.zip"
    package_zip.write_text("not a zip\n", encoding="utf-8")

    assert verify_zip(package_zip) == 2


def test_verify_release_package_zip_rejects_duplicate_entries(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "duplicate.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["evidence.md"],"sha256":{"evidence.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr("evidence.md", "first\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            zf.writestr("evidence.md", "second\n")

    assert verify_zip(package_zip) == 2


def test_verify_release_package_zip_rejects_symlink_entry(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "symlink.zip"
    symlink_info = ZipInfo("linked.md")
    symlink_info.external_attr = 0o120777 << 16
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["linked.md"],"sha256":{"linked.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr(symlink_info, "evidence.md")

    assert verify_zip(package_zip) == 2


def test_verify_release_package_zip_rejects_too_many_files(tmp_path: Path) -> None:
    module = _load_module("verify_release_package_zip_file_count")
    package_zip = tmp_path / "too-many.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["a.txt","b.txt"],"sha256":{"a.txt":"' + ("0" * 64) + '","b.txt":"' + ("0" * 64) + '"}}\n')
        zf.writestr("a.txt", "a\n")
        zf.writestr("b.txt", "b\n")

    assert module.run_zip(package_zip, max_files=2) == 2


def test_verify_release_package_zip_rejects_uncompressed_size_limit(tmp_path: Path) -> None:
    module = _load_module("verify_release_package_zip_size")
    package_zip = tmp_path / "too-large.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["evidence.md"],"sha256":{"evidence.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr("evidence.md", "too large\n")

    assert module.run_zip(package_zip, max_uncompressed_bytes=5) == 2


def test_verify_release_package_zip_rejects_high_compression_ratio(tmp_path: Path) -> None:
    module = _load_module("verify_release_package_zip_ratio")
    package_zip = tmp_path / "high-ratio.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["evidence.md"],"sha256":{"evidence.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr("evidence.md", "a" * 1000)

    assert module.run_zip(package_zip, max_compression_ratio=1.0) == 2


def test_verify_release_package_rejects_not_ready_manifest(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "FAILED",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_missing_manifest_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_invalid_manifest_timestamp(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "not-a-stamp",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_invalid_package_dir_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/not-a-release-package",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_absolute_package_dir_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": str(tmp_path / "release-package-20260528T120000Z"),
        "evidence_file": "evidence.md",
        "prod_ready_file": "prod-ready.md",
        "included_files": ["evidence.md", "prod-ready.md"],
        "sha256": {"evidence.md": "unused", "prod-ready.md": "unused"},
    }
    (package_dir / "prod-ready.md").write_text("prod\n", encoding="utf-8")
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_package_dir_timestamp_mismatch(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120001Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_unincluded_evidence_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "missing-evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_same_evidence_and_prod_ready_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_nested_evidence_metadata(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    nested = package_dir / "nested"
    nested.mkdir()
    evidence = nested / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "nested/evidence.md",
        "prod_ready_file": "nested/evidence.md",
        "included_files": ["nested/evidence.md"],
        "sha256": {"nested/evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_extra_unmanifested_file(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    (package_dir / "extra.md").write_text("extra\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_nested_manifest_as_extra_file(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    nested = package_dir / "nested"
    nested.mkdir()
    (nested / "manifest.json").write_text("{}\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_symlink_in_package_dir(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    link = package_dir / "linked.md"
    try:
        link.symlink_to(evidence)
    except OSError as exc:
        pytest.skip(f"symlink creation is not available: {exc}")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md", "linked.md"],
        "sha256": {
            "evidence.md": "unused",
            "linked.md": "unused",
        },
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_duplicate_manifest_entries(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md", "evidence.md"],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_non_string_manifest_entry(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "evidence.md",
        "included_files": ["evidence.md", 42],
        "sha256": {"evidence.md": "unused"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_nested_manifest_entry(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    nested = package_dir / "nested"
    nested.mkdir()
    evidence = nested / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    root_evidence = package_dir / "root-evidence.md"
    root_evidence.write_text("ok\n", encoding="utf-8")
    prod_ready = package_dir / "prod-ready.md"
    prod_ready.write_text("prod\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "root-evidence.md",
        "prod_ready_file": "prod-ready.md",
        "included_files": ["nested/evidence.md", "root-evidence.md", "prod-ready.md"],
        "sha256": {
            "nested/evidence.md": "unused",
            "root-evidence.md": "unused",
            "prod-ready.md": "unused",
        },
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_extra_checksum_key(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md"],
        "sha256": {
            "evidence.md": "unused",
            "extra.md": "0" * 64,
        },
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_rejects_invalid_checksum_format(tmp_path: Path) -> None:
    verify_run = _load_run()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    evidence = package_dir / "evidence.md"
    evidence.write_text("ok\n", encoding="utf-8")
    manifest = {
        "status": "READY",
        "included_files": ["evidence.md"],
        "sha256": {"evidence.md": "not-a-sha256"},
    }
    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    assert verify_run(package_dir) == 2


def test_verify_release_package_cli_accepts_positional_dir_and_zip(
    tmp_path: Path, monkeypatch
) -> None:
    build_run = _load_build_run()
    main = _load_main()
    db = tmp_path / "ops.db"
    package_root = tmp_path / "dist"
    docs = tmp_path / "docs" / "releases"
    docs.mkdir(parents=True, exist_ok=True)
    prod = docs / "prod_ready.md"
    readiness = docs / "readiness.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 Р С—Р С•Р В»РЎРЏ)",
                "| 5. Backup Р вЂР вЂќ Р Р†РЎвЂ№Р С—Р С•Р В»Р Р…Р ВµР Р… (Р С—РЎС“РЎвЂљРЎРЉ Р С” backup) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 6. `db_migrate.py` Р Р†РЎвЂ№Р С—Р С•Р В»Р Р…Р ВµР Р… (Р Р†Р ВµРЎР‚РЎРѓР С‘РЎРЏ РЎРѓРЎвЂ¦Р ВµР СРЎвЂ№/Р Р†РЎвЂ№Р Р†Р С•Р Т‘) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 7. Р В Р ВµР В¶Р С‘Р С forensic Р С—Р С•Р Т‘Р С—Р С‘РЎРѓР С‘ Р Р† prod (`mvp` Р С‘Р В»Р С‘ `gost_strict` + env) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
                "| 8. Smoke-check Р С—Р С•РЎРѓР В»Р Вµ Р Р†РЎвЂ№Р С”Р В»Р В°Р Т‘Р С”Р С‘ (РЎРѓРЎРѓРЎвЂ№Р В»Р С”Р В°/Р В»Р С•Р С–) | _(Р В·Р В°Р С—Р С•Р В»Р Р…Р С‘РЎвЂљРЎРЉ)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    readiness.write_text("# readiness\n", encoding="utf-8")
    assert build_run(
        db,
        package_root=package_root,
        prod_ready=prod,
        readiness=readiness,
        apply_migrate=True,
        strict=False,
        strict_generate_sbom=False,
    ) == 0
    package_dir = next(p for p in package_root.iterdir() if p.is_dir() and p.name.startswith("release-package-"))
    package_zip = package_dir.with_suffix(".zip")

    monkeypatch.setattr("sys.argv", ["verify_release_package.py", str(package_dir)])
    assert main() == 0
    monkeypatch.setattr("sys.argv", ["verify_release_package.py", str(package_zip)])
    assert main() == 0


def test_verify_release_package_cli_rejects_ambiguous_package_args(monkeypatch) -> None:
    main = _load_main()
    monkeypatch.setattr(
        "sys.argv",
        ["verify_release_package.py", "pkg.zip", "--package-zip", "pkg.zip"],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit for ambiguous package args")


def test_verify_release_package_cli_applies_zip_limits(tmp_path: Path, monkeypatch) -> None:
    main = _load_main()
    package_zip = tmp_path / "small-limit.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["evidence.md"],"sha256":{"evidence.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr("evidence.md", "too large\n")
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify_release_package.py",
            "--package-zip",
            str(package_zip),
            "--max-zip-uncompressed-bytes",
            "5",
        ],
    )

    assert main() == 2


def test_verify_release_package_cli_uses_env_zip_limits(tmp_path: Path, monkeypatch) -> None:
    main = _load_main()
    package_zip = tmp_path / "env-limit.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"status":"READY","included_files":["evidence.md"],"sha256":{"evidence.md":"' + ("0" * 64) + '"}}\n')
        zf.writestr("evidence.md", "too large\n")
    monkeypatch.setenv("TAKT_RELEASE_VERIFY_MAX_ZIP_UNCOMPRESSED_BYTES", "5")
    monkeypatch.setattr("sys.argv", ["verify_release_package.py", str(package_zip)])

    assert main() == 2


def test_verify_release_package_cli_overrides_env_zip_limits(tmp_path: Path, monkeypatch) -> None:
    main = _load_main()
    package_zip = tmp_path / "override-env-limit.zip"
    payload = "too large\n"
    prod_payload = "prod ready\n"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    prod_digest = hashlib.sha256(prod_payload.encode("utf-8")).hexdigest()
    manifest = {
        "status": "READY",
        "generated_at_utc": "20260528T120000Z",
        "package_dir": "dist/release-package-20260528T120000Z",
        "evidence_file": "evidence.md",
        "prod_ready_file": "prod-ready.md",
        "included_files": ["evidence.md", "prod-ready.md"],
        "sha256": {
            "evidence.md": digest,
            "prod-ready.md": prod_digest,
        },
    }
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False) + "\n")
        zf.writestr("evidence.md", payload)
        zf.writestr("prod-ready.md", prod_payload)
    monkeypatch.setenv("TAKT_RELEASE_VERIFY_MAX_ZIP_UNCOMPRESSED_BYTES", "5")
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify_release_package.py",
            str(package_zip),
            "--max-zip-uncompressed-bytes",
            "1000000",
        ],
    )

    assert main() == 0


def test_verify_release_package_cli_rejects_invalid_env_limit(monkeypatch) -> None:
    main = _load_main()
    monkeypatch.setenv("TAKT_RELEASE_VERIFY_MAX_ZIP_FILES", "not-an-int")
    monkeypatch.setattr("sys.argv", ["verify_release_package.py", "pkg.zip"])

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit for invalid env limit")


def test_verify_release_package_cli_rejects_invalid_zip_limit(monkeypatch) -> None:
    main = _load_main()
    monkeypatch.setattr(
        "sys.argv",
        ["verify_release_package.py", "pkg.zip", "--max-zip-files", "0"],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit for invalid zip limit")


def test_verify_release_package_zip_requires_root_manifest(tmp_path: Path) -> None:
    verify_zip = _load_run_zip()
    package_zip = tmp_path / "wrapped.zip"
    with ZipFile(package_zip, "w", ZIP_DEFLATED) as zf:
        zf.writestr("package/manifest.json", '{"status":"READY","included_files":[],"sha256":{}}\n')

    assert verify_zip(package_zip) == 2
