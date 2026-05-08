from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CHECKED_PATHS = [
    ".github",
    "config",
    "docs",
    "scripts",
    "src",
    "tests",
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    "README.md",
]

FORBIDDEN_PATH_MARKERS = (
    "D:" + "\\",
    "D:" + "/",
    "C:" + "\\",
    "C:" + "/",
    "file:" + "///",
    "site" + "-packages",
    "Neyros" + "_Prod",
    "Version" + " lite",
)


def _iter_text_files(path: Path):
    if path.is_file():
        yield path
        return
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() not in {".pyc", ".pyo", ".pdf", ".png", ".jpg"}:
            yield candidate


def test_release_readiness_artifacts_exist() -> None:
    assert (ROOT / "docs" / "release_checklist.md").is_file()
    assert (ROOT / "docs" / "release_readiness_template.md").is_file()
    assert (ROOT / "docs" / "releases").is_dir()
    assert (ROOT / "migrations" / "0001_init.sql").is_file()
    assert (ROOT / "migrations" / "0005_operation_audit_ledger_remediation.sql").is_file()
    assert (ROOT / "migrations" / "0006_raw_evidence_append_only.sql").is_file()


def test_dockerfile_pins_single_worker_for_process_local_event_window() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--workers", "1"' in dockerfile


def test_source_docs_and_ci_do_not_reference_local_machine_paths() -> None:
    offenders: list[str] = []
    for rel in CHECKED_PATHS:
        for path in _iter_text_files(ROOT / rel):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if any(marker in text for marker in FORBIDDEN_PATH_MARKERS):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_sbom_has_no_local_file_references_when_present() -> None:
    sbom = ROOT / "dist" / "sbom.cyclonedx.json"
    if not sbom.is_file():
        return
    assert sbom.stat().st_size > 0
    payload = json.loads(sbom.read_text(encoding="utf-8"))
    file_refs = [
        ref.get("url")
        for component in payload.get("components", [])
        for ref in component.get("externalReferences", [])
        if isinstance(ref, dict) and str(ref.get("url", "")).lower().startswith("file:")
    ]
    assert file_refs == []
