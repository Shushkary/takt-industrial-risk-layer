from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKED_PATHS = [
    ".github",
    "config",
    "deploy",
    "docs",
    "scripts",
    "src",
    "tests",
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    "README.md",
]

# Маркеры утечки путей окружения сборки (локальная машина разработчика).
# Намеренно НЕ используем широкие префиксы дисков Windows: они ложно
# срабатывают на содержимом полей данных в примерах/фикстурах (путь
# вредоносного файла C:\Temp\update.exe внутри EDR-события) и на случайных
# байтовых последовательностях внутри zip-сжатых бинарных документов.
# Вместо этого ловим сигнатуры, характерные именно для машины разработчика:
#   - профиль пользователя Windows (каталог профиля);
#   - пути виртуального окружения Python;
#   - специфичные для окружения разработчика каталоги/названия;
#   - локальные file:-ссылки на машине разработчика.
# ПРИМЕЧАНИЕ: маркеры собираются конкатенацией, а сами литералы маркеров не
# должны встречаться в этом файле (в т.ч. в комментариях) — иначе гард
# сработает на собственном исходнике.
FORBIDDEN_PATH_MARKERS = (
    "C:" + "\\" + "Users" + "\\",  # профиль пользователя Windows (user profile)
    "C:" + "/" + "Users" + "/",    # то же через прямой слэш
    "D:" + "\\" + "Users" + "\\",  # профиль на диске D:
    "D:" + "/" + "Users" + "/",    # то же через прямой слэш
    "file:" + "///",               # локальные file:-ссылки
    "site" + "-packages",          # пути виртуального окружения
    "Neyros" + "_Prod",            # спец. каталог окружения разработчика
    "Version" + " lite",           # спец. название окружения разработчика
)


# zip-сжатые бинарные офисные документы: чтение как текста даёт ложные
# срабатывания на случайных байтовых последовательностях (например, D:\ или C:\
# внутри сжатого XML), которые не являются реальными ссылками на пути.
# Скан текста по ним не имеет смысла — утечки окружения сборки живут в
# исходниках, CI и документации, а не в презентациях/таблицах.
_BINARY_OFFICE_SUFFIXES = {
    ".pptx", ".pptm", ".potx", ".potm",
    ".docx", ".docm",
    ".xlsx", ".xlsm",
    ".odp", ".ods", ".odt",
}


# Каталоги синтетической телеметрии. В них профиль пользователя Windows —
# легитимное содержимое данных: дроппер в сценарии закономерно попадает в
# `C:` + профиль жертвы, и такие пути описывают смоделированный узел, а не
# машину разработчика. Гард нацелен на утечку окружения сборки в исходники,
# документацию и CI, поэтому данные фикстур из скана исключены.
_DATA_ONLY_DIRS = (Path("tests") / "fixtures",)


def _is_fixture_data(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return any(relative.is_relative_to(data_dir) for data_dir in _DATA_ONLY_DIRS)


def _iter_text_files(path: Path):
    if path.is_file():
        yield path
        return
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() not in {
            ".pyc", ".pyo", ".pdf", ".png", ".jpg", *_BINARY_OFFICE_SUFFIXES
        } and not _is_fixture_data(candidate):
            yield candidate


def _scan_for_local_machine_paths() -> list[str]:
    """Вернуть относительные пути файлов с маркерами путей окружения сборки."""
    offenders: list[str] = []
    for rel in CHECKED_PATHS:
        for path in _iter_text_files(ROOT / rel):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if any(marker in text for marker in FORBIDDEN_PATH_MARKERS):
                offenders.append(str(path.relative_to(ROOT)))
    return offenders


def test_release_readiness_artifacts_exist() -> None:
    assert (ROOT / "docs" / "backend_release_readiness.md").is_file()
    assert (ROOT / "docs" / "release_checklist.md").is_file()
    assert (ROOT / "docs" / "release_readiness_template.md").is_file()
    assert (ROOT / "docs" / "certification_risk_roadmap.md").is_file()
    assert (ROOT / "docs" / "releases").is_dir()
    assert (ROOT / "migrations" / "0001_init.sql").is_file()
    assert (ROOT / "migrations" / "0005_operation_audit_ledger_remediation.sql").is_file()
    assert (ROOT / "migrations" / "0006_raw_evidence_append_only.sql").is_file()


def test_backend_release_readiness_records_s8_gate_status() -> None:
    text = (ROOT / "docs" / "backend_release_readiness.md").read_text(encoding="utf-8")
    required = (
        "Backend status: ready for frontend integration against the real API.",
        "S0-S8 backend remediation gate",
        "architecture guard",
        "OpenAPI snapshot",
        "Schemathesis",
        "backtest regression",
        "domain purity policy",
        "no active equipment control",
        "no SCZI scope expansion",
        "human remains in the loop",
        "release evidence",
        "SBOM",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert missing == []


def test_root_and_frontend_readmes_match_release_gates() -> None:
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    frontend_readme = (ROOT / "frontend" / "takt-arm" / "README.md").read_text(encoding="utf-8")
    required_root = (
        "frontend-ci",
        "npm run test:frontend",
        "frontend evidence dry run",
        "frontend SBOM",
        "build_release_package",
    )
    required_frontend = (
        "44 Vitest/MSW/Testing Library unit tests",
        "frontend CycloneDX SBOM",
        "Playwright e2e scenarios",
        "Runtime API configuration remains limited to `VITE_TAKT_API_BASE_URL` and `VITE_TAKT_API_KEY`",
    )
    assert [phrase for phrase in required_root if phrase not in root_readme] == []
    assert [phrase for phrase in required_frontend if phrase not in frontend_readme] == []


def test_ci_defines_backend_release_gate_jobs() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    required = (
        "release-gates:",
        "release-evidence-dry-run:",
        "python -m pytest -q",
        "lint-imports --config pyproject.toml",
        "python scripts/generate_sbom.py",
        "pip-audit",
        "python -m schemathesis run",
        "http://127.0.0.1:8000/openapi.json",
        "python scripts/verify_audit_ledger.py",
        "python scripts/verify_operation_ledger.py",
        "python scripts/release_finalize.py",
        "python scripts/build_release_package.py",
        "node-version: \"22\"",
        "cache-dependency-path: frontend/takt-arm/package-lock.json",
        "working-directory: frontend/takt-arm",
        "npm ci",
        "npm run test:frontend",
    )
    missing = [phrase for phrase in required if phrase not in workflow]
    assert missing == []


def test_ci_defines_frontend_release_gate_job() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    required = (
        "frontend-ci:",
        "actions/setup-node@v4",
        "cache-dependency-path: frontend/takt-arm/package-lock.json",
        "working-directory: frontend/takt-arm",
        "npm ci",
        "npm run lint",
        "npm run test:frontend",
        "npm run audit:frontend",
        "npm run build-storybook",
    )
    missing = [phrase for phrase in required if phrase not in workflow]
    assert missing == []


def test_dockerfile_pins_single_worker_for_process_local_event_window() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--workers", "1"' in dockerfile


def test_source_docs_and_ci_do_not_reference_local_machine_paths() -> None:
    assert _scan_for_local_machine_paths() == []


def test_guard_still_catches_developer_machine_path() -> None:
    """Самопроверка гарда: настоящий путь разработчика по-прежнему ловится.

    Если гард «починен» простым отключением проверки, этот тест упадёт —
    синтетический путь профиля разработчика обязан оставаться нарушением.
    """
    probe = ROOT / "docs" / "_guard_probe_local_path.md"
    probe.write_text(
        "leaked build path: C:\\Users\\Developer\\secret\\takt-industrial-risk-layer\n",
        encoding="utf-8",
    )
    try:
        offenders = _scan_for_local_machine_paths()
        assert str(probe.relative_to(ROOT)) in offenders
    finally:
        probe.unlink(missing_ok=True)


def test_product_boundary_documents_no_crypto_and_no_active_control() -> None:
    text = (ROOT / "docs" / "product_boundary.md").read_text(encoding="utf-8")
    required = (
        "ТАКТ не является СКЗИ",
        "ТАКТ не является системой активного управления оборудованием",
        "ТАКТ не выполняет блокировку, останов, переключение, перезагрузку или команды на ПЛК",
        "API и фронтенд не должны содержать endpoint, кнопку или сценарий активного управления оборудованием",
        "Приказ ФСТЭК №239",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert missing == []


def test_certification_risk_roadmap_covers_fstec_fsb_budget_and_lab() -> None:
    text = (ROOT / "docs" / "certification_risk_roadmap.md").read_text(encoding="utf-8")
    required = (
        "Приказа ФСТЭК №239",
        "аккредитованной лабораторией",
        "ТАКТ MVP не должен позиционироваться как СКЗИ",
        "Бюджетные строки",
        "Риск-реестр",
        "Вопросы к лаборатории",
        "MVP-готовность и сертификационную готовность",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert missing == []


def test_api_and_frontend_do_not_expose_active_control_commands() -> None:
    checked_roots = [
        ROOT / "src" / "takt" / "interface_adapters" / "api",
        ROOT / "frontend" / "takt-arm" / "src",
    ]
    forbidden_phrases = (
        "отключить узел",
        "заблокировать учетную запись",
        "заблокировать учётную запись",
        "остановить ПЛК",
        "перезагрузить ПЛК",
        "переключить оборудование",
        "отправить команду",
        "shutdown plc",
        "stop plc",
        "disable node",
        "block account",
    )
    offenders: list[str] = []
    for root in checked_roots:
        for path in _iter_text_files(root):
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(phrase.lower() in text for phrase in forbidden_phrases):
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


def test_frontend_release_artifact_gate_is_defined() -> None:
    package = json.loads((ROOT / "frontend" / "takt-arm" / "package.json").read_text(encoding="utf-8"))
    scripts = package["scripts"]
    assert package["engines"]["node"] == ">=20.10"
    assert (ROOT / "frontend" / "takt-arm" / ".nvmrc").read_text(encoding="utf-8").strip() == "22"
    assert "check:workspace-boundary" in scripts["test:frontend"]
    assert "check:api-client" in scripts["test:frontend"]
    assert "test:unit" in scripts["test:frontend"]
    assert "test:e2e" in scripts["test:frontend"]
    assert "sbom:frontend" in scripts["test:frontend"]
    assert "check:release-artifacts" in scripts["test:frontend"]
    assert scripts["test:unit:vitest"] == "vitest run"
    assert scripts["test:e2e:playwright"] == "playwright test"
    assert scripts["audit:frontend"] == "npm audit --omit=dev --audit-level=high"
    for dependency in ("vitest", "@testing-library/react", "@testing-library/jest-dom", "msw", "@playwright/test"):
        assert dependency in package["devDependencies"]
    assert (ROOT / "frontend" / "takt-arm" / "scripts" / "generate-frontend-sbom.mjs").is_file()
    assert (ROOT / "frontend" / "takt-arm" / "scripts" / "check-frontend-release-artifacts.mjs").is_file()
    assert (ROOT / "frontend" / "takt-arm" / "nginx" / "csp.conf").is_file()
    playwright_config = ROOT / "frontend" / "takt-arm" / "playwright.config.ts"
    playwright_spec = ROOT / "frontend" / "takt-arm" / "e2e" / "app-shell.spec.ts"
    assert playwright_config.is_file()
    assert playwright_spec.is_file()
    assert playwright_spec.read_text(encoding="utf-8").count("test(") >= 3
    unit_test_sources = [
        ROOT / "frontend" / "takt-arm" / "src" / "app" / "taktApi.test.ts",
        ROOT / "frontend" / "takt-arm" / "src" / "app" / "format.test.ts",
        ROOT / "frontend" / "takt-arm" / "src" / "components" / "ui" / "DataTable.test.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "layout" / "AppShell.test.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "pages" / "CaseDetail.test.tsx",
    ]
    unit_test_count = sum(path.read_text(encoding="utf-8").count("it(") + path.read_text(encoding="utf-8").count("it.each(") for path in unit_test_sources)
    assert unit_test_count >= 30
    frontend_sources = (
        ROOT / "frontend" / "takt-arm" / "src" / "components" / "ui" / "RiskBadge.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "pages" / "CaseDetail.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "pages" / "IncidentQueue.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "pages" / "SegmentOverview.tsx",
        ROOT / "frontend" / "takt-arm" / "src" / "pages" / "TopologyMap.tsx",
    )
    assert all(".replace('.', ',')" not in path.read_text(encoding="utf-8") for path in frontend_sources)


def test_frontend_csp_documents_static_bundle_boundary() -> None:
    csp = (ROOT / "frontend" / "takt-arm" / "nginx" / "csp.conf").read_text(encoding="utf-8")
    required = (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        'X-Frame-Options "DENY"',
        'X-Content-Type-Options "nosniff"',
        'Referrer-Policy "no-referrer"',
    )
    missing = [phrase for phrase in required if phrase not in csp]
    assert missing == []


def test_frontend_sbom_has_no_local_file_references_when_present() -> None:
    sbom = ROOT / "frontend" / "takt-arm" / "dist" / "frontend-sbom.cyclonedx.json"
    if not sbom.is_file():
        return
    assert sbom.stat().st_size > 0
    payload = json.loads(sbom.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    file_refs = [
        ref.get("url")
        for component in payload.get("components", [])
        for ref in component.get("externalReferences", [])
        if isinstance(ref, dict) and str(ref.get("url", "")).lower().startswith("file:")
    ]
    assert file_refs == []


def test_ci_publishes_the_built_image_for_the_stand() -> None:
    """Собранный в CI образ обязан доезжать до стенда, а не выбрасываться.

    У боевой ВМ нет доступа ни к pypi, ни к Docker Hub: собрать образ на месте нельзя.
    CI — единственное место, где он собирается из исходников с `github.sha` в метке, и пока
    результат сборки выбрасывался, на стенд попадала сборка, сделанная руками. Так метка
    ревизии однажды и разошлась с кодом: прецедент 2026-08-27, образ `3bc35a5` с ревизией
    `d816f4e`. Контрольная сумма рядом с архивом нужна, чтобы оператор проверил, что на ВМ
    приехало ровно то, что собрано.
    """
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    required = (
        # Без `load` образ остаётся в кэше buildx, и `docker save` его не найдёт.
        "load: true",
        "docker save",
        "sha256sum",
        "actions/upload-artifact@v4",
        "takt-risk-layer-image",
        "if-no-files-found: error",
    )
    missing = [phrase for phrase in required if phrase not in workflow]
    assert missing == []
