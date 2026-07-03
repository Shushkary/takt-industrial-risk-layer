from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "src" / "takt" / "interface_adapters" / "api"
STORES_ROOT = ROOT / "src" / "takt" / "infrastructure" / "stores"
USE_CASES_ROOT = ROOT / "src" / "takt" / "application" / "use_cases"


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_api_main_stays_thin_compatibility_entrypoint() -> None:
    main_py = API_ROOT / "main.py"
    text = main_py.read_text(encoding="utf-8")

    assert _line_count(main_py) <= 25
    assert "sys.modules[__name__] = _app" in text
    assert "FastAPI(" not in text
    assert "@app." not in text
    assert "APIRouter(" not in text


def test_api_split_modules_remain_present_and_bounded() -> None:
    expected_routers = {
        "analytics.py",
        "audit_engagements.py",
        "audit_ledger.py",
        "case_actions.py",
        "cases.py",
        "catalog.py",
        "compliance.py",
        "export.py",
        "forensic.py",
        "ingest.py",
        "integrations.py",
        "system.py",
    }
    expected_schemas = {
        "analytics.py",
        "audit_engagements.py",
        "case_actions.py",
        "cases.py",
        "catalog.py",
        "compliance.py",
        "errors.py",
        "ingest.py",
        "integrations.py",
        "system.py",
    }

    router_dir = API_ROOT / "routers"
    schema_dir = API_ROOT / "schemas"
    assert expected_routers <= {path.name for path in router_dir.glob("*.py")}
    assert expected_schemas <= {path.name for path in schema_dir.glob("*.py")}
    assert (API_ROOT / "dependencies.py").is_file()
    assert (API_ROOT / "app.py").is_file()
    assert (API_ROOT / "mappers" / "cases.py").is_file()
    assert (API_ROOT / "pagination.py").is_file()
    assert (API_ROOT / "openapi.py").is_file()
    assert (API_ROOT / "config_paths.py").is_file()
    assert (API_ROOT / "lifecycle.py").is_file()
    assert (API_ROOT / "event_sources.py").is_file()
    assert (API_ROOT / "metrics.py").is_file()

    oversized = {
        path.name: _line_count(path)
        for path in router_dir.glob("*.py")
        if path.name != "__init__.py" and _line_count(path) > 300
    }
    assert oversized == {}


def test_api_app_factory_does_not_own_case_dto_mapping() -> None:
    app_py = API_ROOT / "app.py"
    text = app_py.read_text(encoding="utf-8")

    forbidden_defs = {
        "def _case_to_detail",
        "def _domain_case_from_detail",
        "def _manual_permit_to_detail",
        "def _formal_verdict_record_to_detail",
        "def _case_forensic_verdict_to_detail",
    }
    offenders = sorted(token for token in forbidden_defs if token in text)

    assert offenders == []


def test_api_routers_do_not_reimplement_api_key_auth() -> None:
    """Auth remains centralized in middleware/openapi wiring; routers may only derive audit actors."""
    forbidden_tokens = {
        "TAKT_API_KEY",
        "X-TAKT-API-Key",
        "Authorization",
        "takt_api_key_value",
        "takt_auth_required_from_env",
    }
    allowed_files = {"system.py"}
    offenders: dict[str, list[str]] = {}

    for path in (API_ROOT / "routers").glob("*.py"):
        if path.name == "__init__.py" or path.name in allowed_files:
            continue
        text = path.read_text(encoding="utf-8")
        hits = sorted(token for token in forbidden_tokens if token in text)
        if hits:
            offenders[path.name] = hits

    assert offenders == {}


def test_sqlite_store_stays_facade_over_split_modules() -> None:
    store = STORES_ROOT / "sqlite_store.py"
    expected_modules = {
        "sqlite_audit_engagement_mapper.py",
        "sqlite_audit_engagement_store.py",
        "sqlite_audit_ledger.py",
        "sqlite_case_mapper.py",
        "sqlite_connection.py",
        "sqlite_expected_behavior.py",
        "sqlite_recent_events.py",
        "sqlite_schema.py",
    }

    assert _line_count(store) <= 350
    assert expected_modules <= {path.name for path in STORES_ROOT.glob("sqlite_*.py")}

    facade_imports = expected_modules - {"sqlite_audit_engagement_mapper.py", "sqlite_recent_events.py"}
    text = store.read_text(encoding="utf-8")
    for module in facade_imports:
        assert f"takt.infrastructure.stores.{module.removesuffix('.py')}" in text


def test_application_facades_do_not_depend_on_delivery_frameworks() -> None:
    facade_files = [
        "audit_ledger_facade.py",
        "case_actions_facade.py",
        "cases_query_service.py",
        "compliance_facade.py",
        "export_facade.py",
        "forensic_export_facade.py",
        "ingest_facade.py",
    ]
    forbidden_import_roots = {"fastapi", "uvicorn", "starlette"}
    offenders: dict[str, list[str]] = {}

    for filename in facade_files:
        path = USE_CASES_ROOT / filename
        imports = _import_roots(path)
        forbidden = sorted(imports & forbidden_import_roots)
        if forbidden:
            offenders[filename] = forbidden

    assert offenders == {}
