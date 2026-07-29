from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _discover_domain_modules():
    import takt.domain as domain_pkg

    for mod in pkgutil.walk_packages(domain_pkg.__path__, domain_pkg.__name__ + "."):
        if mod.ispkg:
            continue
        yield mod.name


def test_domain_has_no_forbidden_imports():
    forbidden = (
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "requests",
        "httpx",
        "os",
        "socket",
        "subprocess",
        "Crypto",
        "cryptography",
    )
    for name in _discover_domain_modules():
        m = importlib.import_module(name)
        bad = [k for k in getattr(m, "__dict__", {}) if k in forbidden]
        assert not bad, f"{name} references forbidden names {bad}"


def test_domain_source_has_no_crypto_or_infrastructure_imports():
    forbidden_roots = {
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "requests",
        "httpx",
        "os",
        "socket",
        "subprocess",
        # hashlib — криптографический импорт. Допустим ТОЛЬКО в infrastructure
        # через HasherPort (вариант А): в domain запрещён, чтобы слой оставался
        # чистым и «в продукте не было собственной криптографии». Регрессия
        # (возврат `import hashlib` в domain) должна ловиться этим гардом.
        "hashlib",
        "hmac",
        "Crypto",
        "cryptography",
    }
    offenders: list[str] = []
    for path in (ROOT / "src" / "takt" / "domain").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".", 1)[0]]
            else:
                continue
            bad = sorted(set(names) & forbidden_roots)
            if bad:
                offenders.append(f"{path.relative_to(ROOT)}: {', '.join(bad)}")
    assert offenders == []
