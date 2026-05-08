from __future__ import annotations

import importlib
import pkgutil


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
