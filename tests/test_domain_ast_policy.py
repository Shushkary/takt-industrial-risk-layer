"""Спринт 3: в **takt.domain** запрещены «опасные» вызовы времени/UUID (инъекция через порты в application)."""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOMAIN_ROOT = _REPO_ROOT / "src" / "takt" / "domain"


def _forbidden_call(msg: ast.AST) -> str | None:
    if not isinstance(msg, ast.Call):
        return None
    f = msg.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        mod, attr = f.value.id, f.attr
        if mod == "datetime" and attr in ("now", "utcnow"):
            return f"{mod}.{attr}()"
        if mod == "time" and attr == "time":
            return f"{mod}.{attr}()"
        if mod == "uuid" and attr == "uuid4":
            return f"{mod}.{attr}()"
    if isinstance(f, ast.Name) and f.id == "uuid4":
        return "uuid4()"
    return None


def test_domain_has_no_direct_time_uuid_calls() -> None:
    viol: list[str] = []
    for path in sorted(_DOMAIN_ROOT.rglob("*.py")):
        if path.name == "__pycache__":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as e:
            viol.append(f"{path}: syntax error {e}")
            continue
        for node in ast.walk(tree):
            reason = _forbidden_call(node)
            if reason is not None:
                lineno = getattr(node, "lineno", 0)
                viol.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}: {reason}")
    assert not viol, "Запрещённые вызовы в домене:\n" + "\n".join(viol)
