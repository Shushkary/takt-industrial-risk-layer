"""Repair tests/test_api.py after a broken TestClient wrap (collapse blanks + unwrap with-blocks)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tests" / "test_api.py"
_WITH = re.compile(r"^(\s*)with TestClient\(create_app\(\)\) as (\w+):\s*$")


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = re.sub(r"\n[ \t]*\n+", "\n", text)
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _WITH.match(line)
        if not m:
            out.append(line)
            i += 1
            continue
        ind, name = m.group(1), m.group(2)
        bi = len(ind)
        out.append(f"{ind}{name} = TestClient(create_app())")
        i += 1
        while i < len(lines):
            L = lines[i]
            if not L.strip():
                out.append("")
                i += 1
                continue
            ni = len(L) - len(L.lstrip(" "))
            if ni <= bi:
                break
            out.append(L[4:])
            i += 1
    text = "\n".join(out) + "\n"
    text = text.replace(
        "    if len(fp) >= 4:\n    by_pfx = ",
        "    if len(fp) >= 4:\n        by_pfx = ",
    )
    text = text.replace(
        "        by_pfx = client.get(\"/cases\", params={\"fingerprint_prefix\": fp[:4].lower()}).json()\n    assert any(",
        "        by_pfx = client.get(\"/cases\", params={\"fingerprint_prefix\": fp[:4].lower()}).json()\n        assert any(",
    )
    PATH.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
    sys.exit(0)
