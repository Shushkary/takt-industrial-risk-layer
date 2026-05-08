"""One-off: wrap TestClient(create_app()) assignments in test_api.py with `with ... as`."""

from __future__ import annotations

import re
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "tests" / "test_api.py"
_ASSIGN = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*) = TestClient\(create_app\(\)\)\s*$")
_CHAIN = re.compile(
    r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*) = TestClient\(create_app\(\)\)\.(.+)$"
)
_NEXT_ASSIGN = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*) = TestClient\(create_app\(\)\)\s*$")


def transform(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        raw = line.rstrip("\n\r")
        cm = _CHAIN.match(raw)
        if cm:
            indent, lhs, rest = cm.group(1), cm.group(2), cm.group(3)
            out.append(f"{indent}with TestClient(create_app()) as client:\n")
            out.append(f"{indent}    {lhs} = client.{rest}\n")
            i += 1
            continue

        m = _ASSIGN.match(raw)
        if not m:
            out.append(line)
            i += 1
            continue

        indent, name = m.group(1), m.group(2)
        base = len(indent)
        out.append(f"{indent}with TestClient(create_app()) as {name}:\n")
        i += 1
        while i < len(lines):
            nxt = lines[i]
            nraw = nxt.rstrip("\n\r")
            if nraw.strip() == "":
                out.append(nxt)
                i += 1
                continue
            ni = len(nxt) - len(nxt.lstrip(" "))
            if ni < base:
                break
            na = _NEXT_ASSIGN.match(nraw)
            if na is not None and na.group(1) == indent:
                break
            out.append(" " * 4 + nxt[ni:])
            i += 1

    return "".join(out)


def main() -> None:
    src = _PATH.read_text(encoding="utf-8")
    _PATH.write_text(transform(src), encoding="utf-8")


if __name__ == "__main__":
    main()
