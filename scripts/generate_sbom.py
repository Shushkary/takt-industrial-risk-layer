#!/usr/bin/env python3
"""Generate full CycloneDX SBOM JSON."""

from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path
import shutil


def _remove_local_file_references(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for component in data.get("components", []):
        refs = component.get("externalReferences")
        if not isinstance(refs, list):
            continue
        kept = [ref for ref in refs if not str(ref.get("url", "")).lower().startswith("file:")]
        if kept:
            component["externalReferences"] = kept
        else:
            component.pop("externalReferences", None)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    out = root / "dist" / "sbom.cdx.json"
    compat_out = root / "dist" / "sbom.cyclonedx.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    # Requires `cyclonedx-bom` package, exposes `cyclonedx-py` CLI.
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "environment",
            "--output-format",
            "JSON",
            "--output-file",
            str(out),
        ]
    )
    _remove_local_file_references(out)
    shutil.copyfile(out, compat_out)
    print(f"Wrote {out}")
    print(f"Wrote {compat_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
