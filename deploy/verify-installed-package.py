"""Fail deployment if Python would load package files from another revision."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def verify(source: Path, installed: Path) -> None:
    expected = {path.relative_to(source) for path in source.rglob("*.py")}
    actual = {path.relative_to(installed) for path in installed.rglob("*.py")}
    if not expected or expected != actual:
        raise RuntimeError("installed Python file list differs from the checkout")
    for relative in sorted(expected):
        if (source / relative).read_bytes() != (installed / relative).read_bytes():
            raise RuntimeError(f"installed Python source differs: {relative}")


def main() -> int:
    spec = importlib.util.find_spec("fd_sightings")
    if spec is None or spec.origin is None:
        raise RuntimeError("fd_sightings is not installed in the selected interpreter")
    installed = Path(spec.origin).resolve().parent
    verify(Path(sys.argv[1]).resolve(), installed)
    print(f"Installed Python source verified: {installed}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
