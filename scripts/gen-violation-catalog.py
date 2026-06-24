#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from redline.violations import render_violation_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate docs/VIOLATION_CODES.md from ReasonCode metadata.")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "VIOLATION_CODES.md")
    parser.add_argument("--check", action="store_true", help="fail if the checked-in catalog is stale")
    args = parser.parse_args()

    rendered = render_violation_catalog()
    out_path = args.out if args.out.is_absolute() else ROOT / args.out
    if args.check:
        current = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        if current != rendered:
            print(f"{out_path} is out of date; run uv run python scripts/gen-violation-catalog.py", file=sys.stderr)
            return 1
        print(f"{out_path} is in sync")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
