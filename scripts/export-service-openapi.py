from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from redline.service.app import create_app
from redline.service.config import ServiceConfig


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("schemas/service-openapi.json"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="redline-openapi-") as tmp:
        app = create_app(ServiceConfig(root=Path(tmp), token="redline-demo"))
        schema = app.openapi()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
