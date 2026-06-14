#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from redline.service.cleanup import cleanup_expired_runs
from redline.service.config import ServiceConfig


def main() -> int:
    args = _parse_args()
    config = ServiceConfig.from_env()
    if args.root is not None:
        config = ServiceConfig(
            root=args.root,
            token=config.token,
            max_upload_bytes=config.max_upload_bytes,
            workers=config.workers,
            environment=config.environment,
            host=config.host,
            port=config.port,
            cors_origins=config.cors_origins,
            log_level=config.log_level,
            metadata_store=config.metadata_store,
            artifact_store=config.artifact_store,
            database_url=config.database_url,
            expose_error_details=config.expose_error_details,
            request_rate_limit_per_minute=config.request_rate_limit_per_minute,
            max_packages=config.max_packages,
            max_active_runs=config.max_active_runs,
            max_runs_total=config.max_runs_total,
            run_retention_seconds=config.run_retention_seconds,
        )
    result = cleanup_expired_runs(config=config, older_than_seconds=args.older_than_seconds)
    print(json.dumps(result.__dict__, sort_keys=True))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prune expired Redline service run metadata and artifact directories.")
    parser.add_argument("--root", type=Path, default=None, help="Override REDLINE_SERVICE_ROOT.")
    parser.add_argument(
        "--older-than-seconds",
        type=int,
        default=int(os.environ.get("REDLINE_SERVICE_RUN_RETENTION_SECONDS", str(7 * 24 * 60 * 60))),
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(main())
