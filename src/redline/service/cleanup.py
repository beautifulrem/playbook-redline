from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from redline.service.config import ServiceConfig
from redline.service.storage import create_metadata_store


@dataclass(frozen=True)
class CleanupResult:
    deleted_runs: int
    deleted_artifact_dirs: int
    cutoff: str


def cleanup_expired_runs(*, config: ServiceConfig, older_than_seconds: int | None = None) -> CleanupResult:
    retention = config.run_retention_seconds if older_than_seconds is None else older_than_seconds
    if retention < 0:
        raise ValueError("older_than_seconds must be non-negative")
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=retention)
    cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")
    store = create_metadata_store(config)
    artifact_dirs = store.prune_runs_before(cutoff_iso)
    deleted = 0
    for path in artifact_dirs:
        if _delete_run_dir(path, runs_root=config.runs_dir):
            deleted += 1
    return CleanupResult(deleted_runs=len(artifact_dirs), deleted_artifact_dirs=deleted, cutoff=cutoff_iso)


def _delete_run_dir(path: Path, *, runs_root: Path) -> bool:
    root = runs_root.resolve()
    target = path.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"refusing to delete run directory outside service runs root: {path}") from exc
    if target == root:
        raise ValueError("refusing to delete service runs root")
    if not target.exists():
        return False
    if target.is_symlink() or not target.is_dir():
        raise ValueError(f"refusing to delete unsafe run path: {path}")
    shutil.rmtree(target)
    return True
