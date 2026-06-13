from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ServiceConfig:
    root: Path = Path("artifacts/service")
    token: str = "redline-demo"
    max_upload_bytes: int = 50 * 1024 * 1024
    workers: int = 2

    @classmethod
    def from_env(cls) -> ServiceConfig:
        return cls(
            root=Path(os.environ.get("REDLINE_SERVICE_ROOT", "artifacts/service")),
            token=os.environ.get("REDLINE_SERVICE_TOKEN", "redline-demo"),
            max_upload_bytes=int(os.environ.get("REDLINE_SERVICE_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024))),
            workers=max(1, int(os.environ.get("REDLINE_SERVICE_WORKERS", "2"))),
        )

    @property
    def db_path(self) -> Path:
        return self.root / "redline-service.sqlite3"

    @property
    def packages_dir(self) -> Path:
        return self.root / "packages"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"
