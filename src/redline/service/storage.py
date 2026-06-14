from __future__ import annotations

from pathlib import Path
from typing import Protocol

from redline.service.config import ServiceConfig
from redline.service.models import ArtifactInfo, ArtifactManifest, PackageResponse, RunCreateRequest, RunResponse, RunState, RunWorkItem
from redline.service.store import ServiceStore


class RunMetadataStore(Protocol):
    def upsert_package(self, package: PackageResponse) -> None: ...

    def get_package(self, package_id: str) -> PackageResponse | None: ...

    def create_run(
        self,
        *,
        run_id: str,
        request_id: str,
        request: RunCreateRequest,
        package_path: Path,
        out_dir: Path,
    ) -> RunResponse: ...

    def mark_running(self, run_id: str) -> None: ...

    def mark_completed(
        self,
        *,
        run_id: str,
        state: RunState,
        reason_code: str,
        envelope_status: str,
        package_hash: str | None,
        receipt_hash: str | None,
        report_hash: str | None,
        artifact_manifest: ArtifactManifest,
    ) -> None: ...

    def mark_error(self, *, run_id: str, error_code: str, message: str) -> None: ...

    def claim_next_run(self, *, worker_id: str) -> RunWorkItem | None: ...

    def requeue_interrupted_runs(self) -> int: ...

    def get_run(self, run_id: str) -> RunResponse | None: ...

    def list_runs(self, *, limit: int = 50) -> list[RunResponse]: ...

    def count_packages(self) -> int: ...

    def count_runs(self, *, states: set[RunState] | None = None) -> int: ...

    def prune_runs_before(self, cutoff_iso: str) -> list[Path]: ...


class ArtifactStore(Protocol):
    @property
    def packages_dir(self) -> Path: ...

    @property
    def runs_dir(self) -> Path: ...

    def package_upload_dir(self, upload_id: str) -> Path: ...

    def run_dir(self, run_id: str) -> Path: ...

    def resolve_download_path(self, run: RunResponse, artifact: ArtifactInfo) -> Path: ...


class LocalArtifactStore:
    def __init__(self, config: ServiceConfig) -> None:
        self._config = config

    @property
    def packages_dir(self) -> Path:
        return self._config.packages_dir

    @property
    def runs_dir(self) -> Path:
        return self._config.runs_dir

    def package_upload_dir(self, upload_id: str) -> Path:
        return self.packages_dir / upload_id

    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def resolve_download_path(self, run: RunResponse, artifact: ArtifactInfo) -> Path:
        from redline.service.artifacts import resolve_artifact_path

        return resolve_artifact_path(Path(run.out_dir), artifact.path)


def create_metadata_store(config: ServiceConfig) -> RunMetadataStore:
    if config.metadata_store == "sqlite":
        return ServiceStore(config.db_path)
    if config.metadata_store == "postgres":
        from redline.service.postgres_store import PostgresServiceStore

        assert config.database_url is not None
        return PostgresServiceStore(config.database_url)
    raise ValueError(f"unsupported metadata store: {config.metadata_store}")


def create_artifact_store(config: ServiceConfig) -> ArtifactStore:
    if config.artifact_store == "local":
        return LocalArtifactStore(config)
    raise ValueError(f"unsupported artifact store: {config.artifact_store}")
