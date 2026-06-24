from __future__ import annotations

from pathlib import Path
from typing import Protocol

from redline.service.config import ServiceConfig
from redline.service.models import (
    ArtifactInfo,
    ArtifactManifest,
    PackageResponse,
    ReleaseCandidateResponse,
    ReleaseJobEventResponse,
    ReleaseJobResponse,
    ReleaseJobStatus,
    ReleaseJobType,
    ReleaseJobWorkItem,
    RunCreateRequest,
    RunResponse,
    RunState,
    RunWorkItem,
    StrategyVersionResponse,
)
from redline.service.store import ServiceStore


class RunMetadataStore(Protocol):
    def upsert_package(self, package: PackageResponse) -> None: ...

    def get_package(self, package_id: str) -> PackageResponse | None: ...

    def create_strategy_version(self, version: StrategyVersionResponse) -> StrategyVersionResponse: ...

    def get_strategy_version(self, version_id: str) -> StrategyVersionResponse | None: ...

    def list_strategy_versions(self, *, limit: int = 50) -> list[StrategyVersionResponse]: ...

    def create_release_candidate(self, release: ReleaseCandidateResponse) -> ReleaseCandidateResponse: ...

    def update_release_candidate(self, release: ReleaseCandidateResponse) -> ReleaseCandidateResponse: ...

    def get_release_candidate(self, release_id: str) -> ReleaseCandidateResponse | None: ...

    def list_release_candidates(self, *, limit: int = 50) -> list[ReleaseCandidateResponse]: ...

    def append_release_audit_entry(self, *, release_id: str, entry: dict) -> None: ...

    def list_release_audit_entries(self, *, release_id: str) -> list[dict]: ...

    def create_release_job(
        self,
        *,
        job_id: str,
        release_id: str,
        job_type: ReleaseJobType,
        request_hash: str,
        request: dict,
        idempotency_key: str | None,
        requested_by: str,
    ) -> ReleaseJobResponse: ...

    def get_release_job(self, *, release_id: str, job_id: str) -> ReleaseJobResponse | None: ...

    def list_release_jobs(self, *, release_id: str, limit: int = 50) -> list[ReleaseJobResponse]: ...

    def claim_next_release_job(self, *, worker_id: str) -> ReleaseJobWorkItem | None: ...

    def recover_interrupted_release_jobs(self) -> list[ReleaseJobResponse]: ...

    def cancel_release_job(self, *, release_id: str, job_id: str) -> ReleaseJobResponse | None: ...

    def mark_release_job_status(
        self,
        *,
        job_id: str,
        status: ReleaseJobStatus,
        result: dict | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None: ...

    def append_release_job_event(self, *, release_id: str, job_id: str, event_type: str, payload: dict | None = None) -> ReleaseJobEventResponse: ...

    def list_release_job_events(self, *, release_id: str, job_id: str) -> list[ReleaseJobEventResponse]: ...

    def list_schema_migrations(self) -> list[dict[str, str]]: ...

    def get_idempotency_record(self, *, scope: str, key: str) -> dict | None: ...

    def put_idempotency_record(self, *, scope: str, key: str, request_hash: str, response: dict, status_code: int) -> None: ...

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

    def update_artifact_manifest(self, *, run_id: str, artifact_manifest: ArtifactManifest) -> None: ...

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
