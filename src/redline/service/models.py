from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASS = "pass"
    FAIL = "fail"
    AMBER = "amber"
    ERROR = "error"


class ErrorEnvelope(ApiModel):
    schema_version: Literal["redline.service.error.v1"] = "redline.service.error.v1"
    ok: Literal[False] = False
    request_id: str
    error_code: str
    message: str


class HealthResponse(ApiModel):
    ok: bool
    service: Literal["redline-api"] = "redline-api"
    environment: str = "local"
    metadata_store: str = "sqlite"
    artifact_store: str = "local"


class PackageImportRequest(ApiModel):
    package_path: str
    write_lock: bool = False


class PackageResponse(ApiModel):
    package_id: str
    path: str
    identity_hash: str
    identity_lock_hash: str
    files: list[str]
    created_at: str


class RunCreateRequest(ApiModel):
    package_id: str | None = None
    package_path: str | None = None
    baseline: str = "baseline"
    candidate: str = "candidate_bad"
    suite_path: str = "fixtures/suites/demo_suite.json"
    spec_path: str = "fixtures/specs/redline_spec.json"
    baseline_receipt_path: str | None = None
    baseline_trust_policy_path: str | None = None
    baseline_version_id: str | None = None
    candidate_version_id: str | None = None

    @model_validator(mode="after")
    def require_package_source(self) -> RunCreateRequest:
        if (self.package_id is None) == (self.package_path is None):
            raise ValueError("exactly one of package_id or package_path is required")
        return self


class ArtifactInfo(ApiModel):
    artifact_id: str
    kind: str
    path: str
    sha256: str
    bytes: int
    download_url: str


class ArtifactManifest(ApiModel):
    run_id: str
    artifacts: list[ArtifactInfo]


class RunResponse(ApiModel):
    run_id: str
    state: RunState
    request_id: str
    package_id: str | None = None
    package_path: str
    baseline: str
    candidate: str
    suite_path: str
    spec_path: str
    out_dir: str
    reason_code: str | None = None
    envelope_status: str | None = None
    package_hash: str | None = None
    receipt_hash: str | None = None
    report_hash: str | None = None
    artifact_manifest: ArtifactManifest | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None


class RunListResponse(ApiModel):
    runs: list[RunResponse]


class SponsorMode(StrEnum):
    PREFLIGHT = "preflight"
    LIVE = "live"


class SponsorRequest(ApiModel):
    mode: SponsorMode = SponsorMode.PREFLIGHT
    final_publish: bool = False
    allow_demo_baseline_genesis: bool = False


class SponsorResponse(ApiModel):
    run_id: str
    ok: bool
    state: str
    reason_code: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class RunWorkItem:
    run_id: str
    request_id: str
    request: RunCreateRequest
    package_path: Path
    out_dir: Path
