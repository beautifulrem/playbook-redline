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


class StrategySourceKind(StrEnum):
    UPLOAD = "upload"
    LOCAL = "local"
    FIXTURE = "fixture"
    IMPORTED = "imported"


class ReleaseState(StrEnum):
    DRAFT = "draft"
    REDLINE_RUNNING = "redline_running"
    REDLINE_PASSED = "redline_passed"
    EVIDENCE_COLLECTING = "evidence_collecting"
    REVIEW_REQUIRED = "review_required"
    APPROVED = "approved"
    DEMO_EXECUTED = "demo_executed"
    RELEASE_READY = "release_ready"
    RELEASED_DEMO = "released_demo"
    RELEASED_LIVE_GATED = "released_live_gated"
    REJECTED = "rejected"
    KILLED = "killed"
    BLOCKED_WITHHELD = "blocked_withheld"
    BLOCKED_UNVERIFIED = "blocked_unverified"
    BLOCKED_MISSING_EVIDENCE = "blocked_missing_evidence"
    BLOCKED_RISK_POLICY = "blocked_risk_policy"
    BLOCKED_APPROVAL = "blocked_approval"
    BLOCKED_EXCHANGE_ERROR = "blocked_exchange_error"


class ReleaseTier(StrEnum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"


class SimulationEvidenceSource(StrEnum):
    GETAGENT_STUDIO = "getagent_studio"
    LOCAL_BACKTEST = "local_backtest"
    MANUAL_IMPORT = "manual_import"


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


class StrategyVersionCreateRequest(ApiModel):
    version_id: str = Field(min_length=1, max_length=128)
    strategy_id: str = Field(min_length=1, max_length=128)
    package_id: str | None = None
    package_path: str | None = None
    package_hash: str | None = None
    identity_lock_hash: str | None = None
    source_kind: StrategySourceKind = StrategySourceKind.LOCAL
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(default="system", min_length=1, max_length=128)


class StrategyVersionResponse(ApiModel):
    version_id: str
    strategy_id: str
    package_id: str | None = None
    package_path: str | None = None
    package_hash: str
    identity_lock_hash: str | None = None
    source_kind: StrategySourceKind
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: str
    updated_at: str


class StrategyVersionListResponse(ApiModel):
    strategy_versions: list[StrategyVersionResponse]


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
    baseline_receipt_path: str | None = None
    baseline_trust_policy_path: str | None = None
    baseline_version_id: str | None = None
    candidate_version_id: str | None = None
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


class ReleaseCandidateCreateRequest(ApiModel):
    release_id: str | None = Field(default=None, min_length=1, max_length=128)
    version_id: str = Field(min_length=1, max_length=128)
    strategy_id: str | None = Field(default=None, min_length=1, max_length=128)
    created_by: str = Field(default="system", min_length=1, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReleaseCandidateResponse(ApiModel):
    release_id: str
    strategy_id: str
    version_id: str
    state: ReleaseState
    release_tier: ReleaseTier = ReleaseTier.L0
    created_by: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    run_id: str | None = None
    redline_reason_code: str | None = None
    redline_receipt_hash: str | None = None
    redline_report_hash: str | None = None
    simulation_evidence: dict[str, Any] | None = None
    simulation_evidence_hash: str | None = None
    risk_policy: dict[str, Any] | None = None
    risk_policy_hash: str | None = None
    approval: dict[str, Any] | None = None
    execution_run_id: str | None = None
    execution_evidence: dict[str, Any] | None = None
    evidence_manifest: dict[str, Any] | None = None
    evidence_manifest_hash: str | None = None
    reject_reason: str | None = None
    killed_at: str | None = None
    created_at: str
    updated_at: str


class ReleaseCandidateListResponse(ApiModel):
    release_candidates: list[ReleaseCandidateResponse]


class RedlineRunBindRequest(ApiModel):
    run_id: str = Field(min_length=1, max_length=128)


class SimulationEvidenceRequest(ApiModel):
    source: SimulationEvidenceSource
    period_start: str = Field(min_length=1, max_length=64)
    period_end: str = Field(min_length=1, max_length=64)
    market: str = Field(min_length=1, max_length=64)
    symbol: str = Field(min_length=1, max_length=64)
    trade_count: int = Field(ge=0)
    pnl: str = Field(min_length=1, max_length=64)
    max_drawdown: str = Field(min_length=1, max_length=64)
    win_rate: str = Field(min_length=1, max_length=64)
    sharpe_or_sortino: str | None = Field(default=None, max_length=64)
    source_file_hash: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskPolicyRequest(ApiModel):
    max_order_notional_usdt: str = Field(default="20", min_length=1, max_length=64)
    allowed_product_types: list[str] = Field(default_factory=lambda: ["USDT-FUTURES"])
    allowed_symbols: list[str] = Field(default_factory=lambda: ["BTCUSDT", "ETHUSDT", "SOLUSDT"])
    require_simulation_evidence: bool = True
    require_demo_execution: bool = True
    require_human_approval: bool = True
    mainnet_enabled: bool = False
    expected_order_notional_usdt: str = Field(default="5", min_length=1, max_length=64)


class ApprovalRequest(ApiModel):
    reviewer_id: str = Field(min_length=1, max_length=128)
    comment: str = Field(default="", max_length=2048)
    demo_mode: bool = False


class RejectRequest(ApiModel):
    reviewer_id: str = Field(min_length=1, max_length=128)
    comment: str = Field(default="", max_length=2048)


class ReleaseActionResponse(ApiModel):
    release_id: str
    ok: bool
    state: ReleaseState
    reason_code: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ReleaseSafetyResponse(ApiModel):
    release_freeze: bool
    execution_freeze: bool
    mainnet_orders_enabled: bool


class ReleaseJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReleaseJobType(StrEnum):
    CANONICAL_EXECUTE_DEMO = "canonical_execute_demo"
    EXCHANGE_PREFLIGHT = "exchange_preflight"
    RECONCILIATION = "reconciliation"
    SHOWCASE_ORDER = "showcase_order"


class ReleaseJobResponse(ApiModel):
    job_id: str
    release_id: str
    job_type: ReleaseJobType
    status: ReleaseJobStatus
    requested_by: str
    request_hash: str
    idempotency_key: str | None = None
    events_url: str
    result: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None


class ReleaseJobListResponse(ApiModel):
    jobs: list[ReleaseJobResponse]


class ReleaseJobEventResponse(ApiModel):
    event_id: str
    job_id: str
    release_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    previous_event_hash: str
    event_hash: str


class ReleaseJobEventListResponse(ApiModel):
    events: list[ReleaseJobEventResponse]


@dataclass(frozen=True)
class ReleaseJobWorkItem:
    job_id: str
    release_id: str
    job_type: ReleaseJobType
    request: dict[str, Any]
    requested_by: str


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


class ExecutionRequest(ApiModel):
    symbol: str | None = None
    product_type: str | None = None
    margin_coin: str | None = None
    size: str = "0.0001"
    side: Literal["buy", "sell"] = "buy"
    trade_side: Literal["open", "close"] | None = "open"
    order_type: Literal["market", "limit"] = "market"
    force: Literal["ioc", "fok", "gtc", "post_only"] | None = None
    price: str | None = None
    confirm_mainnet_order: bool = False
    trust_policy_path: str | None = None


class ExecutionResponse(ApiModel):
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
