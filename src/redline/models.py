from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RedlineModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
        arbitrary_types_allowed=False,
    )


class Status(StrEnum):
    PASS = "pass"
    WITHHELD = "withheld"
    REJECT = "reject"
    UNVERIFIED_NO_VERDICT = "unverified_no_verdict"


class ReasonCode(StrEnum):
    PASS = "PASS"
    NEW_BLOCK_BREACH = "NEW_BLOCK_BREACH"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    BASELINE_UNCHAINED = "BASELINE_UNCHAINED"
    BASELINE_GENESIS = "BASELINE_GENESIS"
    COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"
    PROBE_ERROR = "PROBE_ERROR"
    ENGINE_FAILURE = "ENGINE_FAILURE"
    DATA_MISSING = "DATA_MISSING"
    CALIBRATION_FAILED = "CALIBRATION_FAILED"
    BASELINE_BREACHES = "BASELINE_BREACHES"
    BASELINE_UNRUNNABLE = "BASELINE_UNRUNNABLE"
    NONFINITE_VALUE = "NONFINITE_VALUE"
    ENGINE_IDENTITY_MISMATCH = "ENGINE_IDENTITY_MISMATCH"
    CANDIDATE_SANDBOX_VIOLATION = "CANDIDATE_SANDBOX_VIOLATION"
    VERDICT_PATH_VIOLATION = "VERDICT_PATH_VIOLATION"
    RECEIPT_BINDING_FAILED = "RECEIPT_BINDING_FAILED"
    SPONSOR_READBACK_MISMATCH = "SPONSOR_READBACK_MISMATCH"
    UNVERIFIED_NO_VERDICT = "UNVERIFIED_NO_VERDICT"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PARSE_ERROR = "PARSE_ERROR"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"


class ProofKind(StrEnum):
    PACKAGE_CANONICAL = "package_canonical"
    EDIT_PROVENANCE = "edit_provenance"
    SPEC_COMPILE = "spec_compile"
    BASELINE_CALIBRATION = "baseline_calibration"
    REPLAY = "replay"
    REPLAY_WELLFORMED = "replay_wellformed"
    PROBE = "probe"
    COVERAGE = "coverage"
    CANDIDATE_ABSOLUTE = "candidate_absolute"
    DECISION = "decision"
    SPONSOR_READBACK = "sponsor_readback"
    VERIFICATION = "verification"


class ProbeOutcome(StrEnum):
    PASS = "pass"
    BREACH = "breach"
    ERRORED = "errored"


class ProbeType(StrEnum):
    MAX_DRAWDOWN = "max_drawdown"
    TRADE_BUDGET = "trade_budget"


class ChainStatus(StrEnum):
    CHAINED = "chained"
    GENESIS = "genesis"
    UNCHAINED = "unchained"


class VerificationLevel(StrEnum):
    HASH_ONLY = "hash_only"
    REPLAYED = "replayed"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNVERIFIED_NO_VERDICT = "unverified_no_verdict"
    BAD_INPUT = "bad_input"


class Capability(RedlineModel):
    mode: str
    degraded: bool = False


class Capabilities(RedlineModel):
    engine: Capability = Field(default_factory=lambda: Capability(mode="deterministic"))
    scenario_count: int = 0
    qwen_compile: Capability = Field(default_factory=lambda: Capability(mode="json-fallback", degraded=True))
    sponsor_readback: Capability = Field(default_factory=lambda: Capability(mode="unavailable", degraded=True))
    llm_in_verdict: bool = False


class ProbeSpec(RedlineModel):
    id: str
    type: ProbeType
    params: dict[str, str]
    block: bool = True


class RedlineSpec(RedlineModel):
    version: str = "redline.spec.v2.1"
    spec_id: str
    probes: list[ProbeSpec]
    compiler: str = "json"
    model: str | None = None
    tool_schema_hash: str | None = None


class Scenario(RedlineModel):
    id: str
    path: str
    timeframe: str = "1h"


class Suite(RedlineModel):
    version: str = "redline.suite.v2"
    suite_id: str
    scenarios: list[Scenario]
    suite_lock_hash: str | None = None


class Bar(RedlineModel):
    i: int
    timestamp: str
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal


class ReplayPoint(RedlineModel):
    bar: int
    timestamp: str
    close: Decimal
    nav: Decimal
    peak: Decimal
    drawdown: Decimal
    position: Decimal


class ReplayTrace(RedlineModel):
    scenario_id: str
    role: Literal["baseline", "candidate"]
    engine: Literal["deterministic", "nautilus"] = "deterministic"
    bars: int
    trade_count: int
    points: list[ReplayPoint]
    input_hash: str
    artifact_hash: str


class Assertion(RedlineModel):
    metric: str
    op: Literal["<=", "<", ">=", ">", "=="]
    threshold: str
    observed: str
    scenario_id: str
    bar: int
    holds: bool


class ProbeResult(RedlineModel):
    outcome: ProbeOutcome
    assertions: list[Assertion]
    evidence_bar: int | None = None


class CoverageManifest(RedlineModel):
    manifest: str = "suite.scenarios×spec.block_probes"
    cells: list[tuple[str, str]]
    complete: bool
    missing: list[str] = Field(default_factory=list)


class Proof(RedlineModel):
    proof_id: str
    phase: str
    kind: ProofKind
    verdict_bearing: bool
    inputs_hash: str
    artifact_hash: str
    assertions: list[Assertion] = Field(default_factory=list)
    reproduce: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class DecisionContext(RedlineModel):
    suite_id: str
    spec_hash: str
    chain_status: ChainStatus = ChainStatus.GENESIS
    reject_reason: ReasonCode | None = None


class DecisionEnvelope(RedlineModel):
    envelope_version: str = "redline.decision.v1"
    status: Status
    reason_code: ReasonCode
    chain_status: ChainStatus
    required_proof_ids: list[str]
    satisfied_proof_ids: list[str]
    coverage: CoverageManifest
    capabilities: Capabilities


class PackageInfo(RedlineModel):
    identity_hash: str
    manifest_hash: str
    canonical_tar_rules: str = "redline.v9.canonical-tree"


class EditProvenance(RedlineModel):
    tool: str = "fixture"
    prompt_digest: str
    diff_hash: str
    locked_by: str = "author"
    captured_at: str


class BaselineInfo(RedlineModel):
    package_hash: str
    baseline_receipt_hash: str | None = None
    baseline_version_id: str = "fixture:baseline"
    chain_status: ChainStatus = ChainStatus.GENESIS


class CandidateInfo(RedlineModel):
    package_hash: str


class SpecInfo(RedlineModel):
    spec_hash: str
    compiler: str = "json"
    model: str | None = None
    tool_schema_hash: str | None = None


class SuiteInfo(RedlineModel):
    suite_id: str
    scenarios: list[str]
    suite_lock_hash: str


class RunnerInfo(RedlineModel):
    engine: Literal["deterministic", "nautilus"] = "deterministic"
    engine_source_tree_hash: str
    runner_lock_hash: str
    env_lock: str = "TZ=UTC;PYTHONHASHSEED-independent;LC_ALL=C"


class ResultInfo(RedlineModel):
    status: Literal["pass", "withheld"]
    new_breaches: list[Assertion]
    result_hash: str


class ReceiptDecision(RedlineModel):
    reason_code: ReasonCode
    required_proof_ids_source: str = "REQUIRED_PROOFS[status]"
    required_proof_ids: list[str]
    satisfied_proof_ids: list[str]
    verdict_source: str = "deterministic_probe"
    llm_used_for_verdict: bool = False


class ReportInfo(RedlineModel):
    report_hash: str
    attribution_report_hash: str | None = None


class PublishInfo(RedlineModel):
    attempted: bool = False
    stop_before_final_publish: bool = True
    sponsor_status: str = "not_attempted"
    version_id: str | None = None
    run_id: str | None = None
    run_evidence_hash: str | None = None
    readback_hash: str | None = None
    note: str = "run_id is platform execution evidence, not local-equivalence proof"


class Receipt(RedlineModel):
    version: str = "redline.receipt.v3.2"
    package: PackageInfo
    edit_provenance: EditProvenance
    baseline: BaselineInfo
    candidate: CandidateInfo
    spec: SpecInfo
    suite: SuiteInfo
    runner: RunnerInfo
    result: ResultInfo
    coverage: CoverageManifest
    decision: ReceiptDecision
    proofs: list[Proof]
    capabilities: Capabilities
    strength_summary: str
    report: ReportInfo
    publish: PublishInfo = Field(default_factory=PublishInfo)
    receipt_hash: str


class VerificationResult(RedlineModel):
    schema_version: str = "redline.verify.v1"
    status: VerificationStatus
    reason_code: ReasonCode
    verification_level: VerificationLevel
    receipt_hash: str | None = None
    strength_summary: str = ""
    chain_status: ChainStatus = ChainStatus.GENESIS
    edit_provenance_present: bool = False
    proof_coverage: Literal["complete", "incomplete"] = "incomplete"
    missing_proof_ids: list[str] = Field(default_factory=list)


class ProofVerification(RedlineModel):
    schema_version: str = "redline.proof_verification.v1"
    status: Literal["proof_replayed", "proof_mismatch", "proof_unreplayable"]
    proof_id: str
    artifact_hash: str | None = None
    reason_code: ReasonCode = ReasonCode.PASS


class RunArtifacts(RedlineModel):
    envelope: DecisionEnvelope
    receipt: Receipt | None
    proofs: list[Proof]
    traces: list[ReplayTrace]
    report_json: dict[str, Any]
    out_dir: Path | None = None

