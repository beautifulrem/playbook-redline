from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    REDUCE_SIZE = "reduce_size"
    REJECT = "reject"
    UNVERIFIED_NO_VERDICT = "unverified_no_verdict"


class VerdictTier(StrEnum):
    ALLOW = "ALLOW"
    REDUCE_SIZE = "REDUCE_SIZE"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    BLOCK = "BLOCK"


class ReasonCode(StrEnum):
    PASS = "PASS"
    NEW_BLOCK_BREACH = "NEW_BLOCK_BREACH"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    PROOF_HASH_MISMATCH = "PROOF_HASH_MISMATCH"
    LEDGER_CHAIN_BROKEN = "LEDGER_CHAIN_BROKEN"
    CHECKPOINT_MISMATCH = "CHECKPOINT_MISMATCH"
    EXECUTION_LEDGER_BROKEN = "EXECUTION_LEDGER_BROKEN"
    MERKLE_INCLUSION_FAILED = "MERKLE_INCLUSION_FAILED"
    APPROVAL_LINK_MISMATCH = "APPROVAL_LINK_MISMATCH"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    CHAIN_LINK_MISMATCH = "CHAIN_LINK_MISMATCH"
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
    SPONSOR_EVIDENCE_UNVERIFIED = "SPONSOR_EVIDENCE_UNVERIFIED"
    UNVERIFIED_NO_VERDICT = "UNVERIFIED_NO_VERDICT"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PARSE_ERROR = "PARSE_ERROR"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


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
    NO_ENTRY_WHEN = "no_entry_when"
    TRADE_BUDGET = "trade_budget"
    UNAUTHORIZED_ORDER = "unauthorized_order"
    SKIP_CONFIRM = "skip_confirm"
    BLIND_RETRY = "blind_retry"


PLAYBOOK_ADAPTER_ID = "python_strategy_sandbox"
CANONICAL_TAR_RULES = "redline.v9.canonical-tree"
P0_ALLOWED_SCENARIO_IDS = ("btc-crash-2024-03-05", "btc-chop-2024-08")

_DECIMAL_GT_ZERO_LE_ONE_PATTERN = r"^(?:(?:0?\.[0-9]*[1-9][0-9]*)|(?:1(?:\.0*)?))$"
_DECIMAL_ZERO_TO_ONE_PATTERN = r"^(?:(?:0(?:\.[0-9]*)?)|(?:0?\.[0-9]+)|(?:1(?:\.0*)?))$"
_DECIMAL_ZERO_TO_1000_PATTERN = r"^(?:(?:0(?:\.[0-9]*)?)|(?:[1-9][0-9]{0,2}(?:\.[0-9]*)?)|(?:1000(?:\.0*)?))$"
_BPS_ZERO_TO_10000_PATTERN = r"^(?:(?:0(?:\.[0-9]*)?)|(?:[1-9][0-9]{0,3}(?:\.[0-9]*)?)|(?:10000(?:\.0*)?))$"
_INT_ZERO_TO_1000_PATTERN = r"^0*(?:[0-9]{1,3}|1000)$"
_INT_ZERO_TO_100000_PATTERN = r"^0*(?:[0-9]{1,5}|100000)$"

_PROBE_PARAMS_SCHEMA: dict[ProbeType, dict[str, Any]] = {
    ProbeType.MAX_DRAWDOWN: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["max_drawdown"],
        "properties": {
            "max_drawdown": {
                "type": "string",
                "pattern": _DECIMAL_GT_ZERO_LE_ONE_PATTERN,
                "description": "Finite decimal string in (0, 1].",
            }
        },
    },
    ProbeType.NO_ENTRY_WHEN: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["scenario_id", "max_abs_position"],
        "properties": {
            "scenario_id": {
                "type": "string",
                "enum": list(P0_ALLOWED_SCENARIO_IDS),
                "description": "Scenario id supported by the current P0 adapter contract.",
            },
            "before_bar": {
                "type": "string",
                "pattern": _INT_ZERO_TO_100000_PATTERN,
                "description": "Integer decimal string in [0, 100000].",
            },
            "bar_lt": {
                "type": "string",
                "pattern": _INT_ZERO_TO_100000_PATTERN,
                "description": "Integer decimal string in [0, 100000].",
            },
            "max_abs_position": {
                "type": "string",
                "pattern": _DECIMAL_ZERO_TO_ONE_PATTERN,
                "description": "Finite decimal string in [0, 1].",
            },
        },
        "anyOf": [{"required": ["before_bar"]}, {"required": ["bar_lt"]}],
    },
    ProbeType.TRADE_BUDGET: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["max_trades"],
        "properties": {
            "max_trades": {
                "type": "string",
                "pattern": _INT_ZERO_TO_1000_PATTERN,
                "description": "Integer decimal string in [0, 1000].",
            }
        },
    },
    ProbeType.UNAUTHORIZED_ORDER: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["scenario_id", "max_abs_position"],
        "properties": {
            "scenario_id": {
                "type": "string",
                "enum": list(P0_ALLOWED_SCENARIO_IDS),
                "description": "Scenario id supported by the current P0 adapter contract.",
            },
            "max_abs_position": {
                "type": "string",
                "pattern": _DECIMAL_ZERO_TO_1000_PATTERN,
                "description": "Finite decimal string in [0, 1000].",
            },
            "allowed_side": {
                "type": "string",
                "enum": ["both", "long_only", "short_only", "flat_only"],
                "description": "Allowed position side for the scenario.",
            },
        },
    },
    ProbeType.SKIP_CONFIRM: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["scenario_id", "confirm_bar", "max_abs_position"],
        "properties": {
            "scenario_id": {
                "type": "string",
                "enum": list(P0_ALLOWED_SCENARIO_IDS),
                "description": "Scenario id supported by the current P0 adapter contract.",
            },
            "confirm_bar": {
                "type": "string",
                "pattern": _INT_ZERO_TO_100000_PATTERN,
                "description": "Integer decimal string in [0, 100000].",
            },
            "max_abs_position": {
                "type": "string",
                "pattern": _DECIMAL_ZERO_TO_1000_PATTERN,
                "description": "Finite decimal string in [0, 1000].",
            },
        },
    },
    ProbeType.BLIND_RETRY: {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "required": ["scenario_id", "retry_after_bar", "max_retries"],
        "properties": {
            "scenario_id": {
                "type": "string",
                "enum": list(P0_ALLOWED_SCENARIO_IDS),
                "description": "Scenario id supported by the current P0 adapter contract.",
            },
            "retry_after_bar": {
                "type": "string",
                "pattern": _INT_ZERO_TO_100000_PATTERN,
                "description": "Integer decimal string in [0, 100000].",
            },
            "max_retries": {
                "type": "string",
                "pattern": _INT_ZERO_TO_1000_PATTERN,
                "description": "Integer decimal string in [0, 1000].",
            },
        },
    },
}

_PROBE_SPEC_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {"properties": {"type": {"const": probe_type.value}}, "required": ["type"]},
            "then": {"properties": {"params": params_schema}},
        }
        for probe_type, params_schema in _PROBE_PARAMS_SCHEMA.items()
    ],
    "x-runtime-constraints": [
        {
            "name": "probe_param_semantics",
            "enforced_by": "redline.models.ProbeSpec.require_semantic_params",
        }
    ],
}


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
    reason: str | None = None


class Capabilities(RedlineModel):
    engine: Capability = Field(default_factory=lambda: Capability(mode="deterministic"))
    scenario_count: int = 0
    qwen_compile: Capability = Field(default_factory=lambda: Capability(mode="json-fallback", degraded=True))
    sponsor_readback: Capability = Field(default_factory=lambda: Capability(mode="unavailable", degraded=True))
    llm_in_verdict: bool = False


class ProbeSpec(RedlineModel):
    model_config = ConfigDict(json_schema_extra=_PROBE_SPEC_SCHEMA_EXTRA)

    id: str
    type: ProbeType
    params: dict[str, str]
    block: bool = True

    @model_validator(mode="after")
    def require_semantic_params(self) -> ProbeSpec:
        if self.type == ProbeType.MAX_DRAWDOWN:
            value = _decimal_param(self.params, "max_drawdown")
            if value is None or value <= 0 or value > Decimal("1"):
                raise ValueError("max_drawdown must be finite and in (0, 1]")
        elif self.type == ProbeType.TRADE_BUDGET:
            value = _decimal_param(self.params, "max_trades")
            if value is None or value < 0 or value != value.to_integral_value() or value > Decimal("1000"):
                raise ValueError("max_trades must be a finite integer in [0, 1000]")
        elif self.type == ProbeType.NO_ENTRY_WHEN:
            scenario_id = self.params.get("scenario_id")
            if not isinstance(scenario_id, str) or not scenario_id.strip():
                raise ValueError("no_entry_when requires a non-empty scenario_id")
            before_bar = _integer_param(self.params, "before_bar" if "before_bar" in self.params else "bar_lt")
            if before_bar is None or before_bar < 0 or before_bar != before_bar.to_integral_value() or before_bar > Decimal("100000"):
                raise ValueError("no_entry_when before_bar must be a finite integer in [0, 100000]")
            max_abs_position = _decimal_param(self.params, "max_abs_position")
            if max_abs_position is None or max_abs_position < 0 or max_abs_position > Decimal("1"):
                raise ValueError("no_entry_when max_abs_position must be finite and in [0, 1]")
        elif self.type == ProbeType.UNAUTHORIZED_ORDER:
            _validate_scenario_param(self.params, "unauthorized_order")
            max_abs_position = _decimal_param(self.params, "max_abs_position")
            if max_abs_position is None or max_abs_position < 0 or max_abs_position > Decimal("1000"):
                raise ValueError("unauthorized_order max_abs_position must be finite and in [0, 1000]")
            allowed_side = self.params.get("allowed_side", "both")
            if allowed_side not in {"both", "long_only", "short_only", "flat_only"}:
                raise ValueError("unauthorized_order allowed_side must be one of both,long_only,short_only,flat_only")
        elif self.type == ProbeType.SKIP_CONFIRM:
            _validate_scenario_param(self.params, "skip_confirm")
            confirm_bar = _integer_param(self.params, "confirm_bar")
            if confirm_bar is None or confirm_bar < 0 or confirm_bar != confirm_bar.to_integral_value() or confirm_bar > Decimal("100000"):
                raise ValueError("skip_confirm confirm_bar must be a finite integer in [0, 100000]")
            max_abs_position = _decimal_param(self.params, "max_abs_position")
            if max_abs_position is None or max_abs_position < 0 or max_abs_position > Decimal("1000"):
                raise ValueError("skip_confirm max_abs_position must be finite and in [0, 1000]")
        elif self.type == ProbeType.BLIND_RETRY:
            _validate_scenario_param(self.params, "blind_retry")
            retry_after_bar = _integer_param(self.params, "retry_after_bar")
            if retry_after_bar is None or retry_after_bar < 0 or retry_after_bar != retry_after_bar.to_integral_value() or retry_after_bar > Decimal("100000"):
                raise ValueError("blind_retry retry_after_bar must be a finite integer in [0, 100000]")
            max_retries = _integer_param(self.params, "max_retries")
            if max_retries is None or max_retries < 0 or max_retries != max_retries.to_integral_value() or max_retries > Decimal("1000"):
                raise ValueError("blind_retry max_retries must be a finite integer in [0, 1000]")
        return self


class RedlineSpec(RedlineModel):
    version: Literal["redline.spec.v2.1", "redline.spec.v2.2"] = "redline.spec.v2.2"
    spec_id: str
    probes: list[ProbeSpec] = Field(
        min_length=1,
        json_schema_extra={
            "x-unique-by": "id",
            "x-runtime-constraints": [
                {
                    "name": "unique_probe_ids",
                    "enforced_by": "redline.models.RedlineSpec.require_block_probe",
                }
            ],
            "contains": {
                "anyOf": [
                    {"not": {"required": ["block"]}},
                    {"properties": {"block": {"const": True}}, "required": ["block"]},
                ]
            }
        },
    )
    compiler: str = "json"
    declared_intent: str | None = None
    model: str | None = None
    tool_schema_hash: str | None = None
    degraded_reason: str | None = None
    fill_model: Literal["next_bar_open"] = "next_bar_open"
    fee_bps: str = Field(default="0", pattern=_BPS_ZERO_TO_10000_PATTERN, description="Non-negative basis points in [0, 10000].")
    slippage_bps: str = Field(default="0", pattern=_BPS_ZERO_TO_10000_PATTERN, description="Non-negative basis points in [0, 10000].")

    @model_validator(mode="after")
    def require_block_probe(self) -> RedlineSpec:
        _ensure_unique_ids("probe", [probe.id for probe in self.probes])
        if not any(probe.block for probe in self.probes):
            raise ValueError("redline spec must define at least one block probe")
        for key in ("fee_bps", "slippage_bps"):
            value = _decimal_param({"value": getattr(self, key)}, "value")
            if value is None or value < 0 or value > Decimal("10000"):
                raise ValueError(f"{key} must be finite and in [0, 10000]")
        return self


class Scenario(RedlineModel):
    id: str
    path: str
    timeframe: str = "1h"
    data_hash: str | None = None
    source_file_hash: str | None = None
    bar_count: int | None = None
    period_start: str | None = None
    period_end: str | None = None


class Suite(RedlineModel):
    version: Literal["redline.suite.v2"] = "redline.suite.v2"
    suite_id: str
    scenarios: list[Scenario] = Field(
        min_length=1,
        json_schema_extra={
            "x-unique-by": "id",
            "x-runtime-constraints": [
                {
                    "name": "unique_scenario_ids",
                    "enforced_by": "redline.models.Suite.require_unique_scenario_ids",
                }
            ],
        },
    )
    suite_lock_hash: str | None = None

    @model_validator(mode="after")
    def require_unique_scenario_ids(self) -> Suite:
        _ensure_unique_ids("scenario", [scenario.id for scenario in self.scenarios])
        return self


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

    @model_validator(mode="after")
    def require_unique_cells(self) -> CoverageManifest:
        if len(set(self.cells)) != len(self.cells):
            raise ValueError("coverage cells must be unique")
        if self.complete and (not self.cells or self.missing):
            raise ValueError("complete coverage requires non-empty cells and no missing entries")
        return self


def _ensure_unique_ids(kind: str, ids: list[str]) -> None:
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ValueError(f"duplicate {kind} id: {', '.join(duplicates)}")


def _decimal_param(params: dict[str, str], key: str) -> Decimal | None:
    try:
        value = Decimal(params[key])
    except (KeyError, InvalidOperation):
        return None
    return value if value.is_finite() else None


def _decimal_text(raw: str) -> Decimal | None:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw) is None:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    return value if value.is_finite() else None


def _integer_param(params: dict[str, str], key: str) -> Decimal | None:
    raw = params.get(key)
    if raw is None or re.fullmatch(r"[0-9]+", raw) is None:
        return None
    return Decimal(raw)


def _validate_scenario_param(params: dict[str, str], probe_name: str) -> None:
    scenario_id = params.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in P0_ALLOWED_SCENARIO_IDS:
        raise ValueError(f"{probe_name} requires a supported scenario_id")


class Proof(RedlineModel):
    proof_id: str
    phase: str
    kind: ProofKind
    verdict_bearing: bool
    inputs_hash: str
    artifact_hash: str
    assertions: list[Assertion] = Field(default_factory=list)
    reproduce: str | None = None
    fill_model: Literal["next_bar_open"] | None = None
    lookahead_guard: Literal["structural_next_bar"] | None = None
    fees_modeled: bool | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class DecisionContext(RedlineModel):
    suite_id: str
    spec_hash: str
    chain_status: ChainStatus = ChainStatus.GENESIS
    reject_reason: ReasonCode | None = None


class DecisionEnvelope(RedlineModel):
    envelope_version: Literal["redline.decision.v1"] = "redline.decision.v1"
    status: Status
    verdict_tier: VerdictTier | None = None
    adjusted_size_cap: str | None = None
    reason_code: ReasonCode
    chain_status: ChainStatus
    required_proof_ids: list[str]
    satisfied_proof_ids: list[str]
    coverage: CoverageManifest
    capabilities: Capabilities

    @model_validator(mode="after")
    def require_reduce_size_cap(self) -> DecisionEnvelope:
        if self.verdict_tier is VerdictTier.REDUCE_SIZE:
            cap = _decimal_text(self.adjusted_size_cap or "")
            if cap is None or cap <= 0 or cap > 1:
                raise ValueError("REDUCE_SIZE verdict requires adjusted_size_cap in (0, 1]")
        elif self.adjusted_size_cap is not None:
            raise ValueError("adjusted_size_cap is only valid for REDUCE_SIZE verdicts")
        return self


class PackageInfo(RedlineModel):
    identity_hash: str
    manifest_hash: str
    canonical_tar_rules: Literal["redline.v9.canonical-tree"] = CANONICAL_TAR_RULES
    adapter_id: Literal["python_strategy_sandbox"] = PLAYBOOK_ADAPTER_ID
    identity_lock_hash: str
    identity_lock_path: str


class PackageIdentityFile(RedlineModel):
    path: str
    hash: str


class PlaybookIdentityLock(RedlineModel):
    version: Literal["redline.playbook_identity.v1"] = "redline.playbook_identity.v1"
    adapter_id: Literal["python_strategy_sandbox"] = PLAYBOOK_ADAPTER_ID
    canonical_tar_rules: Literal["redline.v9.canonical-tree"] = CANONICAL_TAR_RULES
    locked_files: list[PackageIdentityFile] = Field(min_length=1)
    identity_hash: str
    lock_hash: str


class EditProvenance(RedlineModel):
    tool: str = "fixture"
    prompt_digest: str
    diff_hash: str
    locked_by: str = "author"
    captured_at: str


class PackageImportResult(RedlineModel):
    schema_version: Literal["redline.package_import.v1"] = "redline.package_import.v1"
    path: str
    identity_hash: str
    files: list[str]
    adapter_id: Literal["python_strategy_sandbox"] = PLAYBOOK_ADAPTER_ID
    identity_lock_hash: str
    identity_lock_path: str


class PublishPreflightResult(RedlineModel):
    schema_version: Literal["redline.publish_preflight.v1"] = "redline.publish_preflight.v1"
    ok: bool
    state: str
    receipt_hash: str | None = None
    package_hash: str | None = None
    report_hash: str | None = None
    package_archive_hash: str | None = None
    ledger_hash: str | None = None
    ledger_checkpoint_hash: str | None = None
    ledger_attestation_hash: str | None = None
    annotation_hash: str | None = None
    preflight_transcript_path: str | None = None
    preflight_transcript_hash: str | None = None
    sponsor_evidence: dict[str, str] = Field(default_factory=dict)
    reason_code: ReasonCode | None = None


class LedgerCheckpoint(RedlineModel):
    version: Literal["redline.ledger.checkpoint.v1"] = "redline.ledger.checkpoint.v1"
    ledger_path: str
    ledger_hash: str
    ledger_tail_hash: str
    ledger_entry_count: int
    subject_receipt_hashes: list[str]
    merkle_root: str = "sha256:genesis"
    anchor_kind: Literal["local-artifact", "external-trust-root"] = "local-artifact"
    checkpoint_hash: str


class LedgerCheckpointAttestation(RedlineModel):
    version: Literal["redline.ledger.attestation.v1"] = "redline.ledger.attestation.v1"
    checkpoint_hash: str
    ledger_hash: str
    ledger_tail_hash: str
    ledger_entry_count: int
    subject_receipt_hashes: list[str]
    trust_policy_id: str
    key_id: str
    issuer: str
    audience: str = "redline.publish"
    signer: str
    public_key: str
    signed_at: str
    expires_at: str | None = None
    signature: str
    attestation_hash: str


class TrustKey(RedlineModel):
    key_id: str
    public_key: str
    issuer: str
    revoked: bool = False
    valid_from: str | None = None
    valid_until: str | None = None


class TrustPolicy(RedlineModel):
    version: Literal["redline.trust_policy.v1"] = "redline.trust_policy.v1"
    policy_id: str
    audience: Literal["redline.publish"] = "redline.publish"
    allow_demo: bool = False
    keys: list[TrustKey]
    policy_hash: str


class PackageAnnotation(RedlineModel):
    version: Literal["redline.package.annotation.v1"] = "redline.package.annotation.v1"
    annotation_kind: Literal["demo-preview", "publish-preflight"] = "publish-preflight"
    receipt_path: str
    receipt_hash: str
    report_hash: str
    package_hash: str
    ledger_hash: str
    ledger_checkpoint_hash: str
    ledger_attestation_hash: str | None = None
    trust_policy_id: str | None = None
    trusted_ledger_key_id: str | None = None
    strength_summary: str
    chain_status: ChainStatus
    verification_level: VerificationLevel
    annotation_hash: str


class ExecutionIntent(RedlineModel):
    version: Literal["redline.execution.intent.v1"] = "redline.execution.intent.v1"
    symbol: str = "BTCUSDT"
    product_type: str = "USDT-FUTURES"
    margin_mode: Literal["isolated", "crossed"] = "isolated"
    margin_coin: str = "USDT"
    size: str = "0.0001"
    side: Literal["buy", "sell"] = "buy"
    trade_side: Literal["open", "close"] | None = "open"
    order_type: Literal["market", "limit"] = "market"
    force: Literal["ioc", "fok", "gtc", "post_only"] | None = None
    price: str | None = None
    confirm_mainnet_order: bool = False

    @model_validator(mode="after")
    def require_valid_order_fields(self) -> ExecutionIntent:
        if re.fullmatch(r"[A-Z0-9]+", self.symbol) is None:
            raise ValueError("execution symbol must be uppercase alphanumeric")
        if re.fullmatch(r"[A-Z0-9-]+", self.product_type) is None:
            raise ValueError("execution product_type must be uppercase alphanumeric or hyphenated")
        if re.fullmatch(r"[A-Z0-9]+", self.margin_coin) is None:
            raise ValueError("execution margin_coin must be uppercase alphanumeric")
        size = _decimal_text(self.size)
        if size is None or size <= 0:
            raise ValueError("execution size must be a positive decimal")
        if self.order_type == "limit" and not self.price:
            raise ValueError("limit execution requires price")
        if self.price is not None:
            price = _decimal_text(self.price)
            if price is None or price <= 0:
                raise ValueError("execution price must be a positive decimal")
        return self


class ExecutionLedgerEntry(RedlineModel):
    version: Literal["redline.execution.ledger_entry.v1"] = "redline.execution.ledger_entry.v1"
    run_id: str
    receipt_hash: str
    issuance_ledger_entry_hash: str = "sha256:genesis"
    issuance_checkpoint_hash: str = "sha256:genesis"
    approval_hash: str = "sha256:unapproved"
    verdict: Status
    client_oid: str
    bitget_order_id: str
    response_hash: str
    placed_at: str
    previous_entry_hash: str
    entry_hash: str


class ExecutionEvidence(RedlineModel):
    version: Literal["redline.execution.evidence.v1"] = "redline.execution.evidence.v1"
    run_id: str
    receipt_hash: str
    issuance_ledger_entry_hash: str = "sha256:genesis"
    issuance_checkpoint_hash: str = "sha256:genesis"
    approval_hash: str = "sha256:unapproved"
    verdict: Status
    client_oid: str
    bitget_order_id: str
    response_hash: str
    placed_at: str
    symbol: str
    product_type: str
    order_mode: Literal["demo", "mainnet"]
    paptrading: str | None = "1"
    execution_ledger_entry_hash: str
    artifact_hash: str


class ReleaseBundleAttestation(RedlineModel):
    schema_version: Literal["redline.attestation.v1"] = "redline.attestation.v1"
    release_id: str
    bundle_hash: str
    manifest_hash: str
    evidence_merkle_root: str = "sha256:genesis"
    attestation_provider: Literal["local_signed", "evm_tx", "hedera_hcs"] = "local_signed"
    attested_at: str
    attester_principal: str
    key_id: str = "local"
    issuer: str = "redline"
    public_key: str
    external_reference: dict[str, str] = Field(default_factory=dict)
    signature: str
    attestation_hash: str


class BaselineInfo(RedlineModel):
    package_hash: str
    baseline_receipt_hash: str | None = None
    baseline_version_id: str = "fixture:baseline"
    package_name: str = "baseline"
    chain_status: ChainStatus = ChainStatus.GENESIS


class CandidateInfo(RedlineModel):
    package_hash: str
    candidate_version_id: str = "fixture:candidate"
    package_name: str = "candidate"


class SpecInfo(RedlineModel):
    spec_hash: str
    source_path: str = ""
    compiler: str = "json"
    model: str | None = None
    tool_schema_hash: str | None = None
    degraded_reason: str | None = None


class SuiteInfo(RedlineModel):
    suite_id: str
    scenarios: list[str]
    suite_lock_hash: str
    source_path: str = ""


class RunnerInfo(RedlineModel):
    engine: Literal["deterministic", "nautilus"] = "deterministic"
    engine_source_tree_hash: str
    runner_lock_hash: str
    env_lock: str = "TZ=UTC;PYTHONHASHSEED-independent;LC_ALL=C"


class ResultInfo(RedlineModel):
    status: Status
    new_breaches: list[Assertion]
    result_hash: str


class ReceiptDecision(RedlineModel):
    reason_code: ReasonCode
    verdict_tier: VerdictTier | None = None
    adjusted_size_cap: str | None = None
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
    version: Literal["redline.receipt.v3.2", "redline.receipt.v3.3"] = "redline.receipt.v3.3"
    prev_receipt_hash: str = "sha256:genesis"
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
    status: Literal["proof_verified", "proof_mismatch", "proof_unreplayable"]
    proof_id: str
    artifact_hash: str | None = None
    reason_code: ReasonCode = ReasonCode.PASS


class DoctorCheck(RedlineModel):
    name: str
    ok: bool
    reason_code: ReasonCode = ReasonCode.PASS
    detail: str = ""
    evidence: dict[str, str] = Field(default_factory=dict)


class DoctorResult(RedlineModel):
    schema_version: Literal["redline.doctor.v1"] = "redline.doctor.v1"
    ok: bool
    reason_code: ReasonCode = ReasonCode.PASS
    checks: list[DoctorCheck]


class ReportJson(RedlineModel):
    version: Literal["redline.report.v1"] = "redline.report.v1"
    envelope: DecisionEnvelope
    receipt_hash: str | None = None
    strength_summary: str = ""
    traces: list[ReplayTrace]
    proof_ids: list[str]
    proofs: list[Proof] = Field(default_factory=list)
    edit_provenance: EditProvenance | None = None
    publish: PublishInfo | None = None
    coverage_missing: list[str] = Field(default_factory=list)
    verification_level: VerificationLevel | None = None
    report_hash: str


class RunArtifacts(RedlineModel):
    envelope: DecisionEnvelope
    receipt: Receipt | None
    proofs: list[Proof]
    traces: list[ReplayTrace]
    report_json: dict[str, Any]
    out_dir: Path | None = None
