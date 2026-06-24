from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

from redline.canonical import CanonicalizationError, hash_file, hash_obj
from redline.io_safety import atomic_write_text, ensure_safe_output_dir, reject_unsafe_output_file
from redline.merkle import merkle_root
from redline.models import LedgerCheckpoint, ReasonCode
from redline.receipt import compute_ledger_checkpoint_hash
from redline.service.artifacts import resolve_artifact_path
from redline.service.models import (
    ExecutionRequest,
    ReleaseCandidateResponse,
    ReleaseState,
    ReleaseTier,
    RiskPolicyRequest,
    RunResponse,
    StrategyVersionResponse,
)
from redline.service.store import utc_now
from redline.sponsor.bitget_execution import DEFAULT_DEMO_SYMBOL, DEFAULT_PRODUCT_TYPE
from redline.sponsor.bitget_execution import ExecutionBlocked, load_exchange_preflight_evidence, load_execution_evidence, load_order_status_evidence


AUDIT_LEDGER_NAME = "release-audit-ledger.jsonl"
BUNDLE_NAME = "release-evidence-bundle.json"
MANIFEST_NAME = "release-evidence-manifest.json"
SIMULATION_NAME = "release-simulation-evidence.json"
RISK_POLICY_NAME = "release-risk-policy.json"
DECISION_NAME = "release-decision-record.json"


@dataclass(frozen=True)
class ReleaseTierDecision:
    tier: ReleaseTier
    reason: str
    signals: dict[str, bool]


@dataclass(frozen=True)
class RiskPolicyDecision:
    decision: Literal["allow", "reduce", "block"]
    reason: str | None = None
    adjusted_size: str | None = None

    @property
    def ok(self) -> bool:
        return self.decision != "block"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def reduced(self) -> bool:
        return self.decision == "reduce"

    def model_dump(self) -> dict[str, str]:
        payload = {"decision": self.decision}
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.adjusted_size is not None:
            payload["adjusted_size"] = self.adjusted_size
        return payload


def release_dir(root: Path, release_id: str) -> Path:
    if "/" in release_id or "\\" in release_id or release_id in {"", ".", ".."}:
        raise CanonicalizationError("release id is not a safe artifact path", ReasonCode.RECEIPT_BINDING_FAILED)
    out_dir = root / "releases" / release_id
    ensure_safe_output_dir(out_dir)
    return out_dir


def resolve_release_run_dir(release_dir_path: Path, run_id: object) -> Path:
    text = str(run_id or "")
    if "/" in text or "\\" in text or text in {"", ".", ".."} or any(part in {"", ".", ".."} for part in Path(text).parts):
        raise CanonicalizationError("execution run id is not a safe artifact path", ReasonCode.RECEIPT_BINDING_FAILED)
    runs_root = release_dir_path.parent.parent / "runs"
    run_dir = runs_root / text
    try:
        run_dir.resolve().relative_to(runs_root.resolve())
    except ValueError as exc:
        raise CanonicalizationError("execution run path escapes service runs root", ReasonCode.RECEIPT_BINDING_FAILED) from exc
    return run_dir


def write_release_json(root: Path, release_id: str, filename: str, payload: dict[str, Any]) -> Path:
    path = release_dir(root, release_id) / filename
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def load_release_audit_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    reject_unsafe_output_file(path)
    previous = "sha256:genesis"
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CanonicalizationError("release audit ledger is unreadable", ReasonCode.DATA_MISSING) from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CanonicalizationError("release audit ledger entry is invalid JSON", ReasonCode.PARSE_ERROR) from exc
        if entry.get("previous_entry_hash") != previous:
            raise CanonicalizationError("release audit ledger hash chain mismatch", ReasonCode.RECEIPT_MISMATCH)
        if entry.get("entry_hash") != release_audit_entry_hash(entry):
            raise CanonicalizationError("release audit ledger entry hash mismatch", ReasonCode.RECEIPT_MISMATCH)
        entries.append(entry)
        previous = str(entry["entry_hash"])
    return entries


def append_release_audit_event(
    *,
    root: Path,
    store: Any,
    release_id: str,
    event_type: str,
    actor: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ledger_path = release_dir(root, release_id) / AUDIT_LEDGER_NAME
    entries = load_release_audit_ledger(ledger_path)
    entry = {
        "schema_version": "redline.release.audit.v1",
        "release_id": release_id,
        "event_type": event_type,
        "actor": actor,
        "created_at": utc_now(),
        "payload": payload or {},
        "previous_entry_hash": entries[-1]["entry_hash"] if entries else "sha256:genesis",
        "entry_hash": "sha256:" + "0" * 64,
    }
    entry["entry_hash"] = release_audit_entry_hash(entry)
    ledger_text = "".join(json.dumps(item, sort_keys=True) + "\n" for item in [*entries, entry])
    atomic_write_text(ledger_path, ledger_text)
    store.append_release_audit_entry(release_id=release_id, entry=entry)
    return entry


def release_audit_entry_hash(entry: dict[str, Any]) -> str:
    return hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})


def policy_hash(policy: RiskPolicyRequest | dict[str, Any]) -> str:
    payload = policy.model_dump(mode="json") if isinstance(policy, RiskPolicyRequest) else policy
    return hash_obj(payload)


def evidence_fingerprint(release: ReleaseCandidateResponse, *, strategy_version: StrategyVersionResponse | None = None) -> str:
    payload: dict[str, Any] = {
        "release_id": release.release_id,
        "strategy_id": release.strategy_id,
        "version_id": release.version_id,
        "run_id": release.run_id,
        "redline_receipt_hash": release.redline_receipt_hash,
        "redline_report_hash": release.redline_report_hash,
        "simulation_evidence_hash": release.simulation_evidence_hash,
        "risk_policy_hash": release.risk_policy_hash,
    }
    if strategy_version is not None:
        payload["strategy_version"] = {
            "version_id": strategy_version.version_id,
            "strategy_id": strategy_version.strategy_id,
            "package_hash": strategy_version.package_hash,
            "identity_lock_hash": strategy_version.identity_lock_hash,
        }
    return hash_obj(payload)


def approval_record_hash(approval: dict[str, Any]) -> str:
    payload = dict(approval)
    if "consumed_at" in payload:
        payload["consumed_at"] = None
    return hash_obj(payload)


def simulation_evidence_hash(payload: dict[str, Any]) -> str:
    return hash_obj(payload)


def risk_policy_breach(policy: dict[str, Any], execution: ExecutionRequest | None = None) -> RiskPolicyDecision:
    execution = execution or ExecutionRequest()
    symbol = (execution.symbol or DEFAULT_DEMO_SYMBOL).upper()
    product_type = (execution.product_type or DEFAULT_PRODUCT_TYPE).upper()
    allowed_symbols = {str(item).upper() for item in policy.get("allowed_symbols", [])}
    allowed_product_types = {str(item).upper() for item in policy.get("allowed_product_types", [])}
    if allowed_symbols and symbol not in allowed_symbols:
        return RiskPolicyDecision(decision="block", reason="symbol is not allowed by release risk policy")
    if allowed_product_types and product_type not in allowed_product_types:
        return RiskPolicyDecision(decision="block", reason="product type is not allowed by release risk policy")
    # Mainnet veto and the symbol/product allowlist are absolute blocks: evaluate them
    # BEFORE the notional-reduce branch so a release that forbids mainnet can never be
    # downgraded to a (size-reduced) mainnet order by also tripping the notional cap.
    if execution.confirm_mainnet_order and not bool(policy.get("mainnet_enabled", False)):
        return RiskPolicyDecision(decision="block", reason="mainnet execution is disabled by release risk policy")
    max_notional = _decimal_field(policy, "max_order_notional_usdt")
    expected_notional = _decimal_field(policy, "expected_order_notional_usdt")
    if expected_notional > max_notional:
        adjusted_size = _adjusted_execution_size(execution.size, max_notional=max_notional, expected_notional=expected_notional)
        if adjusted_size is None:
            return RiskPolicyDecision(decision="block", reason="expected order notional exceeds release risk policy")
        return RiskPolicyDecision(
            decision="reduce",
            reason="expected order notional exceeds release risk policy",
            adjusted_size=adjusted_size,
        )
    return RiskPolicyDecision(decision="allow")


def compute_release_tier(release: ReleaseCandidateResponse, strategy_version: StrategyVersionResponse | None = None) -> ReleaseTierDecision:
    _ = strategy_version
    signals = _release_tier_signals(release)
    if release.state is ReleaseState.RELEASED_LIVE_GATED and _has_live_gate_controls(release):
        return ReleaseTierDecision(tier=ReleaseTier.L2, reason="live_gated release state reached", signals=signals)
    if all(signals[key] for key in ("redline_passed", "simulation_evidence", "risk_policy", "demo_execution")):
        return ReleaseTierDecision(tier=ReleaseTier.L1, reason="paptrading demo execution evidence is present", signals=signals)
    return ReleaseTierDecision(tier=ReleaseTier.L0, reason="simulation/pre-demo release tier", signals=signals)


def _release_tier_signals(release: ReleaseCandidateResponse) -> dict[str, bool]:
    return {
        "redline_passed": bool(release.run_id and release.redline_reason_code == ReasonCode.PASS.value and release.redline_receipt_hash),
        "simulation_evidence": release.simulation_evidence is not None and bool(release.simulation_evidence_hash),
        "risk_policy": release.risk_policy is not None and bool(release.risk_policy_hash),
        "demo_execution": release.execution_evidence is not None and bool(release.execution_run_id),
        "approval": release.approval is not None,
        "live_gate_controls": _has_live_gate_controls(release),
    }


def _has_live_gate_controls(release: ReleaseCandidateResponse) -> bool:
    policy = release.risk_policy or {}
    if not bool(policy.get("mainnet_enabled", False)):
        return False
    controls = release.metadata.get("live_gate")
    if not isinstance(controls, dict):
        return False
    release_manager_id = _nonempty_text(controls.get("release_manager_id"))
    second_reviewer_id = _nonempty_text(controls.get("second_reviewer_id"))
    return (
        controls.get("confirm_mainnet_order") is True
        and controls.get("allow_live_gated_release") is True
        and release_manager_id is not None
        and second_reviewer_id is not None
        and second_reviewer_id != release_manager_id
        and second_reviewer_id != release.created_by
    )


def _nonempty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def generate_release_evidence_bundle(
    *,
    root: Path,
    release: ReleaseCandidateResponse,
    strategy_version: StrategyVersionResponse,
    run: RunResponse | None,
) -> tuple[Path, Path, str, dict[str, Any]]:
    out_dir = release_dir(root, release.release_id)
    audit_path = out_dir / AUDIT_LEDGER_NAME
    audit_entries = load_release_audit_ledger(audit_path)
    run_artifacts = _load_run_artifacts(run)
    tier = compute_release_tier(release, strategy_version=strategy_version)
    decision_record = {
        "schema_version": "redline.release.decision.v1",
        "release_id": release.release_id,
        "state": release.state.value,
        "release_tier": tier.tier.value,
        "release_tier_reason": tier.reason,
        "release_tier_signals": tier.signals,
        "approval": release.approval,
        "risk_policy_hash": release.risk_policy_hash,
        "evidence_fingerprint": evidence_fingerprint(release, strategy_version=strategy_version),
        "generated_at": utc_now(),
    }
    write_release_json(root, release.release_id, DECISION_NAME, decision_record)
    bundle = {
        "schema_version": "redline.release.evidence_bundle.v1",
        "release_candidate": release.model_dump(mode="json"),
        "strategy_version": strategy_version.model_dump(mode="json"),
        "redline": {
            "run_id": run.run_id if run else None,
            "state": run.state.value if run else None,
            "reason_code": run.reason_code if run else None,
            "receipt_hash": run.receipt_hash if run else None,
            "report_hash": run.report_hash if run else None,
            "artifacts": run_artifacts,
        },
        "simulation_evidence": release.simulation_evidence,
        "risk_policy": release.risk_policy,
        "execution_evidence": release.execution_evidence,
        "release_decision_record": decision_record,
        "audit_log_slice": audit_entries,
    }
    bundle_path = write_release_json(root, release.release_id, BUNDLE_NAME, bundle)
    bundle_hash = hash_file(bundle_path)
    manifest = {
        "schema_version": "redline.release.evidence_manifest.v1",
        "release_id": release.release_id,
        "generated_at": utc_now(),
        "files": _release_manifest_files(out_dir, run=run, bundle_hash=bundle_hash),
    }
    manifest_path = write_release_json(root, release.release_id, MANIFEST_NAME, manifest)
    manifest_hash = hash_file(manifest_path)
    if hash_file(bundle_path) != bundle_hash:
        raise CanonicalizationError("release evidence bundle hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    manifest = {**manifest, "manifest_hash": manifest_hash}
    return bundle_path, manifest_path, manifest_hash, manifest


def verify_release_file(path: Path, expected_hash: str) -> None:
    reject_unsafe_output_file(path)
    if hash_file(path) != expected_hash:
        raise CanonicalizationError("release evidence file hash mismatch", ReasonCode.RECEIPT_MISMATCH)


def verify_release_evidence_bundle(bundle_path: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    try:
        reject_unsafe_output_file(bundle_path)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        if not isinstance(bundle, dict):
            raise CanonicalizationError("release evidence bundle is invalid", ReasonCode.SCHEMA_INVALID)
        record("bundle-json", True)
    except (CanonicalizationError, OSError, json.JSONDecodeError) as exc:
        record("bundle-verification", False, _verification_detail(exc))
        bundle = None
    if isinstance(bundle, dict):
        release_dir_path = bundle_path.parent
        _run_bundle_check(checks, "manifest-files", lambda: _verify_bundle_manifest(release_dir_path, checks))
        _run_bundle_check(checks, "audit-ledger-chain", lambda: _verify_bundle_audit_ledger(release_dir_path, checks))
        _run_bundle_check(checks, "simulation-evidence", lambda: _verify_bundle_simulation(bundle, checks))
        _run_bundle_check(checks, "risk-policy", lambda: _verify_bundle_risk_policy(bundle, checks))
        _run_bundle_check(checks, "execution-evidence", lambda: _verify_bundle_execution(bundle_path, bundle, checks))
        _run_bundle_check(checks, "execution-sidecars", lambda: _verify_bundle_execution_sidecars(bundle_path, bundle, checks))
        _verify_bundle_chain_links(bundle, checks)
    ok = all(item["ok"] for item in checks)
    return {
        "schema_version": "redline.release_bundle.verify.v1",
        "ok": ok,
        "bundle_path": str(bundle_path),
        "bundle_hash": hash_file(bundle_path) if bundle_path.exists() and bundle_path.is_file() else None,
        "checks": checks,
    }


def _run_bundle_check(checks: list[dict[str, Any]], name: str, check) -> None:
    before = len(checks)
    try:
        check()
    except (CanonicalizationError, OSError, json.JSONDecodeError, ExecutionBlocked, ValueError, TypeError) as exc:
        if len(checks) == before:
            checks.append({"name": name, "ok": False, "detail": _verification_detail(exc)})


def _verify_bundle_audit_ledger(release_dir_path: Path, checks: list[dict[str, Any]]) -> None:
    audit_path = release_dir_path / AUDIT_LEDGER_NAME
    load_release_audit_ledger(audit_path)
    checks.append({"name": "audit-ledger-chain", "ok": True, "detail": ""})


def _release_manifest_files(out_dir: Path, *, run: RunResponse | None, bundle_hash: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for filename in [BUNDLE_NAME, AUDIT_LEDGER_NAME, SIMULATION_NAME, RISK_POLICY_NAME, DECISION_NAME]:
        path = out_dir / filename
        if path.exists():
            files.append(_manifest_file(filename, path, override_hash=bundle_hash if filename == BUNDLE_NAME else None))
    if run and run.artifact_manifest:
        for artifact in run.artifact_manifest.artifacts:
            files.append(
                {
                    "path": f"run/{run.run_id}/{artifact.path}",
                    "kind": artifact.kind,
                    "sha256": artifact.sha256,
                    "bytes": artifact.bytes,
                }
            )
    return files


def _verify_bundle_manifest(release_dir_path: Path, checks: list[dict[str, Any]]) -> None:
    manifest_path = release_dir_path / MANIFEST_NAME
    reject_unsafe_output_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if not isinstance(files, list):
        raise CanonicalizationError("release evidence manifest is invalid", ReasonCode.SCHEMA_INVALID)
    for item in files:
        if not isinstance(item, dict):
            raise CanonicalizationError("release evidence manifest entry is invalid", ReasonCode.SCHEMA_INVALID)
        rel_path = str(item.get("path") or "")
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            raise CanonicalizationError("release evidence manifest path is unsafe", ReasonCode.RECEIPT_BINDING_FAILED)
        if rel_path.startswith("run/"):
            parts = Path(rel_path).parts
            if len(parts) < 3:
                raise CanonicalizationError("release evidence manifest run path is invalid", ReasonCode.SCHEMA_INVALID)
            path = resolve_artifact_path(resolve_release_run_dir(release_dir_path, parts[1]), Path(*parts[2:]).as_posix())
        else:
            path = release_dir_path / rel_path
            reject_unsafe_output_file(path)
            try:
                path.resolve().relative_to(release_dir_path.resolve())
            except ValueError as exc:
                raise CanonicalizationError("release evidence manifest path escapes release directory", ReasonCode.RECEIPT_BINDING_FAILED) from exc
        if not path.exists():
            raise CanonicalizationError("release evidence manifest file is missing", ReasonCode.DATA_MISSING)
        expected = str(item.get("sha256") or "")
        if not expected or hash_file(path) != expected:
            raise CanonicalizationError("release evidence manifest hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    checks.append({"name": "manifest-files", "ok": True, "detail": str(len(files))})


def _verify_bundle_simulation(bundle: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    simulation = bundle.get("simulation_evidence")
    if simulation is None:
        checks.append({"name": "simulation-evidence", "ok": False, "detail": "missing"})
        return
    if not isinstance(simulation, dict):
        raise CanonicalizationError("simulation evidence is invalid", ReasonCode.SCHEMA_INVALID)
    expected = simulation.get("evidence_hash")
    actual = simulation_evidence_hash({key: value for key, value in simulation.items() if key != "evidence_hash"})
    if expected != actual:
        raise CanonicalizationError("simulation evidence hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    checks.append({"name": "simulation-evidence", "ok": True, "detail": str(expected)})


def _verify_bundle_risk_policy(bundle: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    risk_policy = bundle.get("risk_policy")
    if risk_policy is None:
        checks.append({"name": "risk-policy", "ok": False, "detail": "missing"})
        return
    if not isinstance(risk_policy, dict):
        raise CanonicalizationError("risk policy is invalid", ReasonCode.SCHEMA_INVALID)
    expected = risk_policy.get("policy_hash")
    payload = {field: risk_policy[field] for field in RiskPolicyRequest.model_fields if field in risk_policy}
    actual = policy_hash(payload)
    if expected != actual:
        raise CanonicalizationError("risk policy hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    checks.append({"name": "risk-policy", "ok": True, "detail": str(expected)})


def _verify_bundle_execution(bundle_path: Path, bundle: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    execution = bundle.get("execution_evidence")
    if execution is None:
        checks.append({"name": "execution-evidence", "ok": False, "detail": "missing"})
        return
    if not isinstance(execution, dict):
        raise CanonicalizationError("execution evidence is invalid", ReasonCode.SCHEMA_INVALID)
    evidence_path = resolve_release_run_dir(bundle_path.parent, execution.get("run_id")) / "execution-evidence.json"
    evidence = load_execution_evidence(evidence_path)
    if evidence.model_dump(mode="json") != execution:
        raise CanonicalizationError("execution evidence bundle copy mismatch", ReasonCode.RECEIPT_MISMATCH)
    checks.append({"name": "execution-evidence", "ok": True, "detail": evidence.artifact_hash})


def _verify_bundle_execution_sidecars(bundle_path: Path, bundle: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    execution = bundle.get("execution_evidence")
    if not isinstance(execution, dict):
        return
    run_dir = resolve_release_run_dir(bundle_path.parent, execution.get("run_id"))
    preflight_path = run_dir / "exchange-preflight-evidence.json"
    order_status_path = run_dir / "order-status-evidence.json"
    if preflight_path.exists():
        preflight = load_exchange_preflight_evidence(preflight_path)
        checks.append({"name": "exchange-preflight-evidence", "ok": preflight.ok, "detail": preflight.preflight_hash})
    if order_status_path.exists():
        order_status = load_order_status_evidence(order_status_path)
        checks.append({"name": "order-status-evidence", "ok": order_status.status != "unknown_reconciliation_required", "detail": order_status.evidence_hash})


def _verify_bundle_chain_links(bundle: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    chain_checks = [
        ("chain-receipt-link", _check_chain_receipt_link),
        ("chain-approval-link", _check_chain_approval_link),
        ("chain-execution-link", _check_chain_execution_link),
        ("chain-checkpoint-link", _check_chain_checkpoint_link),
    ]
    for name, check in chain_checks:
        try:
            detail = check(bundle)
            checks.append({"name": name, "ok": True, "detail": detail})
        except (CanonicalizationError, KeyError, TypeError, ValueError) as exc:
            checks.append({"name": name, "ok": False, "detail": _verification_detail(exc)})


def _check_chain_receipt_link(bundle: dict[str, Any]) -> str:
    redline = _bundle_mapping(bundle, "redline")
    release = _bundle_mapping(bundle, "release_candidate")
    receipt = _bundle_artifact_content(bundle, "receipt")
    receipt_hash = _bundle_hash_string(redline, "receipt_hash", "receipt hash")
    if receipt.get("receipt_hash") != receipt_hash:
        raise CanonicalizationError("receipt link mismatch", ReasonCode.RECEIPT_MISMATCH)
    if release.get("redline_receipt_hash") not in {None, receipt_hash}:
        raise CanonicalizationError("release receipt link mismatch", ReasonCode.RECEIPT_MISMATCH)
    return receipt_hash


def _check_chain_approval_link(bundle: dict[str, Any]) -> str:
    release = _bundle_mapping(bundle, "release_candidate")
    execution = _bundle_mapping(bundle, "execution_evidence")
    approval = release.get("approval")
    if not isinstance(approval, dict):
        raise CanonicalizationError("approval link is missing", ReasonCode.DATA_MISSING)
    approval_hash = approval_record_hash(approval)
    if execution.get("approval_hash") != approval_hash:
        raise CanonicalizationError("approval link mismatch", ReasonCode.RECEIPT_MISMATCH)
    decision = bundle.get("release_decision_record")
    if isinstance(decision, dict) and decision.get("approval") != approval:
        raise CanonicalizationError("approval decision record mismatch", ReasonCode.RECEIPT_MISMATCH)
    return approval_hash


def _check_chain_execution_link(bundle: dict[str, Any]) -> str:
    redline = _bundle_mapping(bundle, "redline")
    execution = _bundle_mapping(bundle, "execution_evidence")
    execution_artifact = _bundle_artifact_content(bundle, "execution-evidence")
    receipt_hash = _bundle_hash_string(redline, "receipt_hash", "receipt hash")
    if execution.get("receipt_hash") != receipt_hash:
        raise CanonicalizationError("execution receipt link mismatch", ReasonCode.RECEIPT_MISMATCH)
    if execution_artifact != execution:
        raise CanonicalizationError("execution artifact copy mismatch", ReasonCode.RECEIPT_MISMATCH)
    expected_artifact_hash = hash_obj({key: value for key, value in execution.items() if key != "artifact_hash"})
    if execution.get("artifact_hash") != expected_artifact_hash:
        raise CanonicalizationError("execution evidence hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    return str(execution["artifact_hash"])


def _check_chain_checkpoint_link(bundle: dict[str, Any]) -> str:
    redline = _bundle_mapping(bundle, "redline")
    execution = _bundle_mapping(bundle, "execution_evidence")
    checkpoint_payload = _bundle_artifact_content(bundle, "issuance-ledger-checkpoint")
    ledger_payload = _bundle_artifact_content(bundle, "issuance-ledger")
    if not isinstance(ledger_payload, list):
        raise CanonicalizationError("checkpoint ledger link is invalid", ReasonCode.SCHEMA_INVALID)
    checkpoint = LedgerCheckpoint.model_validate(checkpoint_payload)
    if checkpoint.checkpoint_hash != compute_ledger_checkpoint_hash(checkpoint):
        raise CanonicalizationError("checkpoint hash mismatch", ReasonCode.RECEIPT_MISMATCH)
    if "merkle_root" in checkpoint.model_fields_set and checkpoint.merkle_root != merkle_root(checkpoint.subject_receipt_hashes):
        raise CanonicalizationError("checkpoint merkle root mismatch", ReasonCode.RECEIPT_MISMATCH)
    receipt_hash = _bundle_hash_string(redline, "receipt_hash", "receipt hash")
    if receipt_hash not in checkpoint.subject_receipt_hashes:
        raise CanonicalizationError("checkpoint does not cover receipt", ReasonCode.RECEIPT_MISMATCH)
    if execution.get("issuance_checkpoint_hash") != checkpoint.checkpoint_hash:
        raise CanonicalizationError("checkpoint execution link mismatch", ReasonCode.RECEIPT_MISMATCH)
    issuance_entry = _matching_issuance_entry(ledger_payload, receipt_hash)
    if execution.get("issuance_ledger_entry_hash") != issuance_entry["entry_hash"]:
        raise CanonicalizationError("checkpoint ledger entry link mismatch", ReasonCode.RECEIPT_MISMATCH)
    return checkpoint.checkpoint_hash


def _matching_issuance_entry(entries: list[Any], receipt_hash: str) -> dict[str, Any]:
    previous = "sha256:genesis"
    match: dict[str, Any] | None = None
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise CanonicalizationError("issuance ledger entry is invalid", ReasonCode.SCHEMA_INVALID)
        entry_hash = raw_entry.get("entry_hash")
        expected_hash = hash_obj({key: value for key, value in raw_entry.items() if key != "entry_hash"})
        if raw_entry.get("previous_entry_hash") != previous or entry_hash != expected_hash:
            raise CanonicalizationError("checkpoint ledger chain mismatch", ReasonCode.RECEIPT_MISMATCH)
        if raw_entry.get("receipt_hash") == receipt_hash:
            match = raw_entry
        previous = str(entry_hash)
    if match is None:
        raise CanonicalizationError("checkpoint ledger entry is missing", ReasonCode.DATA_MISSING)
    return match


def _bundle_artifact_content(bundle: dict[str, Any], artifact_id: str) -> Any:
    redline = _bundle_mapping(bundle, "redline")
    artifacts = redline.get("artifacts")
    if not isinstance(artifacts, list):
        raise CanonicalizationError("redline artifacts are missing", ReasonCode.DATA_MISSING)
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("artifact_id") == artifact_id:
            return artifact.get("content")
    raise CanonicalizationError(f"{artifact_id} artifact is missing", ReasonCode.DATA_MISSING)


def _bundle_mapping(payload: dict[str, Any], field: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise CanonicalizationError(f"{field} is missing", ReasonCode.DATA_MISSING)
    return value


def _bundle_hash_string(payload: dict[str, Any], field: str, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise CanonicalizationError(f"{label} is missing", ReasonCode.DATA_MISSING)
    return value


def _verification_detail(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if reason is not None:
        return f"{getattr(reason, 'value', str(reason))}: {exc}"
    return type(exc).__name__


def _manifest_file(rel_path: str, path: Path, *, override_hash: str | None = None) -> dict[str, Any]:
    reject_unsafe_output_file(path)
    return {
        "path": rel_path,
        "kind": "release-artifact",
        "sha256": override_hash or hash_file(path),
        "bytes": path.stat().st_size,
    }


def _load_run_artifacts(run: RunResponse | None) -> list[dict[str, Any]]:
    if run is None or run.artifact_manifest is None:
        return []
    loaded: list[dict[str, Any]] = []
    out_dir = Path(run.out_dir)
    for artifact in run.artifact_manifest.artifacts:
        path = resolve_artifact_path(out_dir, artifact.path)
        if hash_file(path) != artifact.sha256:
            raise CanonicalizationError("run artifact hash mismatch", ReasonCode.RECEIPT_MISMATCH)
        loaded.append(
            {
                "artifact_id": artifact.artifact_id,
                "kind": artifact.kind,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "bytes": artifact.bytes,
                "content": _read_artifact_content(path),
            }
        )
    return loaded


def _read_artifact_content(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return text


def _decimal_field(policy: dict[str, Any], field: str) -> Decimal:
    try:
        value = Decimal(str(policy[field]))
    except (KeyError, InvalidOperation) as exc:
        raise CanonicalizationError(f"invalid risk policy decimal field: {field}", ReasonCode.SCHEMA_INVALID) from exc
    if not value.is_finite() or value < 0:
        raise CanonicalizationError(f"invalid risk policy decimal field: {field}", ReasonCode.SCHEMA_INVALID)
    return value


def _adjusted_execution_size(size: str, *, max_notional: Decimal, expected_notional: Decimal) -> str | None:
    try:
        requested_size = Decimal(str(size))
    except InvalidOperation:
        return None
    if requested_size <= 0 or max_notional <= 0 or expected_notional <= 0:
        return None
    adjusted = requested_size * (max_notional / expected_notional)
    if adjusted <= 0:
        return None
    return _decimal_to_text(adjusted)


def _decimal_to_text(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
