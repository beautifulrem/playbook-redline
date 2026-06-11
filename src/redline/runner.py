from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import hash_file, hash_obj, hash_tree
from redline.engine_adapter import DeterministicReplayEngine, ReplayEngineError
from redline.models import (
    Assertion,
    ChainStatus,
    CoverageManifest,
    DecisionContext,
    Proof,
    ProofKind,
    ProbeOutcome,
    ReasonCode,
    RedlineSpec,
    ReplayTrace,
    Receipt,
    RunArtifacts,
    Scenario,
    Status,
    Suite,
    EditProvenance,
    Capability,
    LedgerCheckpoint,
    LedgerCheckpointAttestation,
    TrustPolicy,
)
from redline.probes import PROBE_REGISTRY
from redline.proof_kernel import REQUIRED_PROOFS, decide
from redline.receipt import assert_no_issuance_conflict, atomic_write_receipt, issue_receipt, make_decision_proof, make_verify_proof_reproduce
from redline.report import to_report
from redline.trust import verify_checkpoint_attestation
from redline.tripwire import VerdictPathViolation, verdict_path_tripwire

DEFAULT_EDIT_PROVENANCE_CAPTURED_AT = "2026-06-10T00:00:00Z"


def load_spec(path: Path) -> RedlineSpec:
    with path.open(encoding="utf-8") as fh:
        return RedlineSpec.model_validate(json.load(fh))


def load_suite(path: Path) -> Suite:
    with path.open(encoding="utf-8") as fh:
        payload = json.load(fh)
    suite = Suite.model_validate(payload)
    base = path.parent
    scenarios: list[Scenario] = []
    lock_scenarios: list[dict[str, object]] = []
    for scenario in suite.scenarios:
        scenario_path = Path(scenario.path)
        if not scenario_path.is_absolute():
            scenario_path = (base / scenario_path).resolve()
        metadata = _scenario_file_metadata(scenario_path)
        scenarios.append(scenario.model_copy(update={"path": str(scenario_path), **metadata}))
        lock_scenarios.append({**scenario.model_dump(mode="json"), **metadata})
    lock_payload = {
        "version": suite.version,
        "suite_id": suite.suite_id,
        "scenarios": lock_scenarios,
        "suite_lock_hash": None,
    }
    suite_lock_hash = hash_obj(lock_payload)
    if suite.suite_lock_hash is not None and suite.suite_lock_hash != suite_lock_hash:
        raise ValueError("suite_lock_hash mismatch")
    suite = suite.model_copy(update={"suite_lock_hash": suite_lock_hash})
    return suite.model_copy(update={"scenarios": scenarios})


def _scenario_file_metadata(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    timestamps = [row.get("timestamp", "") for row in rows if row.get("timestamp")]
    return {
        "data_hash": hash_file(path),
        "bar_count": len(rows),
        "period_start": timestamps[0] if timestamps else None,
        "period_end": timestamps[-1] if timestamps else None,
    }


def resolve_package_role_dir(package_dir: Path, role: str) -> Path:
    package_root = package_dir.resolve()
    role_path = Path(role)
    if not role or role_path.is_absolute() or any(part in {"", ".", ".."} for part in role_path.parts):
        raise ValueError(f"package role must stay under package root: {role}")
    resolved = (package_root / role_path).resolve()
    try:
        resolved.relative_to(package_root)
    except ValueError as exc:
        raise ValueError(f"package role escapes package root: {role}") from exc
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError(f"package role not found: {package_root / role_path}")
    return resolved


def run_redline(
    *,
    package_dir: Path,
    baseline: str,
    candidate: str,
    suite_path: Path,
    spec_path: Path,
    out_dir: Path | None = None,
    edit_provenance: EditProvenance | None = None,
    baseline_receipt_path: Path | None = None,
    baseline_trust_policy_path: Path | None = None,
    baseline_version_id: str | None = None,
    candidate_version_id: str | None = None,
    ledger_written_at: str | None = None,
    ledger_path_label: str | None = None,
) -> RunArtifacts:
    package_dir = package_dir.resolve()
    suite_path = suite_path.resolve()
    spec_path = spec_path.resolve()
    baseline_dir = resolve_package_role_dir(package_dir, baseline)
    candidate_dir = resolve_package_role_dir(package_dir, candidate)
    spec = load_spec(spec_path)
    suite = load_suite(suite_path)
    spec_hash = hash_obj(spec)
    package_hash = hash_tree(package_dir)
    baseline_hash = hash_tree(baseline_dir)
    candidate_hash = hash_tree(candidate_dir)
    expected_edit_diff_hash = hash_obj({"baseline": baseline_hash, "candidate": candidate_hash})
    effective_edit_provenance = edit_provenance or EditProvenance(
        prompt_digest=hash_obj({"prompt": "fixture make it more responsive"}),
        diff_hash=expected_edit_diff_hash,
        captured_at=DEFAULT_EDIT_PROVENANCE_CAPTURED_AT,
    )
    chain_status, baseline_receipt_hash, baseline_receipt_error = _baseline_chain(
        baseline_hash=baseline_hash,
        baseline_receipt_path=baseline_receipt_path,
        baseline_trust_policy_path=baseline_trust_policy_path,
    )
    proof_reproduce_kwargs = {
        "include_baseline_receipt": chain_status == ChainStatus.CHAINED,
        "include_trust_policy": chain_status == ChainStatus.CHAINED and baseline_trust_policy_path is not None,
    }

    def simple_proof(
        *,
        kind: ProofKind,
        phase: str,
        inputs: object,
        artifact: object,
        verdict_bearing: bool,
        assertions: list[Assertion] | None = None,
        meta: dict[str, object] | None = None,
    ) -> Proof:
        return _simple_proof(
            kind=kind,
            phase=phase,
            inputs=inputs,
            artifact=artifact,
            verdict_bearing=verdict_bearing,
            assertions=assertions,
            meta=meta,
            **proof_reproduce_kwargs,
        )

    proofs: list[Proof] = [
        simple_proof(
            kind=ProofKind.PACKAGE_CANONICAL,
            phase="import",
            inputs={"package": "playbook", "baseline_role": baseline, "candidate_role": candidate},
            artifact={"package_hash": package_hash, "baseline_hash": baseline_hash, "candidate_hash": candidate_hash},
            verdict_bearing=True,
        ),
        simple_proof(
            kind=ProofKind.EDIT_PROVENANCE,
            phase="capture-edit",
            inputs={"baseline_hash": baseline_hash, "candidate_hash": candidate_hash},
            artifact=effective_edit_provenance,
            verdict_bearing=False,
            meta={"expected_diff_hash": expected_edit_diff_hash, "binding": "package_pair"},
        ),
        simple_proof(
            kind=ProofKind.SPEC_COMPILE,
            phase="compile",
            inputs={"spec_id": spec.spec_id, "compiler": spec.compiler},
            artifact=spec,
            verdict_bearing=True,
            meta={
                "compiler": spec.compiler,
                "model": spec.model or "",
                "tool_schema_hash": spec.tool_schema_hash or "",
                "degraded": str(spec.compiler != "qwen").lower(),
                "degraded_reason": spec.degraded_reason or "",
            },
        ),
    ]
    engine = DeterministicReplayEngine()
    traces: list[ReplayTrace] = []
    reject_reason: ReasonCode | None = baseline_receipt_error
    if effective_edit_provenance.diff_hash != expected_edit_diff_hash:
        reject_reason = ReasonCode.RECEIPT_BINDING_FAILED
    try:
        if reject_reason is None:
            for scenario in suite.scenarios:
                traces.append(engine.replay(package=baseline_dir, scenario=scenario, role="baseline"))
                traces.append(engine.replay(package=candidate_dir, scenario=scenario, role="candidate"))
    except ReplayEngineError as exc:
        reject_reason = exc.reason_code

    coverage_cells: list[tuple[str, str]] = []
    missing: list[str] = []
    baseline_probe_assertions: list[Assertion] = []
    candidate_probe_assertions: list[Assertion] = []
    if reject_reason is None:
        proofs.append(
            simple_proof(
                kind=ProofKind.REPLAY,
                phase="run",
                inputs={"suite": suite.suite_id, "baseline": baseline_hash, "candidate": candidate_hash},
                artifact=[trace.model_dump(mode="json") for trace in traces],
                verdict_bearing=True,
            )
        )
        wellformed_assertions = _wellformed_assertions(traces)
        proofs.append(
            simple_proof(
                kind=ProofKind.REPLAY_WELLFORMED,
                phase="run",
                inputs={"trace_hashes": [trace.artifact_hash for trace in traces]},
                artifact={"assertions": wellformed_assertions},
                verdict_bearing=True,
                assertions=wellformed_assertions,
            )
        )
        trace_map = {(trace.scenario_id, trace.role): trace for trace in traces}
        for scenario in suite.scenarios:
            if reject_reason is not None:
                break
            baseline_trace = trace_map[(scenario.id, "baseline")]
            candidate_trace = trace_map[(scenario.id, "candidate")]
            for probe_spec in spec.probes:
                if probe_spec.block:
                    coverage_cells.append((scenario.id, probe_spec.id))
                probe = PROBE_REGISTRY.get(probe_spec.type)
                if probe is None:
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                    continue
                if not probe.__class__.__module__.startswith("redline.probes."):
                    reject_reason = ReasonCode.VERDICT_PATH_VIOLATION
                    missing.append(f"{scenario.id}:{probe_spec.id}:untrusted_probe")
                    break
                try:
                    with verdict_path_tripwire():
                        baseline_result = probe.evaluate(baseline=baseline_trace, candidate=baseline_trace, params=probe_spec.params)
                        candidate_result = probe.evaluate(baseline=baseline_trace, candidate=candidate_trace, params=probe_spec.params)
                except VerdictPathViolation:
                    reject_reason = ReasonCode.VERDICT_PATH_VIOLATION
                    missing.append(f"{scenario.id}:{probe_spec.id}:verdict_path_violation")
                    break
                except Exception:
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                    continue
                if probe_spec.block and (baseline_result.outcome == ProbeOutcome.ERRORED or candidate_result.outcome == ProbeOutcome.ERRORED):
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                if probe_spec.block and any(not assertion.holds for assertion in baseline_result.assertions):
                    reject_reason = ReasonCode.BASELINE_BREACHES
                    missing.append(f"{scenario.id}:{probe_spec.id}:baseline_breach")
                    break
                if probe_spec.block:
                    baseline_probe_assertions.extend(baseline_result.assertions)
                    candidate_probe_assertions.extend(candidate_result.assertions)
                proofs.append(
                    simple_proof(
                        kind=ProofKind.PROBE,
                        phase="probe",
                        inputs={"scenario": scenario.id, "probe": probe_spec.id},
                        artifact={"baseline": baseline_result, "candidate": candidate_result},
                        verdict_bearing=probe_spec.block,
                        assertions=candidate_result.assertions,
                        meta={"scenario_id": scenario.id, "probe_id": probe_spec.id},
                    )
                )
        if reject_reason is None:
            coverage = CoverageManifest(cells=coverage_cells, complete=not missing, missing=missing)
            proofs.append(
                simple_proof(
                    kind=ProofKind.COVERAGE,
                    phase="decide",
                    inputs={"suite": suite.suite_id, "spec": spec.spec_id},
                    artifact=coverage,
                    verdict_bearing=True,
                )
            )
            proofs.append(
                simple_proof(
                    kind=ProofKind.BASELINE_CALIBRATION,
                    phase="calibrate",
                    inputs={"baseline_hash": baseline_hash, "suite": suite.suite_id},
                    artifact={"baseline": baseline_hash, "suite": suite.suite_id},
                    verdict_bearing=True,
                    assertions=baseline_probe_assertions,
                )
            )
            candidate_absolute = _candidate_absolute_assertions(candidate_probe_assertions)
            proofs.append(
                simple_proof(
                    kind=ProofKind.CANDIDATE_ABSOLUTE,
                    phase="probe",
                    inputs={"candidate_hash": candidate_hash},
                    artifact={"assertions": candidate_absolute},
                    verdict_bearing=True,
                    assertions=candidate_absolute,
                )
            )
        else:
            coverage = CoverageManifest(
                cells=coverage_cells,
                complete=False,
                missing=sorted(set([reject_reason.value, *missing])),
            )
    else:
        coverage = CoverageManifest(cells=[], complete=False, missing=[reject_reason.value])

    envelope = decide(
        proofs=proofs,
        required=REQUIRED_PROOFS,
        coverage=coverage,
        context=DecisionContext(suite_id=suite.suite_id, spec_hash=spec_hash, chain_status=chain_status, reject_reason=reject_reason),
    )
    qwen_degraded_reason = spec.degraded_reason or ("qwen_not_used" if spec.compiler != "qwen" else None)
    envelope = envelope.model_copy(
        update={
            "capabilities": envelope.capabilities.model_copy(
                update={"qwen_compile": Capability(mode=spec.compiler, degraded=spec.compiler != "qwen", reason=qwen_degraded_reason)}
            )
        }
    )
    engine_hash = hash_tree(Path(__file__).resolve().parent / "engine_adapter")
    receipt = issue_receipt(
        envelope=envelope,
        proofs=proofs,
        coverage=coverage,
        package_hash=package_hash,
        baseline_name=baseline,
        baseline_hash=baseline_hash,
        baseline_receipt_hash=baseline_receipt_hash,
        baseline_version_id=baseline_version_id or f"fixture:{baseline}",
        candidate_name=candidate,
        candidate_hash=candidate_hash,
        candidate_version_id=candidate_version_id or f"fixture:{candidate}",
        spec_hash=spec_hash,
        spec_source_path=_portable_path(spec_path),
        spec_compiler=spec.compiler,
        spec_model=spec.model,
        spec_tool_schema_hash=spec.tool_schema_hash,
        spec_degraded_reason=spec.degraded_reason,
        suite_id=suite.suite_id,
        scenario_ids=[scenario.id for scenario in suite.scenarios],
        suite_lock_hash=suite.suite_lock_hash or hash_obj(suite),
        suite_source_path=_portable_path(suite_path),
        engine_source_tree_hash=engine_hash,
        runner_lock_hash=hash_obj({"engine": "deterministic", "engine_hash": engine_hash}),
        edit_provenance=effective_edit_provenance,
        **proof_reproduce_kwargs,
    )
    if receipt is None:
        decision_proof = make_decision_proof(envelope=envelope, proofs=proofs, **proof_reproduce_kwargs)
        if decision_proof.proof_id not in {proof.proof_id for proof in proofs}:
            proofs.append(decision_proof)
    report_json = to_report(envelope=envelope, receipt=receipt, traces=traces)
    if receipt is not None:
        receipt = receipt.model_copy(update={"report": receipt.report.model_copy(update={"report_hash": report_json["report_hash"]})})
        receipt = receipt.model_copy(update={"receipt_hash": ""})
        from redline.receipt import compute_receipt_hash

        receipt = receipt.model_copy(update={"receipt_hash": compute_receipt_hash(receipt)})
        report_json = to_report(envelope=envelope, receipt=receipt, traces=traces)
    artifacts = RunArtifacts(envelope=envelope, receipt=receipt, proofs=proofs, traces=traces, report_json=report_json, out_dir=out_dir)
    if out_dir is not None:
        write_artifacts(artifacts, out_dir=out_dir, ledger_written_at=ledger_written_at, ledger_path_label=ledger_path_label)
    return artifacts


def write_artifacts(artifacts: RunArtifacts, *, out_dir: Path, ledger_written_at: str | None = None, ledger_path_label: str | None = None) -> None:
    if artifacts.receipt is not None:
        assert_no_issuance_conflict(out_dir / "issuance-ledger.jsonl", artifacts.receipt)
    _clear_artifacts_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "envelope.json").write_text(artifacts.envelope.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(artifacts.report_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    proofs_dir = out_dir / "proofs"
    proofs_dir.mkdir(exist_ok=True)
    proofs = artifacts.receipt.proofs if artifacts.receipt is not None else artifacts.proofs
    for proof in proofs:
        (proofs_dir / f"{proof.proof_id.replace(':', '_')}.json").write_text(proof.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if artifacts.receipt is not None:
        atomic_write_receipt(
            out_dir / "receipt.json",
            artifacts.receipt,
            ledger_path=out_dir / "issuance-ledger.jsonl",
            checkpoint_path=out_dir / "issuance-ledger.checkpoint.json",
            ledger_written_at=ledger_written_at,
            ledger_path_label=ledger_path_label,
        )


def _clear_artifacts_dir(out_dir: Path) -> None:
    if not out_dir.exists():
        return
    for name in [
        "envelope.json",
        "report.json",
        "receipt.json",
        "issuance-ledger.attestation.json",
    ]:
        path = out_dir / name
        if path.exists():
            path.unlink()
    proofs_dir = out_dir / "proofs"
    if proofs_dir.exists():
        for proof_path in proofs_dir.glob("*.json"):
            proof_path.unlink()


def _simple_proof(
    *,
    kind: ProofKind,
    phase: str,
    inputs: object,
    artifact: object,
    verdict_bearing: bool,
    assertions: list[Assertion] | None = None,
    meta: dict[str, object] | None = None,
    include_baseline_receipt: bool = False,
    include_trust_policy: bool = False,
) -> Proof:
    inputs_hash = hash_obj(inputs)
    artifact_hash = hash_obj(artifact)
    proof_id = f"proof:{kind.value}:{artifact_hash.removeprefix('sha256:')[:24]}"
    return Proof(
        proof_id=proof_id,
        phase=phase,
        kind=kind,
        verdict_bearing=verdict_bearing,
        inputs_hash=inputs_hash,
        artifact_hash=artifact_hash,
        assertions=assertions or [],
        meta=meta or {},
        reproduce=make_verify_proof_reproduce(
            proof_id=proof_id,
            include_baseline_receipt=include_baseline_receipt,
            include_trust_policy=include_trust_policy,
        ),
    )


def _wellformed_assertions(traces: list[ReplayTrace]) -> list[Assertion]:
    assertions: list[Assertion] = []
    for trace in traces:
        holds = trace.bars == len(trace.points) and trace.bars > 0
        assertions.append(
            Assertion(
                metric="replay_wellformed",
                op="==",
                threshold=str(trace.bars),
                observed=str(len(trace.points)),
                scenario_id=trace.scenario_id,
                bar=trace.points[-1].bar if trace.points else 0,
                holds=holds,
            )
        )
    return assertions


def _candidate_absolute_assertions(assertions: list[Assertion]) -> list[Assertion]:
    return [assertion for assertion in assertions if assertion.metric in {"max_drawdown", "trade_budget"}]


def parse_run_inputs(package_dir: Path, suite_path: Path, spec_path: Path) -> tuple[Path, Path, Path]:
    try:
        load_suite(suite_path)
        load_spec(spec_path)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(str(exc)) from exc
    if not package_dir.exists():
        raise ValueError(f"package not found: {package_dir}")
    return package_dir, suite_path, spec_path


def _baseline_chain(
    *,
    baseline_hash: str,
    baseline_receipt_path: Path | None,
    baseline_trust_policy_path: Path | None,
) -> tuple[ChainStatus, str | None, ReasonCode | None]:
    if baseline_receipt_path is None:
        return ChainStatus.GENESIS, None, None
    try:
        from redline.receipt import compute_receipt_hash

        receipt = Receipt.model_validate(json.loads(baseline_receipt_path.read_text(encoding="utf-8")))
    except Exception:
        return ChainStatus.UNCHAINED, None, ReasonCode.BASELINE_UNCHAINED
    if compute_receipt_hash(receipt) != receipt.receipt_hash:
        return ChainStatus.UNCHAINED, None, ReasonCode.BASELINE_UNCHAINED
    if receipt.result.status != Status.PASS.value:
        return ChainStatus.UNCHAINED, receipt.receipt_hash, ReasonCode.BASELINE_UNCHAINED
    if receipt.candidate.package_hash != baseline_hash:
        return ChainStatus.UNCHAINED, receipt.receipt_hash, ReasonCode.BASELINE_UNCHAINED
    if baseline_trust_policy_path is None or not _baseline_receipt_trusted(
        receipt=receipt,
        receipt_path=baseline_receipt_path,
        trust_policy_path=baseline_trust_policy_path,
    ):
        return ChainStatus.UNCHAINED, receipt.receipt_hash, ReasonCode.BASELINE_UNCHAINED
    return ChainStatus.CHAINED, receipt.receipt_hash, None


def _baseline_receipt_trusted(*, receipt: Receipt, receipt_path: Path, trust_policy_path: Path) -> bool:
    ledger_path = receipt_path.parent / "issuance-ledger.jsonl"
    checkpoint_path = receipt_path.parent / "issuance-ledger.checkpoint.json"
    attestation_path = receipt_path.parent / "issuance-ledger.attestation.json"
    if not ledger_path.exists() or not checkpoint_path.exists() or not attestation_path.exists():
        return False
    try:
        policy = TrustPolicy.model_validate(json.loads(trust_policy_path.read_text(encoding="utf-8")))
        checkpoint = LedgerCheckpoint.model_validate(json.loads(checkpoint_path.read_text(encoding="utf-8")))
        attestation = LedgerCheckpointAttestation.model_validate(json.loads(attestation_path.read_text(encoding="utf-8")))
    except Exception:
        return False
    key_hash = hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )
    matched = False
    previous_entry_hash = "sha256:genesis"
    entry_count = 0
    try:
        with ledger_path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry_count += 1
                entry = json.loads(line)
                entry_hash = entry.get("entry_hash")
                if not isinstance(entry_hash, str):
                    return False
                expected_entry_hash = hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
                if entry_hash != expected_entry_hash or entry.get("previous_entry_hash") != previous_entry_hash:
                    return False
                previous_entry_hash = entry_hash
                if entry.get("receipt_hash") == receipt.receipt_hash:
                    if entry.get("key_hash") != key_hash or entry.get("status") != receipt.result.status:
                        return False
                    matched = True
    except (OSError, json.JSONDecodeError):
        return False
    if not matched:
        return False
    expected_checkpoint_hash = hash_obj(checkpoint.model_copy(update={"checkpoint_hash": ""}))
    if checkpoint.checkpoint_hash != expected_checkpoint_hash:
        return False
    if checkpoint.ledger_hash != hash_file(ledger_path):
        return False
    if checkpoint.ledger_tail_hash != previous_entry_hash or checkpoint.ledger_entry_count != entry_count:
        return False
    if receipt.receipt_hash not in checkpoint.subject_receipt_hashes:
        return False
    try:
        return verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy=policy)
    except ValueError:
        return False


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(resolved)
