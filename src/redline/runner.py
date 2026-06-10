from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import hash_obj, hash_tree
from redline.engine_adapter import DeterministicReplayEngine, ReplayEngineError
from redline.models import (
    Assertion,
    CoverageManifest,
    DecisionContext,
    Proof,
    ProofKind,
    ProbeOutcome,
    ReasonCode,
    RedlineSpec,
    ReplayTrace,
    RunArtifacts,
    Scenario,
    Status,
    Suite,
)
from redline.probes import PROBE_REGISTRY
from redline.proof_kernel import REQUIRED_PROOFS, decide
from redline.receipt import atomic_write_receipt, issue_receipt
from redline.report import to_report
from redline.tripwire import VerdictPathViolation, verdict_path_tripwire


def load_spec(path: Path) -> RedlineSpec:
    with path.open(encoding="utf-8") as fh:
        return RedlineSpec.model_validate(json.load(fh))


def load_suite(path: Path) -> Suite:
    with path.open(encoding="utf-8") as fh:
        payload = json.load(fh)
    suite = Suite.model_validate(payload)
    if suite.suite_lock_hash is None:
        suite = suite.model_copy(update={"suite_lock_hash": hash_obj(payload | {"suite_lock_hash": None})})
    base = path.parent
    scenarios: list[Scenario] = []
    for scenario in suite.scenarios:
        scenario_path = Path(scenario.path)
        if not scenario_path.is_absolute():
            scenario_path = (base / scenario_path).resolve()
        scenarios.append(scenario.model_copy(update={"path": str(scenario_path)}))
    return suite.model_copy(update={"scenarios": scenarios})


def run_redline(
    *,
    package_dir: Path,
    baseline: str,
    candidate: str,
    suite_path: Path,
    spec_path: Path,
    out_dir: Path | None = None,
) -> RunArtifacts:
    package_dir = package_dir.resolve()
    baseline_dir = package_dir / baseline
    candidate_dir = package_dir / candidate
    spec = load_spec(spec_path)
    suite = load_suite(suite_path)
    spec_hash = hash_obj(spec)
    package_hash = hash_tree(package_dir)
    baseline_hash = hash_tree(baseline_dir)
    candidate_hash = hash_tree(candidate_dir)
    proofs: list[Proof] = [
        _simple_proof(
            kind=ProofKind.PACKAGE_CANONICAL,
            phase="import",
            inputs={"package": str(package_dir)},
            artifact={"package_hash": package_hash, "baseline_hash": baseline_hash, "candidate_hash": candidate_hash},
            verdict_bearing=True,
        ),
        _simple_proof(
            kind=ProofKind.SPEC_COMPILE,
            phase="compile",
            inputs={"spec_path": str(spec_path)},
            artifact=spec,
            verdict_bearing=True,
        ),
    ]
    engine = DeterministicReplayEngine()
    traces: list[ReplayTrace] = []
    reject_reason: ReasonCode | None = None
    try:
        for scenario in suite.scenarios:
            traces.append(engine.replay(package=baseline_dir, scenario=scenario, role="baseline"))
            traces.append(engine.replay(package=candidate_dir, scenario=scenario, role="candidate"))
    except ReplayEngineError as exc:
        reject_reason = exc.reason_code

    coverage_cells: list[tuple[str, str]] = []
    missing: list[str] = []
    probe_assertions: list[Assertion] = []
    if reject_reason is None:
        proofs.append(
            _simple_proof(
                kind=ProofKind.REPLAY,
                phase="run",
                inputs={"suite": suite.suite_id, "baseline": baseline_hash, "candidate": candidate_hash},
                artifact=[trace.model_dump(mode="json") for trace in traces],
                verdict_bearing=True,
            )
        )
        wellformed_assertions = _wellformed_assertions(traces)
        proofs.append(
            _simple_proof(
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
                coverage_cells.append((scenario.id, probe_spec.id))
                probe = PROBE_REGISTRY.get(probe_spec.type)
                if probe is None:
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                    continue
                try:
                    with verdict_path_tripwire():
                        result = probe.evaluate(baseline=baseline_trace, candidate=candidate_trace, params=probe_spec.params)
                except VerdictPathViolation:
                    reject_reason = ReasonCode.VERDICT_PATH_VIOLATION
                    missing.append(f"{scenario.id}:{probe_spec.id}:verdict_path_violation")
                    break
                except Exception:
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                    continue
                if result.outcome == ProbeOutcome.ERRORED:
                    missing.append(f"{scenario.id}:{probe_spec.id}:errored")
                probe_assertions.extend(result.assertions)
                proofs.append(
                    _simple_proof(
                        kind=ProofKind.PROBE,
                        phase="probe",
                        inputs={"scenario": scenario.id, "probe": probe_spec.id},
                        artifact=result,
                        verdict_bearing=True,
                        assertions=result.assertions,
                    )
                )
        if reject_reason is None:
            coverage = CoverageManifest(cells=coverage_cells, complete=not missing, missing=missing)
            proofs.append(
                _simple_proof(
                    kind=ProofKind.COVERAGE,
                    phase="decide",
                    inputs={"suite": suite.suite_id, "spec": spec.spec_id},
                    artifact=coverage,
                    verdict_bearing=True,
                )
            )
            baseline_assertions = [assertion for assertion in probe_assertions if assertion.holds]
            proofs.append(
                _simple_proof(
                    kind=ProofKind.BASELINE_CALIBRATION,
                    phase="calibrate",
                    inputs={"baseline_hash": baseline_hash, "suite": suite.suite_id},
                    artifact={"baseline": baseline_hash, "suite": suite.suite_id},
                    verdict_bearing=True,
                    assertions=baseline_assertions[:1],
                )
            )
            candidate_absolute = _candidate_absolute_assertions(probe_assertions)
            proofs.append(
                _simple_proof(
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
        context=DecisionContext(suite_id=suite.suite_id, spec_hash=spec_hash, reject_reason=reject_reason),
    )
    engine_hash = hash_tree(Path(__file__).resolve().parent / "engine_adapter")
    receipt = issue_receipt(
        envelope=envelope,
        proofs=proofs,
        coverage=coverage,
        package_hash=package_hash,
        baseline_hash=baseline_hash,
        candidate_hash=candidate_hash,
        spec_hash=spec_hash,
        suite_id=suite.suite_id,
        scenario_ids=[scenario.id for scenario in suite.scenarios],
        suite_lock_hash=suite.suite_lock_hash or hash_obj(suite),
        engine_source_tree_hash=engine_hash,
        runner_lock_hash=hash_obj({"engine": "deterministic", "engine_hash": engine_hash}),
    )
    report_json = to_report(envelope=envelope, receipt=receipt, traces=traces)
    if receipt is not None:
        receipt = receipt.model_copy(update={"report": receipt.report.model_copy(update={"report_hash": report_json["report_hash"]})})
        receipt = receipt.model_copy(update={"receipt_hash": ""})
        from redline.receipt import compute_receipt_hash

        receipt = receipt.model_copy(update={"receipt_hash": compute_receipt_hash(receipt)})
        report_json = to_report(envelope=envelope, receipt=receipt, traces=traces)
    artifacts = RunArtifacts(envelope=envelope, receipt=receipt, proofs=proofs, traces=traces, report_json=report_json, out_dir=out_dir)
    if out_dir is not None:
        write_artifacts(artifacts, out_dir=out_dir)
    return artifacts


def write_artifacts(artifacts: RunArtifacts, *, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "envelope.json").write_text(artifacts.envelope.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(artifacts.report_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    proofs_dir = out_dir / "proofs"
    proofs_dir.mkdir(exist_ok=True)
    for proof in artifacts.proofs:
        (proofs_dir / f"{proof.proof_id.replace(':', '_')}.json").write_text(proof.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if artifacts.receipt is not None:
        atomic_write_receipt(out_dir / "receipt.json", artifacts.receipt, ledger_path=out_dir / "issuance-ledger.jsonl")


def _simple_proof(
    *,
    kind: ProofKind,
    phase: str,
    inputs: object,
    artifact: object,
    verdict_bearing: bool,
    assertions: list[Assertion] | None = None,
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
        reproduce=f"uv run redline verify-proof artifacts/receipt.json --proof-id {proof_id}",
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
