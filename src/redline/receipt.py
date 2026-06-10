from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from redline.canonical import hash_obj
from redline.models import (
    Assertion,
    BaselineInfo,
    CandidateInfo,
    CoverageManifest,
    DecisionEnvelope,
    EditProvenance,
    PackageInfo,
    Proof,
    ProofKind,
    Receipt,
    ReceiptDecision,
    ReportInfo,
    ResultInfo,
    RunnerInfo,
    SpecInfo,
    Status,
    SuiteInfo,
)
from redline.proof_kernel import decision_proof_id


def make_decision_proof(*, envelope: DecisionEnvelope, proofs: list[Proof]) -> Proof:
    proof_id = decision_proof_id(
        status=envelope.status,
        reason_code=envelope.reason_code,
        proof_ids=[proof.proof_id for proof in proofs],
        coverage=envelope.coverage,
    )
    return Proof(
        proof_id=proof_id,
        phase="decide",
        kind=ProofKind.DECISION,
        verdict_bearing=True,
        inputs_hash=hash_obj({"proof_ids": [proof.proof_id for proof in proofs], "coverage": envelope.coverage}),
        artifact_hash=hash_obj(envelope),
        assertions=[],
        reproduce=f"uv run redline check artifacts/receipt.json --proof-id {proof_id}",
    )


def compute_receipt_hash(receipt: Receipt) -> str:
    return hash_obj(receipt.model_copy(update={"receipt_hash": ""}))


def issue_receipt(
    *,
    envelope: DecisionEnvelope,
    proofs: list[Proof],
    coverage: CoverageManifest,
    package_hash: str,
    baseline_hash: str,
    candidate_hash: str,
    spec_hash: str,
    suite_id: str,
    scenario_ids: list[str],
    suite_lock_hash: str,
    engine_source_tree_hash: str,
    runner_lock_hash: str,
    report_hash: str = "sha256:pending",
) -> Receipt | None:
    if envelope.status not in {Status.PASS, Status.WITHHELD}:
        return None
    all_proofs = [*proofs]
    decision_proof = make_decision_proof(envelope=envelope, proofs=proofs)
    if decision_proof.proof_id not in {proof.proof_id for proof in all_proofs}:
        all_proofs.append(decision_proof)
    breaches: list[Assertion] = [
        assertion for proof in all_proofs if proof.kind == ProofKind.PROBE for assertion in proof.assertions if not assertion.holds
    ]
    result_status = "pass" if envelope.status == Status.PASS else "withheld"
    receipt = Receipt(
        package=PackageInfo(identity_hash=package_hash, manifest_hash=package_hash),
        edit_provenance=EditProvenance(
            prompt_digest=hash_obj({"prompt": "fixture make it more responsive"}),
            diff_hash=hash_obj({"baseline": baseline_hash, "candidate": candidate_hash}),
            captured_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        ),
        baseline=BaselineInfo(package_hash=baseline_hash, chain_status=envelope.chain_status),
        candidate=CandidateInfo(package_hash=candidate_hash),
        spec=SpecInfo(spec_hash=spec_hash),
        suite=SuiteInfo(suite_id=suite_id, scenarios=scenario_ids, suite_lock_hash=suite_lock_hash),
        runner=RunnerInfo(
            engine_source_tree_hash=engine_source_tree_hash,
            runner_lock_hash=runner_lock_hash,
        ),
        result=ResultInfo(status=result_status, new_breaches=breaches, result_hash=hash_obj({"status": result_status, "breaches": breaches})),
        coverage=coverage,
        decision=ReceiptDecision(
            reason_code=envelope.reason_code,
            required_proof_ids=envelope.required_proof_ids,
            satisfied_proof_ids=envelope.satisfied_proof_ids,
        ),
        proofs=all_proofs,
        capabilities=envelope.capabilities,
        strength_summary=_strength_summary(all_proofs, len(scenario_ids)),
        report=ReportInfo(report_hash=report_hash),
        receipt_hash="",
    )
    receipt = receipt.model_copy(update={"receipt_hash": compute_receipt_hash(receipt)})
    return receipt


def atomic_write_receipt(path: Path, receipt: Receipt, *, ledger_path: Path | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = receipt.model_dump_json(indent=2)
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(data)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    if ledger_path is not None:
        _append_ledger(ledger_path, receipt)


def _append_ledger(path: Path, receipt: Receipt) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = {
        "package_hash": receipt.package.identity_hash,
        "candidate_hash": receipt.candidate.package_hash,
        "suite_lock_hash": receipt.suite.suite_lock_hash,
        "spec_hash": receipt.spec.spec_hash,
    }
    entry = {
        "key_hash": hash_obj(key),
        "status": receipt.result.status,
        "receipt_hash": receipt.receipt_hash,
        "written_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True))
        fh.write("\n")


def _strength_summary(proofs: list[Proof], scenario_count: int) -> str:
    items: list[str] = []
    for proof in proofs:
        for assertion in proof.assertions:
            items.append(f"{assertion.metric} {assertion.op} {assertion.threshold} observed {assertion.observed}")
    return f"tested: {'; '.join(sorted(set(items)))}; {scenario_count} anchored scenarios"
