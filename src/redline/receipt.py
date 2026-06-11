from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from redline.canonical import hash_file, hash_obj
from redline.models import (
    Assertion,
    BaselineInfo,
    CandidateInfo,
    CoverageManifest,
    DecisionEnvelope,
    EditProvenance,
    LedgerCheckpoint,
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


class IssuanceLedgerConflict(RuntimeError):
    pass


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
        reproduce=f"uv run redline verify-proof receipt.json --proof-id {proof_id} --package <package> --suite <suite> --spec <spec>",
    )


def compute_receipt_hash(receipt: Receipt) -> str:
    return hash_obj(receipt.model_copy(update={"receipt_hash": ""}))


def issue_receipt(
    *,
    envelope: DecisionEnvelope,
    proofs: list[Proof],
    coverage: CoverageManifest,
    package_hash: str,
    baseline_name: str,
    baseline_hash: str,
    baseline_receipt_hash: str | None = None,
    baseline_version_id: str = "fixture:baseline",
    candidate_name: str,
    candidate_hash: str,
    candidate_version_id: str = "fixture:candidate",
    spec_hash: str,
    spec_source_path: str,
    spec_compiler: str = "json",
    spec_model: str | None = None,
    spec_tool_schema_hash: str | None = None,
    spec_degraded_reason: str | None = None,
    suite_id: str,
    scenario_ids: list[str],
    suite_lock_hash: str,
    suite_source_path: str,
    engine_source_tree_hash: str,
    runner_lock_hash: str,
    report_hash: str = "sha256:pending",
    edit_provenance: EditProvenance | None = None,
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
        edit_provenance=edit_provenance
        or EditProvenance(
            prompt_digest=hash_obj({"prompt": "fixture make it more responsive"}),
            diff_hash=hash_obj({"baseline": baseline_hash, "candidate": candidate_hash}),
            captured_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        ),
        baseline=BaselineInfo(
            package_hash=baseline_hash,
            baseline_receipt_hash=baseline_receipt_hash,
            baseline_version_id=baseline_version_id,
            package_name=baseline_name,
            chain_status=envelope.chain_status,
        ),
        candidate=CandidateInfo(
            package_hash=candidate_hash,
            candidate_version_id=candidate_version_id,
            package_name=candidate_name,
        ),
        spec=SpecInfo(
            spec_hash=spec_hash,
            source_path=spec_source_path,
            compiler=spec_compiler,
            model=spec_model,
            tool_schema_hash=spec_tool_schema_hash,
            degraded_reason=spec_degraded_reason,
        ),
        suite=SuiteInfo(suite_id=suite_id, scenarios=scenario_ids, suite_lock_hash=suite_lock_hash, source_path=suite_source_path),
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


def atomic_write_receipt(
    path: Path,
    receipt: Receipt,
    *,
    ledger_path: Path | None = None,
    checkpoint_path: Path | None = None,
    ledger_written_at: str | None = None,
    ledger_path_label: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if ledger_path is not None:
        assert_no_issuance_conflict(ledger_path, receipt)
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = receipt.model_dump_json(indent=2)
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(data)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    if ledger_path is not None:
        try:
            _append_ledger(ledger_path, receipt, written_at=ledger_written_at)
            create_ledger_checkpoint(
                ledger_path=ledger_path,
                checkpoint_path=checkpoint_path,
                subject_receipt_hashes=[receipt.receipt_hash],
                ledger_path_label=ledger_path_label,
            )
        except Exception:
            path.unlink(missing_ok=True)
            raise


def create_ledger_checkpoint(
    *,
    ledger_path: Path,
    checkpoint_path: Path | None = None,
    subject_receipt_hashes: list[str] | None = None,
    anchor_kind: Literal["local-artifact", "external-trust-root"] = "local-artifact",
    ledger_path_label: str | None = None,
) -> LedgerCheckpoint:
    entries = _read_ledger_entries(ledger_path)
    ledger_tail_hash = entries[-1]["entry_hash"] if entries else "sha256:genesis"
    ledger_receipt_hashes = [entry["receipt_hash"] for entry in entries if isinstance(entry.get("receipt_hash"), str)]
    checkpoint = LedgerCheckpoint(
        ledger_path=ledger_path_label or str(ledger_path),
        ledger_hash=hash_file(ledger_path),
        ledger_tail_hash=ledger_tail_hash,
        ledger_entry_count=len(entries),
        subject_receipt_hashes=sorted(set([*(subject_receipt_hashes or []), *ledger_receipt_hashes])),
        anchor_kind=anchor_kind,
        checkpoint_hash="",
    )
    checkpoint = checkpoint.model_copy(update={"checkpoint_hash": hash_obj(checkpoint)})
    if checkpoint_path is not None:
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.write_text(checkpoint.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return checkpoint


def assert_no_issuance_conflict(ledger_path: Path, receipt: Receipt) -> None:
    _raise_on_ledger_conflict(ledger_path, receipt)


def _append_ledger(path: Path, receipt: Receipt, *, written_at: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_entry_hash = _last_ledger_entry_hash(path)
    entry = {
        "key_hash": _ledger_key_hash(receipt),
        "status": receipt.result.status,
        "receipt_hash": receipt.receipt_hash,
        "previous_entry_hash": previous_entry_hash,
        "written_at": written_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    entry["entry_hash"] = hash_obj(entry)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True))
        fh.write("\n")


def _raise_on_ledger_conflict(path: Path, receipt: Receipt) -> None:
    if not path.exists():
        return
    key_hash = _ledger_key_hash(receipt)
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IssuanceLedgerConflict("issuance ledger is not valid JSONL") from exc
            if entry.get("key_hash") == key_hash:
                raise IssuanceLedgerConflict(
                    f"anti-reroll conflict for {key_hash}: historical={entry.get('status')} new={receipt.result.status}"
                )


def _ledger_key_hash(receipt: Receipt) -> str:
    return hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )


def _last_ledger_entry_hash(path: Path) -> str:
    previous = "sha256:genesis"
    if not path.exists():
        return previous
    for entry in _read_ledger_entries(path):
        previous = entry["entry_hash"]
    return previous


def _read_ledger_entries(path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    previous_entry_hash = "sha256:genesis"
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            entry = json.loads(line)
            entry_hash = entry.get("entry_hash")
            if not isinstance(entry_hash, str):
                raise IssuanceLedgerConflict("issuance ledger entry is missing entry_hash")
            expected_entry_hash = hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
            if entry_hash != expected_entry_hash or entry.get("previous_entry_hash") != previous_entry_hash:
                raise IssuanceLedgerConflict("issuance ledger hash chain is invalid")
            previous_entry_hash = entry_hash
            entries.append(entry)
    return entries


def _strength_summary(proofs: list[Proof], scenario_count: int) -> str:
    items: list[str] = []
    for proof in proofs:
        for assertion in proof.assertions:
            items.append(f"{assertion.metric} {assertion.op} {assertion.threshold} observed {assertion.observed}")
    return f"tested: {'; '.join(sorted(set(items)))}; {scenario_count} anchored scenarios"
