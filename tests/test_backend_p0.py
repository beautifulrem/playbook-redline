from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

from redline.canonical import CanonicalizationError, canonical_number, hash_obj
from redline.engine_adapter import DeterministicReplayEngine
from redline.models import (
    CoverageManifest,
    DecisionContext,
    ProbeOutcome,
    ProbeResult,
    ProbeType,
    ProofKind,
    ReasonCode,
    Receipt,
    ReplayTrace,
    Status,
    VerificationLevel,
    VerificationStatus,
)
from redline.probes import PROBE_REGISTRY
from redline.proof_kernel import REQUIRED_PROOFS, decide
from redline.receipt import compute_receipt_hash
from redline.runner import load_suite, run_redline
from redline.verifier import verify, verify_proof

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"


def test_required_proofs_covers_all_statuses() -> None:
    assert set(REQUIRED_PROOFS) == set(Status)
    assert ProofKind.DECISION in REQUIRED_PROOFS[Status.PASS]
    assert ProofKind.DECISION in REQUIRED_PROOFS[Status.WITHHELD]


def test_canonical_number_vectors_and_float_rejection() -> None:
    assert canonical_number(Decimal("0.30000000000000004")) == "0.30000000"
    assert canonical_number(Decimal("-0.0")) == "0"
    assert canonical_number(Decimal("1e-9")) == "0"
    assert canonical_number(Decimal("1.234567885")) == "1.23456788"
    try:
        hash_obj({"raw": 0.1})
    except CanonicalizationError:
        pass
    else:
        raise AssertionError("raw floats must be rejected")


def test_bad_candidate_withheld_and_good_candidate_pass(tmp_path: Path) -> None:
    bad = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "bad")
    assert bad.envelope.status == Status.WITHHELD
    assert bad.envelope.reason_code == ReasonCode.NEW_BLOCK_BREACH
    assert bad.receipt is not None
    bad_verify = verify(receipt_path=tmp_path / "bad" / "receipt.json", level=VerificationLevel.HASH_ONLY)
    assert bad_verify.status == VerificationStatus.VERIFIED
    assert bad_verify.reason_code == ReasonCode.NEW_BLOCK_BREACH
    good = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "good")
    assert good.envelope.status == Status.PASS
    assert good.receipt is not None


def test_receipt_tamper_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.VERIFIED
    data = json.loads(receipt_path.read_text())
    data["strength_summary"] = "tampered"
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_package_binding_rejects_mismatch(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    other_package = tmp_path / "other_package"
    other_package.mkdir()
    (other_package / "marker.txt").write_text("different", encoding="utf-8")
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=other_package, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED


def test_missing_required_proof_is_unverified(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text())
    data["proofs"] = [proof for proof in data["proofs"] if proof["kind"] != "coverage"]
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.UNVERIFIED_NO_VERDICT
    assert result.reason_code == ReasonCode.UNVERIFIED_NO_VERDICT


def test_partial_coverage_never_passes() -> None:
    coverage = CoverageManifest(cells=[("scenario", "probe")], complete=False, missing=["scenario:probe"])
    envelope = decide(proofs=[], coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x"))
    assert envelope.status == Status.UNVERIFIED_NO_VERDICT
    assert envelope.reason_code == ReasonCode.COVERAGE_INCOMPLETE


def test_sandbox_network_violation_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_malicious", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_verdict_path_network_violation_rejects(monkeypatch, tmp_path: Path) -> None:
    class NetworkProbe:
        def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
            import socket

            socket.socket()
            return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[])

    monkeypatch.setitem(PROBE_REGISTRY, ProbeType.MAX_DRAWDOWN, NetworkProbe())
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.VERDICT_PATH_VIOLATION
    assert artifacts.receipt is None


def test_replay_hash_is_stable() -> None:
    suite = load_suite(SUITE)
    engine = DeterministicReplayEngine()
    scenario = suite.scenarios[0]
    first = engine.replay(package=PACKAGE / "candidate_good", scenario=scenario, role="candidate")
    hashes = {engine.replay(package=PACKAGE / "candidate_good", scenario=scenario, role="candidate").artifact_hash for _ in range(10)}
    assert hashes == {first.artifact_hash}


def test_verify_proof_finds_proof(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    proof_id = artifacts.receipt.proofs[0].proof_id
    result = verify_proof(receipt_path=tmp_path / "receipt.json", proof_id=proof_id)
    assert result.status == "proof_replayed"
