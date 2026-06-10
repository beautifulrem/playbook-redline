from __future__ import annotations

import json
import shutil
from decimal import Decimal
from pathlib import Path

from redline.canonical import CanonicalizationError, canonical_number, hash_obj
from redline.engine_adapter import DeterministicReplayEngine
from redline.engine_adapter.deterministic import build_worker_command
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
from redline.receipt import IssuanceLedgerConflict, atomic_write_receipt, compute_receipt_hash
from redline.runner import load_suite, run_redline
from redline.schemas import export_schemas
from redline.sponsor.bitget import SponsorState, validate_sponsor_evidence_shape
from redline.mcp_server import redline_check_receipt
from redline.surfaces import capture_edit_provenance, compile_spec, import_package, publish_preflight, render_report_html
from redline.verifier import verify, verify_proof

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"


def test_required_proofs_covers_all_statuses() -> None:
    assert set(REQUIRED_PROOFS) == set(Status)
    assert ProofKind.DECISION in REQUIRED_PROOFS[Status.PASS]
    assert ProofKind.DECISION in REQUIRED_PROOFS[Status.WITHHELD]


def test_spec_and_suite_versions_are_locked(tmp_path: Path) -> None:
    spec_data = json.loads(SPEC.read_text())
    spec_data["version"] = "redline.spec.v999"
    bad_spec = tmp_path / "bad-spec.json"
    bad_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    try:
        compile_spec(bad_spec)
    except Exception:
        pass
    else:
        raise AssertionError("unsupported spec version must not validate")
    suite_data = json.loads(SUITE.read_text())
    suite_data["version"] = "redline.suite.v999"
    bad_suite = tmp_path / "bad-suite.json"
    bad_suite.write_text(json.dumps(suite_data), encoding="utf-8")
    try:
        load_suite(bad_suite)
    except Exception:
        pass
    else:
        raise AssertionError("unsupported suite version must not validate")


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
    assert bad_verify.status == VerificationStatus.UNVERIFIED_NO_VERDICT
    bad_replayed = verify(
        receipt_path=tmp_path / "bad" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )
    assert bad_replayed.status == VerificationStatus.VERIFIED
    assert bad_replayed.reason_code == ReasonCode.NEW_BLOCK_BREACH
    good = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "good")
    assert good.envelope.status == Status.PASS
    assert good.receipt is not None
    assert good.receipt.report.report_hash == good.report_json["report_hash"]
    assert good.report_json["proofs"]
    assert good.report_json["edit_provenance"]["diff_hash"] == good.receipt.edit_provenance.diff_hash


def test_suite_has_two_24_bar_scenarios_and_three_p0_probes() -> None:
    suite = load_suite(SUITE)
    spec = compile_spec(SPEC)
    assert len(suite.scenarios) == 2
    assert {probe.type for probe in spec.probes} == {ProbeType.MAX_DRAWDOWN, ProbeType.NO_ENTRY_WHEN, ProbeType.TRADE_BUDGET}
    for scenario in suite.scenarios:
        with Path(scenario.path).open(encoding="utf-8") as fh:
            assert len([line for line in fh if line.strip()]) == 25


def test_no_entry_when_probe_catches_early_crash_entry(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    failures = [
        assertion
        for proof in artifacts.receipt.proofs
        for assertion in proof.assertions
        if assertion.metric == "no_entry_when" and not assertion.holds
    ]
    assert failures
    assert failures[0].scenario_id == "btc-crash-2024-03-05"


def test_baseline_breach_rejects_without_receipt_but_keeps_decision_proof(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    (package / "baseline" / "config.json").write_text('{"entry_bar": 1, "exit_bar": 99, "leverage": "2.0"}\n', encoding="utf-8")
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.BASELINE_BREACHES
    assert artifacts.receipt is None
    decision_proofs = [proof for proof in artifacts.proofs if proof.kind == ProofKind.DECISION]
    assert len(decision_proofs) == 1
    assert (tmp_path / "run" / "proofs" / f"{decision_proofs[0].proof_id.replace(':', '_')}.json").exists()
    assert not (tmp_path / "run" / "receipt.json").exists()


def test_advisory_probe_does_not_block_verdict(tmp_path: Path) -> None:
    spec_data = json.loads(SPEC.read_text())
    for probe in spec_data["probes"]:
        if probe["type"] == "max_drawdown":
            probe["params"]["max_drawdown"] = "0.000001"
            probe["block"] = False
    advisory_spec = tmp_path / "advisory-spec.json"
    advisory_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=advisory_spec, out_dir=tmp_path / "run")
    assert artifacts.envelope.status == Status.PASS
    assert artifacts.receipt is not None


def test_receipt_tamper_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.UNVERIFIED_NO_VERDICT
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
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=other_package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED


def test_replayed_verification_reruns_package(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.VERIFIED
    assert result.verification_level == VerificationLevel.REPLAYED


def test_replayed_verification_rejects_recomputed_hash_with_stale_proofs(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "run" / "receipt.json"
    (package / "candidate_good" / "config.json").write_text('{"leverage": "8"}\n', encoding="utf-8")
    data = json.loads(receipt_path.read_text())
    from redline.canonical import hash_tree

    data["package"]["identity_hash"] = hash_tree(package)
    data["candidate"]["package_hash"] = hash_tree(package / "candidate_good")
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_hash_only_rejects_recomputed_hash_with_inconsistent_package_proof(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text())
    data["package"]["identity_hash"] = "sha256:" + "0" * 64
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_rejects_recomputed_hash_with_stale_report_hash(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "run" / "receipt.json"
    (tmp_path / "run" / "issuance-ledger.jsonl").unlink()
    data = json.loads(receipt_path.read_text())
    data["report"]["report_hash"] = "sha256:" + "0" * 64
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_rejects_missing_ledger(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    (tmp_path / "run" / "issuance-ledger.jsonl").unlink()
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_rejects_external_report_mismatch(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    report_path = tmp_path / "run" / "report.json"
    data = json.loads(report_path.read_text())
    data["report_hash"] = "sha256:" + "0" * 64
    report_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_rejects_external_report_content_forgery(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    report_path = tmp_path / "run" / "report.json"
    data = json.loads(report_path.read_text())
    data["receipt_hash"] = "sha256:" + "0" * 64
    data["proof_ids"] = []
    data["traces"] = []
    data["envelope"]["status"] = "withheld"
    report_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_requires_required_proof_sidecars(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    decision_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.DECISION)
    (tmp_path / "run" / "proofs" / f"{decision_id.replace(':', '_')}.json").unlink()
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_replayed_requires_all_proof_sidecars(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    probe_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.PROBE)
    (tmp_path / "run" / "proofs" / f"{probe_id.replace(':', '_')}.json").unlink()
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_receipt_version_is_locked(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text())
    data["version"] = "redline.receipt.v999"
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.REPLAYED, package=PACKAGE, suite_path=SUITE, spec_path=SPEC)
    assert result.status == VerificationStatus.BAD_INPUT
    assert result.reason_code == ReasonCode.VERSION_UNSUPPORTED


def test_replayed_rejects_legacy_or_forged_ledger_entry(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt = artifacts.receipt
    key_hash = hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )
    (tmp_path / "run" / "issuance-ledger.jsonl").write_text(
        json.dumps({"key_hash": key_hash, "status": receipt.result.status, "receipt_hash": receipt.receipt_hash}) + "\n",
        encoding="utf-8",
    )
    result = verify(receipt_path=tmp_path / "run" / "receipt.json", package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_duplicate_singleton_proof_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text())
    package_proof = next(proof for proof in data["proofs"] if proof["kind"] == "package_canonical")
    data["proofs"].append(package_proof)
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


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


def test_sandbox_file_escape_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_file_escape", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_read_root_bypass_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_read_bypass", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_lookahead_scenario_file_read_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_lookahead", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_fork_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_fork", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_os_open_write_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_os_open_write", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_ctypes_rejects(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_ctypes", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_environment_is_sanitized(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_SENTINEL", "do-not-leak")
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_env_leak", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.PASS
    assert artifacts.receipt is not None


def test_sandbox_virtualenv_is_not_visible_to_candidate(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_virtualenv_leak", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.PASS
    assert artifacts.receipt is not None


def test_sandbox_allows_stdlib_import(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_stdlib_import", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.PASS
    assert artifacts.receipt is not None


def test_candidate_cannot_forge_trusted_trace_from_worker_globals(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_forge_trace", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.WITHHELD
    assert artifacts.envelope.reason_code == ReasonCode.NEW_BLOCK_BREACH
    assert artifacts.receipt is not None


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


def test_verdict_path_llm_import_violation_rejects(monkeypatch, tmp_path: Path) -> None:
    class LlmProbe:
        def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
            __import__("openai")
            return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[])

    monkeypatch.setitem(PROBE_REGISTRY, ProbeType.MAX_DRAWDOWN, LlmProbe())
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.VERDICT_PATH_VIOLATION
    assert artifacts.receipt is None


def test_verdict_path_fork_violation_rejects(monkeypatch, tmp_path: Path) -> None:
    class ForkProbe:
        def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
            import os

            os.fork()
            return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[])

    monkeypatch.setitem(PROBE_REGISTRY, ProbeType.MAX_DRAWDOWN, ForkProbe())
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.VERDICT_PATH_VIOLATION
    assert artifacts.receipt is None


def test_verdict_path_ctypes_violation_rejects(monkeypatch, tmp_path: Path) -> None:
    class CtypesProbe:
        def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
            import ctypes

            ctypes.CDLL(None)
            return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[])

    monkeypatch.setitem(PROBE_REGISTRY, ProbeType.MAX_DRAWDOWN, CtypesProbe())
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


def test_worker_command_uses_macos_sandbox_when_available() -> None:
    cmd = build_worker_command(package=PACKAGE / "candidate_good", scenario_id="scenario", scenario_path=SUITE, role="candidate")
    if Path(cmd[0]).name == "sandbox-exec":
        profile = cmd[2]
        assert "deny network*" in profile
        assert "deny process-fork" in profile
        assert "deny file-write*" in profile
    else:
        assert "-m" in cmd
        assert "redline.engine_adapter.sandbox_worker" in cmd


def test_verify_proof_finds_proof(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    proof_id = artifacts.receipt.proofs[0].proof_id
    result = verify_proof(receipt_path=tmp_path / "receipt.json", proof_id=proof_id)
    assert result.status == "proof_verified"


def test_verify_proof_rejects_forged_receipt_proof(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text())
    package_proof = next(proof for proof in data["proofs"] if proof["kind"] == "package_canonical")
    package_proof["artifact_hash"] = "sha256:" + "0" * 64
    proof_path = tmp_path / "proofs" / f"{package_proof['proof_id'].replace(':', '_')}.json"
    proof_path.write_text(json.dumps(package_proof), encoding="utf-8")
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify_proof(receipt_path=receipt_path, proof_id=package_proof["proof_id"])
    assert result.status == "proof_mismatch"
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_verify_proof_replays_when_package_is_supplied(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    proof_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.REPLAY)
    result = verify_proof(receipt_path=tmp_path / "run" / "receipt.json", proof_id=proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert result.status == "proof_verified"
    (package / "candidate_good" / "config.json").write_text('{"entry_bar": 1, "exit_bar": 99, "leverage": "2.0"}\n', encoding="utf-8")
    mismatch = verify_proof(receipt_path=tmp_path / "run" / "receipt.json", proof_id=proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert mismatch.status == "proof_mismatch"
    assert mismatch.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_mcp_rerun_uses_default_suite_and_spec(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    result = redline_check_receipt(str(tmp_path / "receipt.json"), pkg_path=str(PACKAGE), rerun=True)
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert result["verification_level"] == VerificationLevel.REPLAYED.value


def test_import_compile_capture_edit_and_run_bind_provenance(tmp_path: Path) -> None:
    imported = import_package(PACKAGE)
    assert imported.identity_hash.startswith("sha256:")
    assert "candidate_good/strategy.py" in imported.files
    text_spec = tmp_path / "redline.txt"
    text_spec.write_text("Max drawdown <= 8%; no entry before bar 3; trade budget 20.", encoding="utf-8")
    compiled = compile_spec(text_spec)
    assert [probe.type for probe in compiled.probes] == [ProbeType.MAX_DRAWDOWN, ProbeType.NO_ENTRY_WHEN, ProbeType.TRADE_BUDGET]
    prompt_log = tmp_path / "prompt.txt"
    prompt_log.write_text("make the strategy more responsive", encoding="utf-8")
    provenance = capture_edit_provenance(tool="fixture-agent", prompt_log=prompt_log, baseline=PACKAGE / "baseline", candidate=PACKAGE / "candidate_good")
    artifacts = run_redline(
        package_dir=PACKAGE,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
        edit_provenance=provenance,
    )
    assert artifacts.receipt is not None
    assert artifacts.receipt.edit_provenance == provenance


def test_publish_preflight_writes_annotation_for_pass_and_blocks_withheld(tmp_path: Path) -> None:
    good = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "good")
    assert good.receipt is not None
    good_result = publish_preflight(
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-good",
    )
    assert good_result.ok is True
    assert (tmp_path / "publish-good" / "redline-annotation.json").exists()
    bad = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "bad")
    assert bad.receipt is not None
    bad_result = publish_preflight(
        receipt_path=tmp_path / "bad" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-bad",
    )
    assert bad_result.ok is False
    assert bad_result.state == "LOCAL_PASS_REQUIRED"
    assert bad_result.reason_code == ReasonCode.NEW_BLOCK_BREACH


def test_report_html_is_static_escaped_render(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    report_path = tmp_path / "run" / "report.json"
    data = json.loads(report_path.read_text())
    data["strength_summary"] = "<script>alert(1)</script>"
    report_path.write_text(json.dumps(data), encoding="utf-8")
    out = tmp_path / "report.html"
    render_report_html(report_path, out)
    html = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_sponsor_evidence_verifier() -> None:
    result = validate_sponsor_evidence_shape(ROOT / "artifacts/sponsor/demo-readback.json")
    assert result.ok is False
    assert result.state == SponsorState.RECORDED_ATTESTATION_VALID
    assert result.reason_code == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED


def test_sponsor_evidence_mismatch_rejects(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    data = json.loads((ROOT / "artifacts/sponsor/demo-readback.json").read_text())
    data["metrics_output_hash"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    result = validate_sponsor_evidence_shape(path)
    assert result.ok is False
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_public_json_surfaces_have_schemas(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    expected = {
        "decision-envelope.v1.schema.json",
        "edit-provenance.v1.schema.json",
        "package-import.v1.schema.json",
        "proof.v1.schema.json",
        "proof-verification.v1.schema.json",
        "publish-preflight.v1.schema.json",
        "receipt.v3.2.schema.json",
        "report.v1.schema.json",
        "sponsor-readback-evidence.v1.schema.json",
        "sponsor-step-result.v1.schema.json",
        "spec.v2.1.schema.json",
        "suite.v2.schema.json",
        "verification-result.v1.schema.json",
    }
    assert {path.name for path in tmp_path.iterdir()} == expected


def test_proof_reproduce_commands_are_valid_shape(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    for proof in artifacts.receipt.proofs:
        assert proof.reproduce is not None
        assert proof.reproduce.startswith("uv run redline verify-proof receipt.json --proof-id ")


def test_anti_reroll_ledger_rejects_conflicting_status(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=None)
    assert artifacts.receipt is not None
    receipt = artifacts.receipt
    key_hash = hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )
    ledger = tmp_path / "issuance-ledger.jsonl"
    ledger.write_text(json.dumps({"key_hash": key_hash, "status": "withheld"}) + "\n", encoding="utf-8")
    try:
        atomic_write_receipt(tmp_path / "receipt.json", receipt, ledger_path=ledger)
    except IssuanceLedgerConflict:
        pass
    else:
        raise AssertionError("conflicting historical verdict must block receipt issuance")
    assert not (tmp_path / "receipt.json").exists()
