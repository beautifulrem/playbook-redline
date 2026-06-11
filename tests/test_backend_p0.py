from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from typer.testing import CliRunner

import redline.surfaces as surfaces_module
import redline.receipt as receipt_module
import redline.cli as cli_module

from redline.canonical import CanonicalizationError, canonical_number, hash_obj, hash_tree, sha256_bytes
from redline.cli import app
from redline.engine_adapter import DeterministicReplayEngine
from redline.engine_adapter.deterministic import build_worker_command
from redline.models import (
    CoverageManifest,
    DecisionContext,
    LedgerCheckpoint,
    PackageAnnotation,
    ProbeOutcome,
    ProbeResult,
    ProbeType,
    ProofKind,
    ReasonCode,
    ReportJson,
    Receipt,
    ReplayTrace,
    Status,
    VerificationLevel,
    VerificationStatus,
)
from redline.probes import PROBE_REGISTRY
from redline.proof_kernel import REQUIRED_PROOFS, decide
from redline.receipt import IssuanceLedgerConflict, atomic_write_receipt, compute_receipt_hash, make_decision_proof
from redline.runner import load_spec, load_suite, run_redline
from redline.schemas import export_schemas
from redline.sponsor.bitget import BitgetSponsorAdapter, SponsorState, SponsorStepResult, make_package_archive, validate_sponsor_evidence_shape, verify_sponsor_readback_evidence
from redline.mcp_server import build_server, redline_check_receipt, redline_compile_spec, redline_export_if_clean, redline_import_playbook, redline_run_suite
from redline.surfaces import (
    capture_edit_provenance,
    compile_spec,
    execute_sponsor_readback,
    import_package,
    make_receipt_bound_package_archive,
    publish_preflight,
    render_report_html,
    verify_annotation,
)
from redline.trust import generate_trust_keypair, make_trust_policy, sign_checkpoint, verify_checkpoint_attestation
from redline.verifier import verify, verify_proof

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"


def _sign_run_checkpoint(run_dir: Path, private_key: str, *, policy_id: str, key_id: str, issuer: str) -> object:
    checkpoint = LedgerCheckpoint.model_validate(json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text()))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer=issuer,
        trust_policy_id=policy_id,
        key_id=key_id,
        issuer=issuer,
    )
    (run_dir / "issuance-ledger.attestation.json").write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return attestation


def _make_chained_pass_fixture(tmp_path: Path, *, policy_id: str = "test-policy", key_id: str = "test-key", issuer: str = "test-ci") -> tuple[Path, object]:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id=policy_id, key_id=key_id, public_key=public_key, issuer=issuer)
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="baseline",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "baseline",
    )
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id=policy_id, key_id=key_id, issuer=issuer)
    chained = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert chained.receipt is not None
    assert chained.envelope.status == Status.PASS
    assert chained.envelope.reason_code == ReasonCode.PASS
    return package, chained


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
    assert (tmp_path / "good" / "issuance-ledger.checkpoint.json").exists()
    ReportJson.model_validate(good.report_json)
    assert good.report_json["proofs"]
    assert good.report_json["edit_provenance"]["diff_hash"] == good.receipt.edit_provenance.diff_hash


def test_run_records_external_version_anchors(tmp_path: Path) -> None:
    artifacts = run_redline(
        package_dir=PACKAGE,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path,
        baseline_version_id="git:main:baseline",
        candidate_version_id="git:feature:candidate",
    )
    assert artifacts.receipt is not None
    assert artifacts.receipt.baseline.baseline_version_id == "git:main:baseline"
    assert artifacts.receipt.candidate.candidate_version_id == "git:feature:candidate"


def test_suite_has_two_24_bar_scenarios_and_three_p0_probes() -> None:
    suite = load_suite(SUITE)
    spec = compile_spec(SPEC)
    assert len(suite.scenarios) == 2
    assert suite.suite_lock_hash is not None
    assert {probe.type for probe in spec.probes} == {ProbeType.MAX_DRAWDOWN, ProbeType.NO_ENTRY_WHEN, ProbeType.TRADE_BUDGET}
    for scenario in suite.scenarios:
        assert scenario.data_hash is not None
        assert scenario.bar_count == 24
        assert scenario.period_start is not None
        assert scenario.period_end is not None
        with Path(scenario.path).open(encoding="utf-8") as fh:
            assert len([line for line in fh if line.strip()]) == 25


def test_suite_lock_hash_covers_scenario_csv_content(tmp_path: Path) -> None:
    shutil.copytree(SUITE.parent, tmp_path / "suites")
    suite_path = tmp_path / "suites" / "demo_suite.json"
    suite = load_suite(suite_path)
    data = json.loads(suite_path.read_text())
    data["suite_lock_hash"] = suite.suite_lock_hash
    suite_path.write_text(json.dumps(data), encoding="utf-8")
    assert load_suite(suite_path).suite_lock_hash == suite.suite_lock_hash
    csv_path = tmp_path / "suites" / "btc_chop.csv"
    csv_path.write_text(csv_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    try:
        load_suite(suite_path)
    except ValueError as exc:
        assert "suite_lock_hash mismatch" in str(exc)
    else:
        raise AssertionError("suite lock must cover scenario data bytes")


def test_package_canonicalization_rejects_symlink_escape(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    external = tmp_path / "outside-secret.txt"
    external.write_text("do not package me", encoding="utf-8")
    (package / "external-link.txt").symlink_to(external)
    try:
        hash_tree(package)
    except CanonicalizationError as exc:
        assert exc.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    else:
        raise AssertionError("canonical package hashing must reject symlinks")
    try:
        make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")
    except CanonicalizationError as exc:
        assert exc.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    else:
        raise AssertionError("package archives must share the canonical symlink policy")


def test_candidate_entropy_source_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_random")
    (package / "candidate_random" / "strategy.py").write_text(
        "import random\n\n"
        "def signal(bar, state, config):\n"
        "    return random.choice([0, 1])\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_random",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION


def test_candidate_builtins_eval_bypass_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_eval_bypass")
    (package / "candidate_eval_bypass" / "strategy.py").write_text(
        "import builtins\n\n"
        "def signal(bar, state, config):\n"
        "    return builtins.__dict__['eval']('0')\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_eval_bypass",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION


def test_candidate_operator_attrgetter_globals_bypass_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_attrgetter_bypass")
    (package / "candidate_attrgetter_bypass" / "strategy.py").write_text(
        "import operator\n\n"
        "def signal(bar, state, config):\n"
        "    builtins = operator.attrgetter('__globals__')(signal)['__builtins__']\n"
        "    importer = builtins['__import__'] if isinstance(builtins, dict) else builtins.__dict__['__import__']\n"
        "    return int.from_bytes(importer('os').urandom(1), 'big') % 2\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_attrgetter_bypass",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION


def test_candidate_platform_os_reexport_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_platform_os")
    (package / "candidate_platform_os" / "strategy.py").write_text(
        "import platform\n\n"
        "def signal(bar, state, config):\n"
        "    state['host_tmp_count'] = len(platform.os.listdir('/tmp'))\n"
        "    return 0\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_platform_os",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION


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
    assert result.status == VerificationStatus.UNVERIFIED_NO_VERDICT
    assert result.reason_code == ReasonCode.BASELINE_GENESIS
    assert result.verification_level == VerificationLevel.REPLAYED


def test_pass_receipt_requires_each_block_probe_proof(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    probe_ids = {proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.PROBE and proof.verdict_bearing}
    assert probe_ids
    assert probe_ids.issubset(set(artifacts.receipt.decision.required_proof_ids))


def test_demo_receipts_replay_from_fresh_clone_path(monkeypatch, tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    shutil.copytree(ROOT / "fixtures", clone / "fixtures")
    shutil.copytree(ROOT / "artifacts/demo", clone / "artifacts/demo")
    monkeypatch.chdir(clone)

    pass_result = verify(
        receipt_path=Path("artifacts/demo/pass/receipt.json"),
        package=Path("fixtures/demo_pack"),
        suite_path=Path("fixtures/suites/demo_suite.json"),
        spec_path=Path("fixtures/specs/redline_spec.json"),
        level=VerificationLevel.REPLAYED,
    )
    assert pass_result.status == VerificationStatus.UNVERIFIED_NO_VERDICT
    assert pass_result.reason_code == ReasonCode.BASELINE_GENESIS

    withheld_result = verify(
        receipt_path=Path("artifacts/demo/withheld/receipt.json"),
        package=Path("fixtures/demo_pack"),
        suite_path=Path("fixtures/suites/demo_suite.json"),
        spec_path=Path("fixtures/specs/redline_spec.json"),
        level=VerificationLevel.REPLAYED,
    )
    assert withheld_result.status == VerificationStatus.VERIFIED
    assert withheld_result.reason_code == ReasonCode.NEW_BLOCK_BREACH


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


def test_verifier_rejects_non_verdict_proof_marked_verdict_bearing(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "run" / "receipt.json"
    data = json.loads(receipt_path.read_text())
    for proof in data["proofs"]:
        if proof["kind"] == ProofKind.EDIT_PROVENANCE.value:
            proof["verdict_bearing"] = True
            break
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)
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


def test_replayed_rejects_external_ledger_override_and_bad_checkpoint(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    external_ledger = tmp_path / "external-ledger.jsonl"
    shutil.copyfile(tmp_path / "run" / "issuance-ledger.jsonl", external_ledger)
    override = verify(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        ledger_path=external_ledger,
        level=VerificationLevel.REPLAYED,
    )
    assert override.status == VerificationStatus.REJECTED
    assert override.reason_code == ReasonCode.RECEIPT_MISMATCH

    checkpoint = tmp_path / "run" / "issuance-ledger.checkpoint.json"
    data = json.loads(checkpoint.read_text())
    data["ledger_tail_hash"] = "sha256:" + "0" * 64
    checkpoint.write_text(json.dumps(data), encoding="utf-8")
    bad_checkpoint = verify(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )
    assert bad_checkpoint.status == VerificationStatus.REJECTED
    assert bad_checkpoint.reason_code == ReasonCode.RECEIPT_MISMATCH


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


def test_empty_complete_coverage_never_passes() -> None:
    coverage = CoverageManifest.model_construct(cells=[], complete=True, missing=[])
    envelope = decide(proofs=[], coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x"))
    assert envelope.status == Status.UNVERIFIED_NO_VERDICT
    assert envelope.reason_code == ReasonCode.COVERAGE_INCOMPLETE


def test_duplicate_coverage_cells_are_schema_invalid() -> None:
    with pytest.raises(ValidationError):
        CoverageManifest(cells=[("scenario", "probe"), ("scenario", "probe")], complete=True, missing=[])


def test_empty_suite_and_nonblocking_spec_are_schema_invalid(tmp_path: Path) -> None:
    suite_data = json.loads(SUITE.read_text())
    suite_data["suite_lock_hash"] = None
    suite_data["scenarios"] = []
    empty_suite = tmp_path / "empty-suite.json"
    empty_suite.write_text(json.dumps(suite_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_suite(empty_suite)

    spec_data = json.loads(SPEC.read_text())
    spec_data["probes"] = []
    empty_spec = tmp_path / "empty-spec.json"
    empty_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(empty_spec)

    spec_data = json.loads(SPEC.read_text())
    for probe in spec_data["probes"]:
        probe["block"] = False
    nonblocking_spec = tmp_path / "nonblocking-spec.json"
    nonblocking_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(nonblocking_spec)


def test_duplicate_suite_scenario_and_probe_ids_are_schema_invalid(tmp_path: Path) -> None:
    suite_data = json.loads(SUITE.read_text())
    suite_data["suite_lock_hash"] = None
    suite_data["scenarios"][1]["id"] = suite_data["scenarios"][0]["id"]
    duplicate_suite = tmp_path / "duplicate-suite.json"
    duplicate_suite.write_text(json.dumps(suite_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_suite(duplicate_suite)

    spec_data = json.loads(SPEC.read_text())
    spec_data["probes"][1]["id"] = spec_data["probes"][0]["id"]
    duplicate_spec = tmp_path / "duplicate-spec.json"
    duplicate_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(duplicate_spec)


def test_exported_spec_schema_requires_block_probe(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    schema = json.loads((tmp_path / "spec.v2.1.schema.json").read_text(encoding="utf-8"))
    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    for probe in spec_data["probes"]:
        probe["block"] = False
    errors = list(Draft202012Validator(schema).iter_errors(spec_data))
    assert errors


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
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_virtualenv_is_not_visible_to_candidate(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_virtualenv_leak", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_indirect_dynamic_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_dynamic_entropy")
    (package / "candidate_dynamic_entropy" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    return getattr(__builtins__, 'eval')(\"__import__('os').urandom(1)[0] % 2\")\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_dynamic_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_importlib_dynamic_builtin_access(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_importlib_eval")
    (package / "candidate_importlib_eval" / "strategy.py").write_text(
        "import importlib\n\n"
        "def signal(bar, state, config):\n"
        "    return importlib.import_module('builtins').eval('1')\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_importlib_eval",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_sys_modules_builtin_access(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_sys_modules_eval")
    (package / "candidate_sys_modules_eval" / "strategy.py").write_text(
        "import sys\n\n"
        "def signal(bar, state, config):\n"
        "    return sys.modules['builtins'].eval('1')\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_sys_modules_eval",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_object_address_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_object_entropy")
    (package / "candidate_object_entropy" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    return hash(str(object())) % 2\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_object_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_runtime_file_read_leak(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_runtime_read")
    (package / "candidate_runtime_read" / "strategy.py").write_text(
        "import sys\n\n"
        "def signal(bar, state, config):\n"
        "    with open(sys.executable, 'rb') as fh:\n"
        "        return fh.read(1)[0]\n",
        encoding="utf-8",
    )
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_runtime_read",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_replay_rejects_nonpositive_or_nonfinite_market_data(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suites"
    shutil.copytree(SUITE.parent, suite_dir)
    suite_path = suite_dir / "demo_suite.json"
    suite_data = json.loads(suite_path.read_text())
    suite_data["suite_lock_hash"] = None
    suite_path.write_text(json.dumps(suite_data), encoding="utf-8")
    csv_path = suite_dir / "btc_crash.csv"
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    header = rows[0].split(",")
    close_index = header.index("close")
    values = rows[1].split(",")
    values[close_index] = "0"
    rows[1] = ",".join(values)
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=suite_path, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.DATA_MISSING
    assert artifacts.receipt is None

    values[close_index] = "NaN"
    rows[1] = ",".join(values)
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=suite_path, spec_path=SPEC, out_dir=tmp_path / "run-nan")
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.DATA_MISSING
    assert artifacts.receipt is None


def test_replay_rejects_nonfinite_leverage_without_traceback(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    (package / "candidate_good" / "config.json").write_text('{"leverage": "NaN"}\n', encoding="utf-8")

    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.NONFINITE_VALUE
    assert artifacts.receipt is None


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


def test_verify_proof_requires_package_for_live_replay(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    proof_id = artifacts.receipt.proofs[0].proof_id
    result = verify_proof(receipt_path=tmp_path / "receipt.json", proof_id=proof_id)
    assert result.status == "proof_unreplayable"
    assert result.reason_code == ReasonCode.DATA_MISSING


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


def test_verify_proof_rejects_duplicate_receipt_proof_ids(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    duplicate = next(proof for proof in artifacts.receipt.proofs if proof.kind == ProofKind.PROBE)
    non_decision = [proof for proof in artifacts.receipt.proofs if proof.kind != ProofKind.DECISION]
    ambiguous_proofs = [*non_decision, duplicate]
    envelope = decide(
        proofs=ambiguous_proofs,
        coverage=artifacts.receipt.coverage,
        context=DecisionContext(
            suite_id=artifacts.receipt.suite.suite_id,
            spec_hash=artifacts.receipt.spec.spec_hash,
            chain_status=artifacts.receipt.baseline.chain_status,
        ),
    )
    decision_proof = make_decision_proof(envelope=envelope, proofs=ambiguous_proofs)
    ambiguous_receipt = artifacts.receipt.model_copy(
        update={
            "proofs": [*ambiguous_proofs, decision_proof],
            "decision": artifacts.receipt.decision.model_copy(
                update={
                    "reason_code": envelope.reason_code,
                    "required_proof_ids": envelope.required_proof_ids,
                    "satisfied_proof_ids": envelope.satisfied_proof_ids,
                }
            ),
            "receipt_hash": "",
        }
    )
    ambiguous_receipt = ambiguous_receipt.model_copy(update={"receipt_hash": compute_receipt_hash(ambiguous_receipt)})
    (tmp_path / "receipt.json").write_text(ambiguous_receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")
    result = verify_proof(receipt_path=tmp_path / "receipt.json", proof_id=duplicate.proof_id, package=PACKAGE, suite_path=SUITE, spec_path=SPEC)
    assert result.status == "proof_mismatch"
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_verify_proof_replays_when_package_is_supplied(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    proof_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.REPLAY)
    proof = next(proof for proof in artifacts.receipt.proofs if proof.proof_id == proof_id)
    assert "--baseline-receipt" not in proof.reproduce
    assert "--trust-policy" not in proof.reproduce
    result = verify_proof(receipt_path=tmp_path / "run" / "receipt.json", proof_id=proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert result.status == "proof_verified"
    (package / "candidate_good" / "config.json").write_text('{"entry_bar": 1, "exit_bar": 99, "leverage": "2.0"}\n', encoding="utf-8")
    mismatch = verify_proof(receipt_path=tmp_path / "run" / "receipt.json", proof_id=proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert mismatch.status == "proof_mismatch"
    assert mismatch.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_chained_verify_proof_reproduce_carries_chain_inputs(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    replay_proof = next(proof for proof in artifacts.receipt.proofs if proof.kind == ProofKind.REPLAY)
    decision_proof = next(proof for proof in artifacts.receipt.proofs if proof.kind == ProofKind.DECISION)
    for proof in (replay_proof, decision_proof):
        assert "--baseline-receipt <baseline-receipt>" in proof.reproduce
        assert "--trust-policy <trust-policy>" in proof.reproduce
    result = verify_proof(
        receipt_path=tmp_path / "run" / "receipt.json",
        proof_id=replay_proof.proof_id,
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        trust_policy_path=tmp_path / "trust-policy.json",
    )
    assert result.status == "proof_verified"


def test_mcp_rerun_uses_default_suite_and_spec(monkeypatch, tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    monkeypatch.chdir(tmp_path)
    result = redline_check_receipt(str(tmp_path / "receipt.json"), pkg_path=str(PACKAGE), rerun=True)
    assert result["schema_version"] == "redline.mcp.check.v1"
    assert result["status"] == VerificationStatus.UNVERIFIED_NO_VERDICT.value
    assert result["reason_code"] == ReasonCode.BASELINE_GENESIS.value
    assert result["verification_level"] == VerificationLevel.REPLAYED.value


def test_mcp_package_path_defaults_to_replayed_and_checks_proof_sidecars(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    next((tmp_path / "run" / "proofs").glob("proof_probe_*.json")).unlink()
    result = redline_check_receipt(str(tmp_path / "run" / "receipt.json"), pkg_path=str(PACKAGE))
    assert result["schema_version"] == "redline.mcp.check.v1"
    assert result["verification_level"] == VerificationLevel.REPLAYED.value
    assert result["status"] == VerificationStatus.REJECTED.value
    assert result["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value


def test_mcp_import_compile_run_and_export_surfaces(tmp_path: Path) -> None:
    imported = redline_import_playbook(str(PACKAGE))
    assert imported["schema_version"] == "redline.mcp.import.v1"
    assert imported["identity_hash"].startswith("sha256:")
    assert "candidate_good/strategy.py" in imported["files"]

    compiled = redline_compile_spec(str(SPEC))
    assert compiled["schema_version"] == "redline.mcp.compile.v1"
    assert compiled["spec_hash"].startswith("sha256:")
    assert compiled["compiler"] == "json"
    assert compiled["spec"]["version"] == "redline.spec.v2.1"

    run = redline_run_suite(
        str(PACKAGE),
        baseline="baseline",
        candidate="candidate_bad",
        suite_path=str(SUITE),
        spec_path=str(SPEC),
    )
    assert run["schema_version"] == "redline.mcp.run.v1"
    assert run["envelope"]["status"] == Status.WITHHELD.value
    assert run["envelope"]["reason_code"] == ReasonCode.NEW_BLOCK_BREACH.value
    assert run["receipt_hash"].startswith("sha256:")

    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    export = redline_export_if_clean(
        str(tmp_path / "run" / "receipt.json"),
        str(PACKAGE),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
        report_path=str(tmp_path / "run" / "report.json"),
    )
    assert export["schema_version"] == "redline.mcp.export_if_clean.v1"
    assert export["export_allowed"] is False
    assert export["verification"]["schema_version"] == "redline.mcp.check.v1"
    assert export["verification"]["reason_code"] == ReasonCode.BASELINE_GENESIS.value


def test_fastmcp_registers_design_tool_names() -> None:
    server = build_server()
    tool_names = set(server._tool_manager._tools)
    assert tool_names == {"redline_check_receipt"}
    assert "redline_verify_receipt" not in tool_names
    assert "redline_import_playbook" not in tool_names
    assert "redline_compile_spec" not in tool_names
    assert "redline_run_suite" not in tool_names
    assert "redline_export_if_clean" not in tool_names


def test_mcp_verifies_chained_receipt_with_trust_inputs(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="mcp-policy", key_id="mcp-key", public_key=public_key, issuer="mcp-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="mcp-policy", key_id="mcp-key", issuer="mcp-ci")
    chained = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "chained",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert chained.receipt is not None
    _sign_run_checkpoint(tmp_path / "chained", private_key, policy_id="mcp-policy", key_id="mcp-key", issuer="mcp-ci")
    untrusted_check = redline_check_receipt(
        str(tmp_path / "chained" / "receipt.json"),
        pkg_path=str(package),
        rerun=True,
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert untrusted_check["status"] != VerificationStatus.VERIFIED.value
    assert untrusted_check["reason_code"] == ReasonCode.BASELINE_UNCHAINED.value
    assert untrusted_check["trust_source"] == "untrusted_tool_input"
    untrusted_export = redline_export_if_clean(
        str(tmp_path / "chained" / "receipt.json"),
        str(package),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
        report_path=str(tmp_path / "chained" / "report.json"),
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert untrusted_export["export_allowed"] is False
    assert untrusted_export["trust_source"] == "untrusted_tool_input"
    monkeypatch.setenv("REDLINE_TRUST_POLICY_HASH", policy.policy_hash)
    result = redline_check_receipt(
        str(tmp_path / "chained" / "receipt.json"),
        pkg_path=str(package),
        rerun=True,
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert result["reason_code"] == ReasonCode.PASS.value
    assert result["chain_status"] == "chained"
    assert result["trust_source"] == "protected_env"
    trusted_export = redline_export_if_clean(
        str(tmp_path / "chained" / "receipt.json"),
        str(package),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
        report_path=str(tmp_path / "chained" / "report.json"),
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert trusted_export["export_allowed"] is True
    assert trusted_export["trust_source"] == "protected_env"
    assert trusted_export["export"]["state"] == "ANNOTATED_PACKAGE_READY"
    assert Path(trusted_export["annotation_path"]).exists()
    assert Path(trusted_export["annotated_package_path"]).exists()


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


def test_import_compile_cli_bad_inputs_return_typed_json(tmp_path: Path) -> None:
    runner = CliRunner()
    missing_package = runner.invoke(app, ["import", str(tmp_path / "missing-package"), "--json"])
    assert missing_package.exit_code == 2
    payload = json.loads(missing_package.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    missing_spec = runner.invoke(app, ["compile", str(tmp_path / "missing-spec.json"), "--json"])
    assert missing_spec.exit_code == 2
    payload = json.loads(missing_spec.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    malformed_spec = tmp_path / "bad-spec.json"
    malformed_spec.write_text("{not-json", encoding="utf-8")
    malformed = runner.invoke(app, ["compile", str(malformed_spec), "--json"])
    assert malformed.exit_code == 2
    payload = json.loads(malformed.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.PARSE_ERROR.value

    missing_suite = runner.invoke(
        app,
        [
            "run",
            str(PACKAGE),
            "--candidate",
            "candidate_good",
            "--suite",
            str(tmp_path / "missing-suite.json"),
            "--json",
        ],
    )
    assert missing_suite.exit_code == 2
    payload = json.loads(missing_suite.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    missing_run_spec = runner.invoke(
        app,
        [
            "run",
            str(PACKAGE),
            "--candidate",
            "candidate_good",
            "--spec",
            str(tmp_path / "missing-spec.json"),
            "--json",
        ],
    )
    assert missing_run_spec.exit_code == 2
    payload = json.loads(missing_run_spec.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    symlink_package = tmp_path / "symlink-package"
    shutil.copytree(PACKAGE, symlink_package)
    (symlink_package / "external-link.txt").symlink_to("/etc/passwd")
    symlink_import = runner.invoke(app, ["import", str(symlink_package), "--json"])
    assert symlink_import.exit_code == 4
    payload = json.loads(symlink_import.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value

    missing_check_package = runner.invoke(
        app,
        [
            "check",
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--package",
            str(tmp_path / "missing-package"),
            "--rerun",
            "--json",
        ],
    )
    assert missing_check_package.exit_code == 2
    payload = json.loads(missing_check_package.stdout)
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    missing_prompt = runner.invoke(app, ["capture-edit", "--prompt-log", str(tmp_path / "missing-prompt.txt"), "--json"])
    assert missing_prompt.exit_code == 2
    payload = json.loads(missing_prompt.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    prompt_log = tmp_path / "prompt.txt"
    prompt_log.write_text("make it safer", encoding="utf-8")
    missing_edit_role = runner.invoke(
        app,
        [
            "capture-edit",
            "--prompt-log",
            str(prompt_log),
            "--baseline",
            str(tmp_path / "missing-baseline"),
            "--candidate",
            str(tmp_path / "missing-candidate"),
            "--json",
        ],
    )
    assert missing_edit_role.exit_code == 2
    payload = json.loads(missing_edit_role.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.FILE_NOT_FOUND.value


def test_mcp_bad_inputs_return_specific_reason_codes(tmp_path: Path) -> None:
    imported = redline_import_playbook(str(tmp_path / "missing-package"))
    assert imported["schema_version"] == "redline.mcp.error.v1"
    assert imported["reason_code"] == ReasonCode.FILE_NOT_FOUND.value
    compiled = redline_compile_spec(str(tmp_path / "missing-spec.json"))
    assert compiled["schema_version"] == "redline.mcp.error.v1"
    assert compiled["reason_code"] == ReasonCode.FILE_NOT_FOUND.value
    run = redline_run_suite(str(tmp_path / "missing-package"))
    assert run["schema_version"] == "redline.mcp.error.v1"
    assert run["reason_code"] == ReasonCode.FILE_NOT_FOUND.value


def test_edit_provenance_diff_mismatch_rejects(tmp_path: Path) -> None:
    prompt_log = tmp_path / "prompt.txt"
    prompt_log.write_text("make the strategy more responsive", encoding="utf-8")
    bad_provenance = capture_edit_provenance(
        tool="fixture-agent",
        prompt_log=prompt_log,
        baseline=PACKAGE / "baseline",
        candidate=PACKAGE / "candidate_bad",
    )
    artifacts = run_redline(
        package_dir=PACKAGE,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
        edit_provenance=bad_provenance,
    )
    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    assert any(proof.kind == ProofKind.EDIT_PROVENANCE for proof in artifacts.proofs)


def test_qwen_compile_path_records_locked_spec_metadata(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == "qwen-test"
        content = {
            "version": "redline.spec.v2.1",
            "spec_id": "qwen-compiled",
            "probes": [
                {"id": "drawdown_limit", "type": "max_drawdown", "params": {"max_drawdown": "0.07"}, "block": True},
                {"id": "no_entry_when_crash", "type": "no_entry_when", "params": {"scenario_id": "btc-crash-2024-03-05", "before_bar": "4", "max_abs_position": "0"}, "block": True},
                {"id": "trade_budget", "type": "trade_budget", "params": {"max_trades": "12"}, "block": True},
            ],
        }
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode()

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    assert compiled.compiler == "qwen"
    assert compiled.model == "qwen-test"
    assert compiled.declared_intent == text_spec.read_text(encoding="utf-8")
    assert compiled.tool_schema_hash is not None
    assert compiled.degraded_reason is None
    assert compiled.probes[0].params["max_drawdown"] == "0.07"


def test_qwen_compile_discards_invalid_model_output(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        content = {"version": "redline.spec.v2.1", "spec_id": "bad", "probes": [{"id": "bad", "type": "unknown", "params": {}, "block": True}]}
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode()

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    assert compiled.compiler == "json-fallback"
    assert compiled.degraded_reason == "qwen_response_invalid"
    assert compiled.declared_intent == text_spec.read_text(encoding="utf-8")
    assert {probe.type for probe in compiled.probes} == {ProbeType.MAX_DRAWDOWN, ProbeType.NO_ENTRY_WHEN, ProbeType.TRADE_BUDGET}


def test_qwen_compile_discards_semantically_extreme_thresholds(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        content = {
            "version": "redline.spec.v2.1",
            "spec_id": "extreme",
            "probes": [
                {"id": "drawdown_limit", "type": "max_drawdown", "params": {"max_drawdown": "999"}, "block": True},
                {"id": "no_entry_when_crash", "type": "no_entry_when", "params": {"scenario_id": "btc-crash-2024-03-05", "before_bar": "4", "max_abs_position": "0"}, "block": True},
                {"id": "trade_budget", "type": "trade_budget", "params": {"max_trades": "12"}, "block": True},
            ],
        }
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode()

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    assert compiled.compiler == "json-fallback"
    assert compiled.degraded_reason == "qwen_semantic_sanity_failed"
    assert compiled.probes[0].params["max_drawdown"] == "0.07"


def test_qwen_compile_records_transport_degraded_reason(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def http_transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        return 429, b'{"error":"rate limited"}'

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=http_transport)
    assert compiled.compiler == "json-fallback"
    assert compiled.degraded_reason == "qwen_http_429"

    def failing_transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        raise TimeoutError("timeout")

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=failing_transport)
    assert compiled.compiler == "json-fallback"
    assert compiled.degraded_reason == "qwen_transport_exception"


def test_publish_preflight_requires_chained_pass_by_default_and_demo_flag_writes_annotation(tmp_path: Path) -> None:
    good = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "good")
    assert good.receipt is not None
    good_result = publish_preflight(
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-good",
    )
    assert good_result.ok is False
    assert good_result.state == "CHAINED_PASS_REQUIRED"
    assert good_result.reason_code == ReasonCode.BASELINE_GENESIS
    demo_result = publish_preflight(
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-demo",
        allow_demo_baseline_genesis=True,
    )
    assert demo_result.ok is True
    assert demo_result.state == "DEMO_ANNOTATION_READY"
    annotation_path = tmp_path / "publish-demo" / "redline-annotation.json"
    assert annotation_path.exists()
    annotation_verify = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        report_path=tmp_path / "good" / "report.json",
        ledger_checkpoint_path=tmp_path / "good" / "issuance-ledger.checkpoint.json",
    )
    assert annotation_verify.ok is False
    assert annotation_verify.state == "DEMO_ANNOTATION_REQUIRES_ALLOW_FLAG"
    annotation_verify = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        report_path=tmp_path / "good" / "report.json",
        ledger_checkpoint_path=tmp_path / "good" / "issuance-ledger.checkpoint.json",
        allow_demo_preview=True,
    )
    assert annotation_verify.ok is True
    assert annotation_verify.reason_code == ReasonCode.BASELINE_GENESIS
    bare_verify = verify_annotation(annotation_path=annotation_path)
    assert bare_verify.ok is False
    assert bare_verify.state == "ANNOTATION_BINDINGS_REQUIRED"
    tampered = json.loads(annotation_path.read_text())
    tampered["report_hash"] = "sha256:" + "0" * 64
    annotation_path.write_text(json.dumps(tampered), encoding="utf-8")
    tampered_verify = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        report_path=tmp_path / "good" / "report.json",
        ledger_checkpoint_path=tmp_path / "good" / "issuance-ledger.checkpoint.json",
    )
    assert tampered_verify.ok is False
    assert tampered_verify.state == "ANNOTATION_HASH_MISMATCH"
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


def test_signed_checkpoint_allows_chained_pass_publish_path(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="test-policy", key_id="test-key", public_key=public_key, issuer="test-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline_run = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="baseline",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "baseline",
    )
    assert baseline_run.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="test-policy", key_id="test-key", issuer="test-ci")
    chained_run = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "chained",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert chained_run.envelope.status == Status.PASS
    assert chained_run.envelope.reason_code == ReasonCode.PASS
    assert chained_run.receipt is not None
    assert chained_run.receipt.baseline.baseline_receipt_hash == baseline_run.receipt.receipt_hash

    checkpoint = LedgerCheckpoint.model_validate(json.loads((tmp_path / "chained" / "issuance-ledger.checkpoint.json").read_text()))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="test-ci",
        trust_policy_id="test-policy",
        key_id="test-key",
        issuer="test-ci",
    )
    attestation_path = tmp_path / "chained" / "issuance-ledger.attestation.json"
    attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    assert verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy=policy)

    unsigned = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        level=VerificationLevel.REPLAYED,
    )
    assert unsigned.status == VerificationStatus.REJECTED
    assert unsigned.reason_code == ReasonCode.BASELINE_UNCHAINED
    verified = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trusted_ledger_public_key=public_key,
        level=VerificationLevel.REPLAYED,
    )
    assert verified.status == VerificationStatus.REJECTED
    assert verified.reason_code == ReasonCode.BASELINE_UNCHAINED
    try:
        render_report_html(
            tmp_path / "chained" / "report.json",
            tmp_path / "raw-key-verified.html",
            receipt_path=tmp_path / "chained" / "receipt.json",
            package=package,
            suite_path=SUITE,
            spec_path=SPEC,
            baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
            ledger_attestation_path=attestation_path,
            trusted_ledger_public_key=public_key,
            require_verified=True,
        )
    except ValueError as exc:
        assert "BASELINE_UNCHAINED" in str(exc)
    else:
        raise AssertionError("raw public key must not produce a verified report stamp")
    verified_with_policy = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        level=VerificationLevel.REPLAYED,
    )
    assert verified_with_policy.status == VerificationStatus.VERIFIED
    assert verified_with_policy.reason_code == ReasonCode.PASS

    publish = publish_preflight(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert publish.ok is True
    assert publish.state == "ANNOTATED_PACKAGE_READY"
    assert publish.ledger_attestation_hash == attestation.attestation_hash
    assert publish.package_archive_hash is not None
    with tarfile.open(tmp_path / "publish" / "annotated-package.tar.gz", "r:gz") as tar:
        assert ".redline/redline-annotation.json" in tar.getnames()
        annotation_member = tar.extractfile(".redline/redline-annotation.json")
        assert annotation_member is not None
        assert json.loads(annotation_member.read().decode("utf-8"))["annotation_hash"] == publish.annotation_hash
    annotation_result = verify_annotation(
        annotation_path=tmp_path / "publish" / "redline-annotation.json",
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        report_path=tmp_path / "chained" / "report.json",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_checkpoint_path=tmp_path / "chained" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
    )
    assert annotation_result.ok is True
    assert annotation_result.reason_code == ReasonCode.PASS
    proof_backup = tmp_path / "proof-backup"
    shutil.copytree(tmp_path / "chained" / "proofs", proof_backup)
    shutil.rmtree(tmp_path / "chained" / "proofs")
    missing_sidecar_result = verify_annotation(
        annotation_path=tmp_path / "publish" / "redline-annotation.json",
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        report_path=tmp_path / "chained" / "report.json",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_checkpoint_path=tmp_path / "chained" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
    )
    assert missing_sidecar_result.ok is False
    assert missing_sidecar_result.state == "ANNOTATION_RECEIPT_INVALID"
    assert missing_sidecar_result.reason_code == ReasonCode.RECEIPT_MISMATCH
    shutil.copytree(proof_backup, tmp_path / "chained" / "proofs")
    forged_annotation_path = tmp_path / "forged-publish-annotation.json"
    forged_annotation = json.loads((tmp_path / "publish" / "redline-annotation.json").read_text())
    forged_annotation["ledger_attestation_hash"] = None
    forged_annotation["trust_policy_id"] = None
    forged_annotation["trusted_ledger_key_id"] = None
    forged_hash_payload = {**forged_annotation, "annotation_hash": ""}
    forged_annotation["annotation_hash"] = hash_obj({key: value for key, value in forged_hash_payload.items() if value is not None})
    forged_annotation_path.write_text(json.dumps(forged_annotation), encoding="utf-8")
    forged_result = verify_annotation(
        annotation_path=forged_annotation_path,
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        report_path=tmp_path / "chained" / "report.json",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_checkpoint_path=tmp_path / "chained" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
    )
    assert forged_result.ok is False
    assert forged_result.state == "ANNOTATION_ATTESTATION_REQUIRED"
    render_report_html(
        tmp_path / "chained" / "report.json",
        tmp_path / "verified.html",
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trusted_ledger_public_key=public_key,
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
        require_verified=True,
    )
    assert "VERIFIED / PASS" in (tmp_path / "verified.html").read_text(encoding="utf-8")
    try:
        render_report_html(
            tmp_path / "chained" / "report.json",
            tmp_path / "self-policy-verified.html",
            receipt_path=tmp_path / "chained" / "receipt.json",
            package=package,
            suite_path=SUITE,
            spec_path=SPEC,
            baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
            ledger_attestation_path=attestation_path,
            trust_policy_path=policy_path,
            require_verified=True,
        )
    except ValueError as exc:
        assert "PASS" in str(exc)
    else:
        raise AssertionError("caller-supplied trust policy without pinned hash must not produce a verified report stamp")

    self_signed_publish = publish_preflight(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "self-signed-publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trusted_ledger_public_key=public_key,
    )
    assert self_signed_publish.ok is False
    assert self_signed_publish.state == "TRUSTED_LEDGER_CHECKPOINT_REQUIRED"
    unpinned_policy_publish = publish_preflight(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "unpinned-policy-publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
    )
    assert unpinned_policy_publish.ok is False
    assert unpinned_policy_publish.state == "TRUST_POLICY_REQUIRED"


def test_verify_annotation_rejects_withheld_publish_annotation(tmp_path: Path) -> None:
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="annotation-policy", key_id="annotation-key", public_key=public_key, issuer="annotation-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    withheld = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "withheld")
    assert withheld.receipt is not None
    attestation = _sign_run_checkpoint(tmp_path / "withheld", private_key, policy_id="annotation-policy", key_id="annotation-key", issuer="annotation-ci")
    checkpoint = LedgerCheckpoint.model_validate(json.loads((tmp_path / "withheld" / "issuance-ledger.checkpoint.json").read_text()))
    annotation = PackageAnnotation(
        annotation_kind="publish-preflight",
        receipt_path=str(tmp_path / "withheld" / "receipt.json"),
        receipt_hash=withheld.receipt.receipt_hash,
        report_hash=withheld.receipt.report.report_hash,
        package_hash=hash_tree(PACKAGE),
        ledger_hash=checkpoint.ledger_hash,
        ledger_checkpoint_hash=checkpoint.checkpoint_hash,
        ledger_attestation_hash=attestation.attestation_hash,
        strength_summary=withheld.receipt.strength_summary,
        chain_status=withheld.receipt.baseline.chain_status,
        verification_level=VerificationLevel.REPLAYED,
        trust_policy_id=attestation.trust_policy_id,
        trusted_ledger_key_id=attestation.key_id,
        annotation_hash="",
    )
    annotation = annotation.model_copy(update={"annotation_hash": hash_obj(annotation)})
    annotation_path = tmp_path / "forged-publish-annotation.json"
    annotation_path.write_text(annotation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    result = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "withheld" / "receipt.json",
        package=PACKAGE,
        report_path=tmp_path / "withheld" / "report.json",
        ledger_checkpoint_path=tmp_path / "withheld" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=tmp_path / "withheld" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
    )
    assert result.ok is False
    assert result.state == "ANNOTATION_LOCAL_PASS_REQUIRED"
    assert result.reason_code == ReasonCode.NEW_BLOCK_BREACH


def test_signed_checkpoint_rejects_wrong_public_key(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="test-policy", key_id="test-key", public_key=public_key, issuer="test-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline_run = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline_run.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="test-policy", key_id="test-key", issuer="test-ci")
    chained_run = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "chained",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert chained_run.receipt is not None
    _other_private, other_public = generate_trust_keypair()
    wrong_policy = make_trust_policy(policy_id="test-policy", key_id="test-key", public_key=other_public, issuer="test-ci")
    wrong_policy_path = tmp_path / "wrong-policy.json"
    wrong_policy_path.write_text(wrong_policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    checkpoint = LedgerCheckpoint.model_validate(json.loads((tmp_path / "chained" / "issuance-ledger.checkpoint.json").read_text()))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="test-ci",
        trust_policy_id="test-policy",
        key_id="test-key",
        issuer="test-ci",
    )
    attestation_path = tmp_path / "chained" / "issuance-ledger.attestation.json"
    attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    assert not verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trusted_public_key_text=other_public)
    result = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=wrong_policy_path,
        level=VerificationLevel.REPLAYED,
    )
    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_report_html_is_static_escaped_render(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    report_path = tmp_path / "run" / "report.json"
    forged_preview = tmp_path / "forged-preview.json"
    data = json.loads(report_path.read_text())
    data["strength_summary"] = "<script>alert(1)</script>"
    data["report_hash"] = hash_obj({key: value for key, value in {**data, "receipt_hash": None}.items() if key != "report_hash"})
    forged_preview.write_text(json.dumps(data), encoding="utf-8")
    out = tmp_path / "report.html"
    render_report_html(forged_preview, out)
    html = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "UNVERIFIED PREVIEW" in html
    try:
        render_report_html(
            tmp_path / "run" / "report.json",
            tmp_path / "verified.html",
            receipt_path=tmp_path / "run" / "receipt.json",
            package=PACKAGE,
            suite_path=SUITE,
            spec_path=SPEC,
            require_verified=True,
        )
    except ValueError as exc:
        assert "BASELINE_GENESIS" in str(exc)
    else:
        raise AssertionError("genesis report must not render with --verified")


def test_report_html_rejects_stale_report_hash(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    report_path = tmp_path / "run" / "report.json"
    data = json.loads(report_path.read_text())
    data["envelope"]["status"] = "withheld"
    report_path.write_text(json.dumps(data), encoding="utf-8")
    try:
        render_report_html(report_path, tmp_path / "forged.html")
    except ValueError as exc:
        assert "report_hash mismatch" in str(exc)
    else:
        raise AssertionError("stale report_hash must not render")


def test_publish_execute_forbids_demo_baseline(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    result = CliRunner().invoke(
        app,
        [
            "publish",
            str(PACKAGE),
            str(tmp_path / "run" / "receipt.json"),
            "--suite",
            str(SUITE),
            "--spec",
            str(SPEC),
            "--out",
            str(tmp_path / "publish"),
            "--execute",
            "--yes-i-understand-redline-is-wrapper-only",
            "--allow-demo-baseline-genesis",
            "--json",
        ],
    )
    assert result.exit_code == 6
    stdout = json.loads(result.stdout)
    assert stdout["ok"] is False
    assert stdout["state"] == "DEMO_EXECUTE_FORBIDDEN"


def test_publish_rejects_output_inside_package_and_symlink_package(tmp_path: Path) -> None:
    runner = CliRunner()
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    inside_out = package / "publish"
    inside = runner.invoke(
        app,
        [
            "publish",
            str(package),
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--out",
            str(inside_out),
            "--allow-demo-baseline-genesis",
            "--json",
        ],
    )
    assert inside.exit_code == 4
    payload = json.loads(inside.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "OUTPUT_PATH_INSIDE_PACKAGE"
    assert not inside_out.exists()

    symlink_package = tmp_path / "symlink-package"
    shutil.copytree(PACKAGE, symlink_package)
    (symlink_package / "external-link.txt").symlink_to("/etc/passwd")
    symlinked = runner.invoke(
        app,
        [
            "publish",
            str(symlink_package),
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--out",
            str(tmp_path / "publish"),
            "--allow-demo-baseline-genesis",
            "--json",
        ],
    )
    assert symlinked.exit_code == 4
    payload = json.loads(symlinked.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "PACKAGE_INVALID"
    assert payload["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value


def test_publish_rejects_existing_file_out_path_with_json_error(tmp_path: Path) -> None:
    out_file = tmp_path / "publish-file"
    out_file.write_text("not a directory", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "publish",
            str(PACKAGE),
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--out",
            str(out_file),
            "--allow-demo-baseline-genesis",
            "--json",
        ],
    )
    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "OUTPUT_PATH_INVALID"
    assert payload["reason_code"] == ReasonCode.DATA_MISSING.value
    assert "Traceback" not in result.stderr


def test_make_demo_refuses_broad_or_unowned_output_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    root_result = runner.invoke(app, ["make-demo", "--out", "."])
    assert root_result.exit_code == 6
    fixture_result = runner.invoke(app, ["make-demo", "--out", str(PACKAGE)])
    assert fixture_result.exit_code == 6
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    sentinel = sentinel_dir / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    sentinel_result = runner.invoke(app, ["make-demo", "--out", str(sentinel_dir)])
    assert sentinel_result.exit_code == 6
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_make_demo_rejects_bad_package_without_receipts(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "bad-demo"
    result = runner.invoke(app, ["make-demo", "--package", str(tmp_path / "missing-package"), "--out", str(out_dir)])
    assert result.exit_code == 6
    assert not (out_dir / "pass" / "receipt.json").exists()
    assert not (out_dir / "withheld" / "receipt.json").exists()


def test_make_demo_allows_standard_tmp_path(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = Path("/tmp") / f"redline-demo-{tmp_path.name}"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    try:
        result = runner.invoke(app, ["make-demo", "--out", str(out_dir)])
        assert result.exit_code == 0
        assert (out_dir / "pass" / "receipt.json").exists()
        assert (out_dir / "withheld" / "receipt.json").exists()
    finally:
        if out_dir.exists():
            shutil.rmtree(out_dir)


def test_run_rejects_package_role_escape_without_receipt(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(PACKAGE / "candidate_good", tmp_path / "outside_candidate")
    out_dir = tmp_path / "escaped-run"
    result = CliRunner().invoke(app, ["run", str(package), "--candidate", "../outside_candidate", "--out", str(out_dir), "--json"])
    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.DATA_MISSING.value
    assert not (out_dir / "receipt.json").exists()


def test_run_same_out_dir_preserves_ledger_conflict(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "run"
    first = runner.invoke(app, ["run", str(PACKAGE), "--candidate", "candidate_good", "--out", str(out_dir), "--json"])
    assert first.exit_code == 10
    receipt_before = (out_dir / "receipt.json").read_text(encoding="utf-8")
    ledger_before = (out_dir / "issuance-ledger.jsonl").read_text(encoding="utf-8")
    second = runner.invoke(app, ["run", str(PACKAGE), "--candidate", "candidate_good", "--out", str(out_dir), "--json"])
    assert second.exit_code == 4
    payload = json.loads(second.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value
    assert (out_dir / "receipt.json").read_text(encoding="utf-8") == receipt_before
    assert (out_dir / "issuance-ledger.jsonl").read_text(encoding="utf-8") == ledger_before


def test_make_demo_rebuild_is_stable(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "demo"
    other_out_dir = tmp_path / "demo-copy"
    first = runner.invoke(app, ["make-demo", "--out", str(out_dir)])
    assert first.exit_code == 0
    first_snapshot = {str(path.relative_to(out_dir)): path.read_bytes() for path in sorted(out_dir.rglob("*")) if path.is_file()}
    second = runner.invoke(app, ["make-demo", "--out", str(out_dir)])
    assert second.exit_code == 0
    second_snapshot = {str(path.relative_to(out_dir)): path.read_bytes() for path in sorted(out_dir.rglob("*")) if path.is_file()}
    assert second_snapshot == first_snapshot
    third = runner.invoke(app, ["make-demo", "--out", str(other_out_dir)])
    assert third.exit_code == 0
    third_snapshot = {str(path.relative_to(other_out_dir)): path.read_bytes() for path in sorted(other_out_dir.rglob("*")) if path.is_file()}
    assert third_snapshot == first_snapshot


def test_default_run_receipt_is_stable_across_output_dirs(tmp_path: Path) -> None:
    first = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "a")
    second = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_bad", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "b")
    assert first.receipt is not None
    assert second.receipt is not None
    assert second.receipt.receipt_hash == first.receipt.receipt_hash


def test_bitget_sponsor_adapter_records_redacted_transcript(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive_a = make_package_archive(package_dir=package, out_path=tmp_path / "a.tar.gz")
    archive_b = make_package_archive(package_dir=package, out_path=tmp_path / "b.tar.gz")
    assert archive_a.read_bytes() == archive_b.read_bytes()
    calls: list[tuple[str, str, dict[str, str], bytes]] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append((method, url, headers, body))
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"draft_id": "draft-1", "version_id": "version-1"}).encode()
        if url.endswith("/api/v1/playbook/run") and method == "POST":
            return 200, json.dumps({"run_id": "run-1", "status": "started"}).encode()
        if "/api/v1/playbook/run?" in url and method == "GET":
            metrics_output = {
                "status": artifacts.receipt.result.status,
                "breaches": [assertion.model_dump(mode="json") for assertion in artifacts.receipt.result.new_breaches],
            }
            return 200, json.dumps({"run_id": "run-1", "version_id": "version-1", "status": "completed", "metrics_output": metrics_output}).encode()
        return 404, b"{}"

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive_a)
    assert upload.ok is True
    run = adapter.run(version_id=upload.evidence["version_id"])
    assert run.ok is True
    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id=upload.evidence["version_id"],
        expected_metrics_output_hash=artifacts.receipt.result.result_hash,
        expected_package_hash=artifacts.receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence["package_archive_hash"],
    )
    assert readback.ok is False
    assert readback.state == SponsorState.RECORDED_ATTESTATION_VALID
    assert readback.reason_code == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED
    assert readback.evidence["proof_eligible"] == "false"
    assert "metrics_output_hash" in readback.evidence
    transcript = (tmp_path / "transcript.jsonl").read_text(encoding="utf-8")
    assert "abcd1234secret5678" not in transcript
    assert "abcd***5678" in transcript
    assert "secret-key-1" not in transcript
    assert "passphrase-1" not in transcript
    assert "ACCESS-SIGN" in calls[0][2]
    assert "ACCESS-TIMESTAMP" in calls[0][2]
    assert "ACCESS-PASSPHRASE" in calls[0][2]
    assert calls[0][2]["Idempotency-Key"].startswith("redline-")


def test_bitget_sponsor_readback_rejects_metric_mismatch(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"draft_id": "draft-1", "version_id": "version-1"}).encode()
        if url.endswith("/api/v1/playbook/run") and method == "POST":
            return 200, json.dumps({"run_id": "run-1", "status": "started"}).encode()
        if "/api/v1/playbook/run?" in url and method == "GET":
            return 200, json.dumps({"run_id": "run-1", "version_id": "version-1", "status": "completed", "metrics_output": {"unexpected": True}}).encode()
        return 404, b"{}"

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    run = adapter.run(version_id=upload.evidence["version_id"])
    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id=upload.evidence["version_id"],
        expected_metrics_output_hash=artifacts.receipt.result.result_hash,
        expected_package_hash=artifacts.receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence["package_archive_hash"],
    )
    assert readback.ok is False
    assert readback.state == SponsorState.MISMATCH
    assert readback.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_bitget_publish_rejects_failed_terminal_status(tmp_path: Path) -> None:
    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert url.endswith("/api/v1/playbook/publish")
        return 200, json.dumps({"code": "00000", "data": {"status": "failed"}}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    adapter.proof_eligible = True
    result = adapter.publish(draft_id="draft-1")
    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_sponsor_evidence_verifier() -> None:
    result = validate_sponsor_evidence_shape(ROOT / "artifacts/sponsor/demo-readback.json")
    assert result.ok is False
    assert result.state == SponsorState.RECORDED_ATTESTATION_VALID
    assert result.reason_code == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED


def test_live_sponsor_readback_verifies_three_recorded_fields(tmp_path: Path) -> None:
    metrics_output = {"status": "pass", "breaches": []}
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": hash_obj(metrics_output),
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": hash_obj(metrics_output),
        "package_hash": "sha256:" + "1" * 64,
        "package_archive_hash": "sha256:" + "2" * 64,
        "source_kind": "recorded",
        "proof_eligible": False,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert method == "GET"
        assert "/api/v1/playbook/run?" in url
        return 200, json.dumps(
            {
                "code": "00000",
                "data": {
                    "run_id": "run-live-1",
                    "version_id": "version-live-1",
                    "status": "completed",
                    "metrics_output": metrics_output,
                    "package_hash": evidence["package_hash"],
                    "package_archive_hash": evidence["package_archive_hash"],
                },
            }
        ).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    adapter.proof_eligible = True
    result = verify_sponsor_readback_evidence(evidence_path=evidence_path, adapter=adapter)
    assert result.ok is True
    assert result.state == SponsorState.READBACK_VERIFIED
    assert result.evidence["run_id"] == "run-live-1"
    assert result.evidence["source_kind"] == "live"
    assert result.evidence["package_hash"] == evidence["package_hash"]


def test_live_sponsor_readback_requires_package_binding(tmp_path: Path) -> None:
    metrics_output = {"status": "pass", "breaches": []}
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": hash_obj(metrics_output),
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": hash_obj(metrics_output),
        "package_hash": "sha256:" + "1" * 64,
        "package_archive_hash": "sha256:" + "2" * 64,
        "source_kind": "recorded",
        "proof_eligible": False,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        return 200, json.dumps(
            {
                "code": "00000",
                "data": {
                    "run_id": "run-live-1",
                    "version_id": "version-live-1",
                    "status": "completed",
                    "metrics_output": metrics_output,
                    "package_hash": "sha256:" + "9" * 64,
                    "package_archive_hash": evidence["package_archive_hash"],
                },
            }
        ).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    adapter.proof_eligible = True
    result = verify_sponsor_readback_evidence(evidence_path=evidence_path, adapter=adapter)
    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_sponsor_run_evidence_binds_expected_receipt_package(tmp_path: Path) -> None:
    data = json.loads((ROOT / "artifacts/sponsor/demo-readback.json").read_text())
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(data), encoding="utf-8")

    class NoPollAdapter:
        proof_eligible = True

        def poll(self, *, run_id: str):
            raise AssertionError("package binding mismatch should be rejected before live poll")

    result = verify_sponsor_readback_evidence(
        evidence_path=evidence_path,
        adapter=NoPollAdapter(),  # type: ignore[arg-type]
        expected_package_hash="sha256:" + "0" * 64,
    )
    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_sponsor_run_evidence_binds_expected_package_archive(tmp_path: Path) -> None:
    data = json.loads((ROOT / "artifacts/sponsor/demo-readback.json").read_text())
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(data), encoding="utf-8")

    class NoPollAdapter:
        proof_eligible = True

        def poll(self, *, run_id: str):
            raise AssertionError("archive binding mismatch should be rejected before live poll")

    result = verify_sponsor_readback_evidence(
        evidence_path=evidence_path,
        adapter=NoPollAdapter(),  # type: ignore[arg-type]
        expected_package_hash=data["package_hash"],
        expected_package_archive_hash="sha256:" + "0" * 64,
        expected_metrics_output_hash=data["expected_metrics_output_hash"],
    )
    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert result.evidence["expected_package_archive_hash"] == "sha256:" + "0" * 64


def test_verify_sponsor_run_cli_binds_annotated_archive(monkeypatch, tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive, _annotation = make_receipt_bound_package_archive(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        annotation_path=tmp_path / "archive" / "redline-annotation.json",
        out_path=tmp_path / "archive" / "annotated-package.tar.gz",
    )
    archive_hash = sha256_bytes(archive.read_bytes())
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": artifacts.receipt.result.result_hash,
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": artifacts.receipt.result.result_hash,
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": archive_hash,
        "source_kind": "live",
        "proof_eligible": True,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    class FakeAdapter:
        proof_eligible = True

        def __init__(self, **kwargs: object) -> None:
            pass

        def poll(self, *, run_id: str) -> SponsorStepResult:
            return SponsorStepResult(
                ok=True,
                state=SponsorState.READBACK_VERIFIED,
                evidence={
                    "run_id": run_id,
                    "version_id": evidence["expected_version_id"],
                    "status": "completed",
                    "metrics_output_hash": evidence["expected_metrics_output_hash"],
                    "package_hash": evidence["package_hash"],
                    "package_archive_hash": evidence["package_archive_hash"],
                },
            )

    monkeypatch.setattr(cli_module, "BitgetSponsorAdapter", FakeAdapter)
    monkeypatch.setenv("REDLINE_BITGET_ACCESS_KEY", "access")
    monkeypatch.setenv("REDLINE_BITGET_SECRET_KEY", "secret")
    monkeypatch.setenv("REDLINE_BITGET_PASSPHRASE", "passphrase")
    result = CliRunner().invoke(
        app,
        [
            "verify-sponsor-run",
            str(evidence_path),
            "--receipt",
            str(tmp_path / "run" / "receipt.json"),
            "--package",
            str(package),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["state"] == SponsorState.READBACK_VERIFIED.value


def test_execute_sponsor_readback_rejects_platform_metric_mismatch(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="sponsor-policy", key_id="sponsor-key", public_key=public_key, issuer="sponsor-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert artifacts.receipt is not None
    _sign_run_checkpoint(tmp_path / "run", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    publish = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert publish.ok is True
    observed_expected_hashes: list[str | None] = []

    class FakeAdapter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def upload(self, *, envelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None):
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.UPLOAD_ACCEPTED,
                evidence={
                    "version_id": "version-1",
                    "draft_id": "draft-1",
                    "package_hash": package_hash,
                    "package_archive_hash": "sha256:" + "4" * 64,
                },
            )

        def run(self, *, version_id: str):
            return surfaces_module.SponsorStepResult(ok=True, state=SponsorState.RUN_STARTED, evidence={"run_id": "run-1"})

        def readback(
            self,
            *,
            run_id: str,
            expected_version_id: str | None = None,
            expected_metrics_output_hash: str | None = None,
            expected_package_hash: str | None = None,
            expected_package_archive_hash: str | None = None,
        ):
            observed_expected_hashes.append(expected_metrics_output_hash)
            return surfaces_module.SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "run_id": run_id,
                    "version_id": expected_version_id or "",
                    "status": "completed",
                    "metrics_output_hash": "sha256:" + "9" * 64,
                    "expected_metrics_output_hash": expected_metrics_output_hash or "",
                    "package_hash": expected_package_hash or "",
                    "package_archive_hash": expected_package_archive_hash or "",
                    "transcript_hash": "sha256:" + "8" * 64,
                },
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", FakeAdapter)
    result = execute_sponsor_readback(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        out_dir=tmp_path / "publish",
        access_key="access",
        secret_key="secret",
        passphrase="pass",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
    )
    assert observed_expected_hashes == [artifacts.receipt.result.result_hash]
    assert result.ok is False
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    sponsor_proofs = sorted((tmp_path / "publish" / "proofs").glob("proof_sponsor_readback_*.json"))
    assert sponsor_proofs
    proof = json.loads(sponsor_proofs[0].read_text())
    assert proof["kind"] == ProofKind.SPONSOR_READBACK.value
    assert proof["meta"]["receipt_hash"] == artifacts.receipt.receipt_hash


def test_execute_sponsor_readback_rejects_tampered_receipt_before_adapter(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="sponsor-policy", key_id="sponsor-key", public_key=public_key, issuer="sponsor-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert artifacts.receipt is not None
    _sign_run_checkpoint(tmp_path / "run", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    publish = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert publish.ok is True

    class AdapterMustNotRun:
        def __init__(self, **kwargs: object) -> None:
            raise AssertionError("tampered receipt must be rejected before adapter creation")

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", AdapterMustNotRun)
    tampered = json.loads((tmp_path / "run" / "receipt.json").read_text())
    tampered["package"]["identity_hash"] = "sha256:" + "0" * 64
    tampered["receipt_hash"] = "sha256:" + "0" * 64
    (tmp_path / "run" / "receipt.json").write_text(json.dumps(tampered), encoding="utf-8")
    result = execute_sponsor_readback(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        out_dir=tmp_path / "publish",
        access_key="access",
        secret_key="secret",
        passphrase="pass",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
    )
    assert result.ok is False
    assert result.state == SponsorState.LOCAL_PASS_REQUIRED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_execute_sponsor_readback_rejects_genesis_before_adapter(monkeypatch, tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    publish = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        allow_demo_baseline_genesis=True,
    )
    assert publish.ok is True

    class AdapterMustNotRun:
        def __init__(self, **kwargs: object) -> None:
            raise AssertionError("genesis sponsor execution must be rejected before adapter creation")

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", AdapterMustNotRun)
    result = execute_sponsor_readback(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=PACKAGE,
        out_dir=tmp_path / "publish",
        access_key="access",
        secret_key="secret",
        passphrase="pass",
    )
    assert result.ok is False
    assert result.state == SponsorState.LOCAL_PASS_REQUIRED
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_verify_sponsor_run_cli_requires_credentials(monkeypatch, tmp_path: Path) -> None:
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        monkeypatch.delenv(key, raising=False)
    result = CliRunner().invoke(app, ["verify-sponsor-run", str(ROOT / "artifacts/sponsor/demo-readback.json"), "--json"])
    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "BITGET_CREDENTIALS_REQUIRED"
    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)
    schema = json.loads((schema_dir / "sponsor-step-result.v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)


def test_verify_sponsor_script_emits_single_json_document(monkeypatch) -> None:
    env = os.environ.copy()
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        env.pop(key, None)
    result = subprocess.run(
        [
            str(ROOT / "scripts/verify-sponsor-run.sh"),
            "artifacts/sponsor/demo-readback.json",
            "artifacts/demo/pass/receipt.json",
            "fixtures/demo_pack",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 6
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "redline.sponsor.verify_script.v1"
    assert payload["receipt_exit_code"] == 10
    assert payload["sponsor_exit_code"] == 6
    assert payload["receipt_check"]["schema_version"] == "redline.verify.v1"
    assert payload["sponsor_readback"]["state"] == "BITGET_CREDENTIALS_REQUIRED"


def test_verify_sponsor_run_cli_checks_evidence_before_credentials(monkeypatch, tmp_path: Path) -> None:
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        monkeypatch.delenv(key, raising=False)
    result = CliRunner().invoke(app, ["verify-sponsor-run", str(tmp_path / "missing-evidence.json"), "--json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["state"] == SponsorState.MISMATCH.value
    assert payload["reason_code"] == ReasonCode.SCHEMA_INVALID.value


def test_trust_cli_bad_inputs_return_typed_json(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_policy = runner.invoke(
        app,
        [
            "trust-policy",
            "--public-key",
            "not-a-key",
            "--key-id",
            "k",
            "--issuer",
            "i",
            "--out",
            str(tmp_path / "bad-policy.json"),
            "--json",
        ],
    )
    assert bad_policy.exit_code == 2
    assert json.loads(bad_policy.stdout)["reason_code"] == ReasonCode.SCHEMA_INVALID.value

    missing_checkpoint = runner.invoke(
        app,
        [
            "sign-ledger-checkpoint",
            str(tmp_path / "missing-checkpoint.json"),
            "--private-key",
            "not-a-key",
            "--json",
        ],
    )
    assert missing_checkpoint.exit_code == 2
    assert json.loads(missing_checkpoint.stdout)["reason_code"] == ReasonCode.FILE_NOT_FOUND.value

    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text("{not json", encoding="utf-8")
    bad_attestation = tmp_path / "attestation.json"
    bad_attestation.write_text("{not json", encoding="utf-8")
    verify_bad_json = runner.invoke(app, ["verify-ledger-attestation", str(bad_attestation), str(checkpoint), "--json"])
    assert verify_bad_json.exit_code == 2
    assert json.loads(verify_bad_json.stdout)["reason_code"] == ReasonCode.PARSE_ERROR.value


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
        "ledger-attestation.v1.schema.json",
        "ledger-checkpoint.v1.schema.json",
        "package-annotation.v1.schema.json",
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


def test_checked_in_schemas_match_exported_models(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    checked_in = ROOT / "schemas"
    for exported in sorted(tmp_path.iterdir()):
        assert (checked_in / exported.name).read_text(encoding="utf-8") == exported.read_text(encoding="utf-8")


def test_generated_reports_validate_against_exported_schema(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)
    schema = json.loads((schema_dir / "report.v1.schema.json").read_text())
    Draft202012Validator(schema).validate(json.loads((tmp_path / "run" / "report.json").read_text()))


def test_composite_action_runs_against_caller_workspace() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert 'allow-amber-baseline-genesis:' in action
    assert 'default: "false"' in action
    assert "working-directory: ${{ github.workspace }}" in action
    assert 'uv --project "${{ github.action_path }}" run redline run "${{ github.workspace }}/${{ inputs.package }}"' in action
    assert "path: ${{ github.workspace }}/${{ inputs.out }}" in action


def test_decision_envelope_construction_stays_in_proof_kernel() -> None:
    offenders = []
    for path in sorted((ROOT / "src/redline").glob("*.py")):
        if path.name in {"models.py", "proof_kernel.py"}:
            continue
        if "DecisionEnvelope(" in path.read_text(encoding="utf-8"):
            offenders.append(path.name)
    assert offenders == []


def test_proof_reproduce_commands_are_valid_shape(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    for proof in artifacts.receipt.proofs:
        assert proof.reproduce is not None
        assert proof.reproduce.startswith("uv run redline verify-proof receipt.json --proof-id ")
        assert "--package <package> --suite <suite> --spec <spec>" in proof.reproduce


def test_receipt_write_removes_receipt_when_ledger_write_fails(monkeypatch, tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=None)
    assert artifacts.receipt is not None

    def fail_append(*args, **kwargs):
        raise OSError("simulated ledger write failure")

    monkeypatch.setattr(receipt_module, "_append_ledger", fail_append)
    receipt_path = tmp_path / "receipt.json"
    try:
        atomic_write_receipt(receipt_path, artifacts.receipt, ledger_path=tmp_path / "issuance-ledger.jsonl")
    except OSError:
        pass
    else:
        raise AssertionError("ledger write failure must propagate")
    assert not receipt_path.exists()


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


def test_anti_reroll_ledger_rejects_same_status_reroll(tmp_path: Path) -> None:
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
    ledger.write_text(
        json.dumps({"key_hash": key_hash, "status": receipt.result.status, "receipt_hash": "sha256:" + "0" * 64}) + "\n",
        encoding="utf-8",
    )
    try:
        atomic_write_receipt(tmp_path / "receipt.json", receipt, ledger_path=ledger)
    except IssuanceLedgerConflict:
        pass
    else:
        raise AssertionError("same-key historical verdict must block receipt issuance")
    assert not (tmp_path / "receipt.json").exists()
