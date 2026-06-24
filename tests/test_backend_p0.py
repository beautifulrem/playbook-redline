from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
from decimal import Decimal
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from typer.testing import CliRunner

import redline.surfaces as surfaces_module
import redline.receipt as receipt_module
import redline.cli as cli_module
import redline.sponsor.bitget as bitget_module
import redline.runner as runner_module

from redline.canonical import CanonicalizationError, canonical_number, hash_file, hash_obj, hash_tree, sha256_bytes
from redline.cli import app
from redline.engine_adapter import DeterministicReplayEngine
from redline.engine_adapter.deterministic import build_worker_command
from redline.models import (
    Assertion,
    Capabilities,
    ChainStatus,
    CoverageManifest,
    DecisionContext,
    DecisionEnvelope,
    LedgerCheckpoint,
    PackageAnnotation,
    Proof,
    ProbeOutcome,
    ProbeResult,
    ProbeSpec,
    ProbeType,
    ProofKind,
    ReasonCode,
    ReportJson,
    Receipt,
    ReplayPoint,
    ReplayTrace,
    Scenario,
    Status,
    VerdictTier,
    VerificationLevel,
    VerificationStatus,
)
from redline.package_identity import build_identity_lock, identity_lock_path, load_identity_lock, write_identity_lock
from redline.probes import PROBE_REGISTRY, TRUSTED_PROBE_EVALUATE
from redline.probes.drawdown import MaxDrawdownProbe
from redline.proof_kernel import REQUIRED_PROOFS, decide, decision_proof_id
from redline.receipt import IssuanceLedgerConflict, atomic_write_receipt, compute_receipt_hash, create_ledger_checkpoint, make_decision_proof
from redline.runner import load_spec, load_suite, run_redline
from redline.schemas import export_schemas
from redline.spec_compiler import OutOfScopeError
from redline.sponsor.bitget import BitgetSponsorAdapter, SponsorState, SponsorStepResult, make_package_archive, validate_sponsor_evidence_shape, verify_sponsor_readback_evidence
from redline.mcp_server import build_server, redline_check_receipt, redline_compile_spec, redline_export_if_clean, redline_import_playbook, redline_run_suite, redline_verify_receipt
from redline.merkle import merkle_proof, merkle_root, verify_inclusion
from redline.render import HONEST_STATEMENT, load_evidence_panel, render_evidence_comparison_html
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
from redline.trust import generate_trust_keypair, make_trust_policy, sign_checkpoint, verify_checkpoint_attestation, verify_trust_policy
from redline.tripwire import VerdictPathViolation, verdict_path_tripwire
from redline.verifier import load_receipt, verify, verify_proof

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


def _receipt_key_hash(receipt: Receipt) -> str:
    return hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )


def _make_probe_trace(positions: list[str], *, scenario_id: str = "btc-crash-2024-03-05") -> ReplayTrace:
    decimal_positions = [Decimal(position) for position in positions]
    points = [
        ReplayPoint(
            bar=index,
            timestamp=f"2026-01-01T{index:02d}:00:00Z",
            close=Decimal("100"),
            nav=Decimal("10000"),
            peak=Decimal("10000"),
            drawdown=Decimal("0"),
            position=position,
        )
        for index, position in enumerate(decimal_positions)
    ]
    trade_count = sum(Decimal("1") for index in range(1, len(decimal_positions)) if decimal_positions[index] != decimal_positions[index - 1])
    trace_without_hash = {
        "scenario_id": scenario_id,
        "role": "candidate",
        "engine": "deterministic",
        "bars": len(points),
        "trade_count": int(trade_count),
        "points": points,
        "input_hash": hash_obj({"scenario_id": scenario_id, "positions": positions}),
    }
    return ReplayTrace(**trace_without_hash, artifact_hash=hash_obj(trace_without_hash))


def _rewrite_ledger_for_receipt(run_dir: Path, receipt: Receipt) -> None:
    ledger_path = run_dir / "issuance-ledger.jsonl"
    key_hash = _receipt_key_hash(receipt)
    previous_entry_hash = "sha256:genesis"
    rewritten: list[dict[str, object]] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        entry["previous_entry_hash"] = previous_entry_hash
        if entry.get("key_hash") == key_hash:
            entry["receipt_hash"] = receipt.receipt_hash
            entry["status"] = receipt.result.status
        entry["entry_hash"] = hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
        rewritten.append(entry)
        previous_entry_hash = str(entry["entry_hash"])
    ledger_path.write_text("".join(json.dumps(entry, sort_keys=True) + "\n" for entry in rewritten), encoding="utf-8")
    create_ledger_checkpoint(
        ledger_path=ledger_path,
        checkpoint_path=run_dir / "issuance-ledger.checkpoint.json",
        subject_receipt_hashes=[receipt.receipt_hash],
        ledger_path_label="issuance-ledger.jsonl",
    )


def _append_duplicate_ledger_key_and_resign(run_dir: Path, private_key: str, *, policy_id: str, key_id: str, issuer: str) -> None:
    receipt = load_receipt(run_dir / "receipt.json")
    ledger_path = run_dir / "issuance-ledger.jsonl"
    lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    last_entry = json.loads(lines[-1])
    duplicate = {
        "key_hash": _receipt_key_hash(receipt),
        "status": receipt.result.status,
        "receipt_hash": "sha256:" + "1" * 64,
        "previous_entry_hash": last_entry["entry_hash"],
        "written_at": "2026-06-10T00:00:01Z",
    }
    duplicate["entry_hash"] = hash_obj(duplicate)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(duplicate, sort_keys=True))
        fh.write("\n")
    create_ledger_checkpoint(
        ledger_path=ledger_path,
        checkpoint_path=run_dir / "issuance-ledger.checkpoint.json",
        subject_receipt_hashes=[receipt.receipt_hash],
        ledger_path_label="issuance-ledger.jsonl",
    )
    _sign_run_checkpoint(run_dir, private_key, policy_id=policy_id, key_id=key_id, issuer=issuer)


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
    _sign_run_checkpoint(tmp_path / "run", private_key, policy_id=policy_id, key_id=key_id, issuer=issuer)
    return package, chained


def test_receipt_prev_hash_chain_continuous(tmp_path: Path) -> None:
    _package, chained = _make_chained_pass_fixture(tmp_path)
    assert chained.receipt is not None
    baseline_receipt = load_receipt(tmp_path / "baseline" / "receipt.json")
    chained_receipt = load_receipt(tmp_path / "run" / "receipt.json")

    assert baseline_receipt.prev_receipt_hash == "sha256:genesis"
    assert chained_receipt.baseline.baseline_receipt_hash == baseline_receipt.receipt_hash
    assert chained_receipt.prev_receipt_hash == baseline_receipt.receipt_hash

    tampered = chained_receipt.model_copy(update={"prev_receipt_hash": "sha256:" + "f" * 64})
    assert compute_receipt_hash(tampered) != chained_receipt.receipt_hash


def test_prev_hash_missing_old_receipt_defaults_to_genesis(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None

    legacy_payload = json.loads((tmp_path / "run" / "receipt.json").read_text(encoding="utf-8"))
    legacy_payload.pop("prev_receipt_hash", None)
    legacy_payload["receipt_hash"] = ""
    legacy_hash = compute_receipt_hash(Receipt.model_validate(legacy_payload))
    legacy_payload["receipt_hash"] = legacy_hash

    legacy_receipt = Receipt.model_validate(legacy_payload)

    assert legacy_receipt.prev_receipt_hash == "sha256:genesis"
    assert "prev_receipt_hash" not in legacy_receipt.model_fields_set
    assert compute_receipt_hash(legacy_receipt) == legacy_hash


def test_merkle_root_and_inclusion_proofs_are_deterministic() -> None:
    leaves = [
        "sha256:" + "1" * 64,
        {"receipt_hash": "sha256:" + "2" * 64, "kind": "approval"},
        ["execution", "sha256:" + "3" * 64],
    ]

    root = merkle_root(leaves)

    assert root.startswith("sha256:")
    assert root == merkle_root(tuple(leaves))
    assert root != merkle_root(list(reversed(leaves)))
    assert merkle_root([]) == "sha256:genesis"
    for index, leaf in enumerate(leaves):
        proof = merkle_proof(leaves, index)
        assert verify_inclusion(leaf, index, proof, root, leaf_count=len(leaves))


def test_merkle_inclusion_rejects_tampered_leaf_path_or_root() -> None:
    leaves = ["sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64]
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 2)

    assert verify_inclusion(leaves[2], 2, proof, root, leaf_count=len(leaves))
    assert not verify_inclusion("sha256:" + "d" * 64, 2, proof, root, leaf_count=len(leaves))
    assert not verify_inclusion(leaves[2], 1, proof, root, leaf_count=len(leaves))
    assert not verify_inclusion(leaves[2], 2, [{"side": "left", "hash": "sha256:" + "0" * 64}, *proof[1:]], root, leaf_count=len(leaves))
    assert not verify_inclusion(leaves[2], 2, proof, "sha256:" + "f" * 64, leaf_count=len(leaves))
    assert not verify_inclusion(leaves[2], 2, proof, root, leaf_count=2)
    with pytest.raises(IndexError):
        merkle_proof(leaves, 3)


def test_merkle_checkpoint_root_covers_subject_receipt_hashes(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt = load_receipt(tmp_path / "run" / "receipt.json")
    extra_receipt_hash = "sha256:" + "9" * 64

    checkpoint = create_ledger_checkpoint(
        ledger_path=tmp_path / "run" / "issuance-ledger.jsonl",
        subject_receipt_hashes=[receipt.receipt_hash, extra_receipt_hash],
        ledger_path_label="issuance-ledger.jsonl",
    )

    expected_subjects = sorted({receipt.receipt_hash, extra_receipt_hash})
    assert checkpoint.subject_receipt_hashes == expected_subjects
    assert checkpoint.merkle_root == merkle_root(expected_subjects)
    tampered = checkpoint.model_copy(update={"merkle_root": merkle_root([receipt.receipt_hash])})
    assert hash_obj(tampered.model_copy(update={"checkpoint_hash": ""})) != checkpoint.checkpoint_hash


def test_merkle_checkpoint_verifier_rejects_recomputed_wrong_root(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    checkpoint_path = tmp_path / "run" / "issuance-ledger.checkpoint.json"
    checkpoint_data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint_data["merkle_root"] = merkle_root(["sha256:" + "0" * 64])
    forged = LedgerCheckpoint.model_validate(checkpoint_data)
    checkpoint_data["checkpoint_hash"] = hash_obj(forged.model_copy(update={"checkpoint_hash": ""}))
    checkpoint_path.write_text(json.dumps(checkpoint_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = verify(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )

    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


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


@settings(max_examples=25, deadline=None)
@given(
    st.dictionaries(
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=12),
        st.one_of(st.integers(min_value=-10_000, max_value=10_000), st.booleans(), st.none()),
        min_size=1,
        max_size=8,
    )
)
def test_hash_obj_is_order_equivalent(payload: dict[str, object]) -> None:
    forward = dict(payload.items())
    reverse = dict(reversed(list(payload.items())))
    assert hash_obj(forward) == hash_obj(reverse)


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


def test_tape_source_hash_tamper_rejects(tmp_path: Path) -> None:
    shutil.copytree(SUITE.parent, tmp_path / "suites")
    suite_path = tmp_path / "suites" / "demo_suite.json"
    suite_data = json.loads(suite_path.read_text(encoding="utf-8"))
    suite_data["suite_lock_hash"] = None
    suite_path.write_text(json.dumps(suite_data), encoding="utf-8")
    suite = load_suite(suite_path)

    for scenario in suite.scenarios:
        assert scenario.source_file_hash == hash_file(Path(scenario.path))
        assert scenario.source_file_hash == scenario.data_hash

    locked = json.loads(suite_path.read_text(encoding="utf-8"))
    locked["suite_lock_hash"] = None
    for scenario in locked["scenarios"]:
        loaded = next(item for item in suite.scenarios if item.id == scenario["id"])
        scenario["source_file_hash"] = loaded.source_file_hash
    suite_path.write_text(json.dumps(locked), encoding="utf-8")
    csv_path = tmp_path / "suites" / "btc_chop.csv"
    csv_path.write_text(csv_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="source_file_hash mismatch"):
        load_suite(suite_path)


def test_probe_unauthorized_order_passes_and_breaches() -> None:
    ProbeSpec(
        id="unauthorized_order",
        type=ProbeType.UNAUTHORIZED_ORDER,
        params={"scenario_id": "btc-crash-2024-03-05", "max_abs_position": "1", "allowed_side": "long_only"},
    )
    probe = PROBE_REGISTRY[ProbeType.UNAUTHORIZED_ORDER]
    baseline = _make_probe_trace(["0", "0", "0"])

    passing = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["0", "0.5", "1"]),
        params={"scenario_id": "btc-crash-2024-03-05", "max_abs_position": "1", "allowed_side": "long_only"},
    )
    size_breach = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["0", "1.5", "1"]),
        params={"scenario_id": "btc-crash-2024-03-05", "max_abs_position": "1", "allowed_side": "long_only"},
    )
    side_breach = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["0", "-0.1", "0"]),
        params={"scenario_id": "btc-crash-2024-03-05", "max_abs_position": "1", "allowed_side": "long_only"},
    )

    assert passing.outcome == ProbeOutcome.PASS
    assert size_breach.outcome == ProbeOutcome.BREACH
    assert size_breach.assertions[0].metric == "unauthorized_order_size"
    assert side_breach.outcome == ProbeOutcome.BREACH
    assert side_breach.assertions[0].metric == "unauthorized_order_side"


def test_probe_skip_confirm_passes_and_breaches() -> None:
    ProbeSpec(
        id="skip_confirm",
        type=ProbeType.SKIP_CONFIRM,
        params={"scenario_id": "btc-crash-2024-03-05", "confirm_bar": "2", "max_abs_position": "0"},
    )
    probe = PROBE_REGISTRY[ProbeType.SKIP_CONFIRM]
    baseline = _make_probe_trace(["0", "0", "0", "0"])

    passing = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["1", "1", "0", "0"]),
        params={"scenario_id": "btc-crash-2024-03-05", "confirm_bar": "2", "max_abs_position": "0"},
    )
    breach = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["1", "1", "0.5", "0"]),
        params={"scenario_id": "btc-crash-2024-03-05", "confirm_bar": "2", "max_abs_position": "0"},
    )

    assert passing.outcome == ProbeOutcome.PASS
    assert breach.outcome == ProbeOutcome.BREACH
    assert breach.evidence_bar == 2
    assert breach.assertions[0].metric == "skip_confirm"


def test_probe_blind_retry_passes_and_breaches() -> None:
    ProbeSpec(
        id="blind_retry",
        type=ProbeType.BLIND_RETRY,
        params={"scenario_id": "btc-crash-2024-03-05", "retry_after_bar": "1", "max_retries": "1"},
    )
    probe = PROBE_REGISTRY[ProbeType.BLIND_RETRY]
    baseline = _make_probe_trace(["0", "0", "0", "0"])

    passing = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["0", "1", "1", "1"]),
        params={"scenario_id": "btc-crash-2024-03-05", "retry_after_bar": "1", "max_retries": "1"},
    )
    breach = probe.evaluate(
        baseline=baseline,
        candidate=_make_probe_trace(["0", "1", "0", "1"]),
        params={"scenario_id": "btc-crash-2024-03-05", "retry_after_bar": "1", "max_retries": "1"},
    )

    assert passing.outcome == ProbeOutcome.PASS
    assert breach.outcome == ProbeOutcome.BREACH
    assert breach.evidence_bar == 2
    assert breach.assertions[0].metric == "blind_retry"


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


def test_package_archive_output_must_stay_outside_package(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    with pytest.raises(CanonicalizationError) as exc:
        make_package_archive(package_dir=package, out_path=package / "package.tar.gz")
    assert exc.value.reason_code == ReasonCode.RECEIPT_BINDING_FAILED


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
    write_identity_lock(package)
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
    write_identity_lock(package)
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


def test_candidate_allowed_module_dunder_reexport_eval_bypass_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_decimal_builtins_eval")
    (package / "candidate_decimal_builtins_eval" / "strategy.py").write_text(
        "from decimal import __builtins__ as b\n\n"
        "e = b['ev' + 'al']\n\n"
        "def signal(bar, state, config):\n"
        "    return e('(id(object()) // 16384) % 2')\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_decimal_builtins_eval",
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
    write_identity_lock(package)
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
    write_identity_lock(package)
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


def test_candidate_pathlib_metadata_read_is_sandbox_violation(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_pathlib_metadata")
    (package / "candidate_pathlib_metadata" / "strategy.py").write_text(
        "from pathlib import Path\n\n"
        "def signal(bar, state, config):\n"
        "    state['outside_root_entries'] = [path.name for path in Path('/').iterdir()][:3]\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_pathlib_metadata",
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


def test_replayed_rejects_forged_runner_identity_even_when_hashes_recomputed(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "run" / "receipt.json"
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    data["runner"]["engine_source_tree_hash"] = "sha256:" + "0" * 64
    data["runner"]["runner_lock_hash"] = "sha256:" + "1" * 64
    forged = Receipt.model_validate(data)
    forged = forged.model_copy(update={"receipt_hash": compute_receipt_hash(forged)})
    receipt_path.write_text(forged.model_dump_json(indent=2) + "\n", encoding="utf-8")
    _rewrite_ledger_for_receipt(tmp_path / "run", forged)

    result = verify(receipt_path=receipt_path, package=package, suite_path=SUITE, spec_path=SPEC, level=VerificationLevel.REPLAYED)

    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.ENGINE_IDENTITY_MISMATCH


def test_runner_lock_hash_ignores_python_patch_version(monkeypatch) -> None:
    class VersionInfo:
        def __init__(self, *, major: int, minor: int, micro: int) -> None:
            self.major = major
            self.minor = minor
            self.micro = micro

    engine_hash = "sha256:" + "a" * 64
    monkeypatch.setattr(runner_module.sys, "version_info", VersionInfo(major=3, minor=12, micro=1))
    first = runner_module._runner_lock_hash(engine_hash)
    monkeypatch.setattr(runner_module.sys, "version_info", VersionInfo(major=3, minor=12, micro=99))
    second = runner_module._runner_lock_hash(engine_hash)
    monkeypatch.setattr(runner_module.sys, "version_info", VersionInfo(major=3, minor=13, micro=0))
    third = runner_module._runner_lock_hash(engine_hash)

    assert first == second
    assert first != third


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


@pytest.mark.parametrize("missing_kind", sorted(REQUIRED_PROOFS[Status.PASS], key=lambda item: item.value))
def test_pass_receipt_rejects_missing_each_required_verdict_proof_kind(tmp_path: Path, missing_kind: ProofKind) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    receipt_path = tmp_path / "receipt.json"
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    removed = [proof["proof_id"] for proof in data["proofs"] if proof["kind"] == missing_kind.value and proof["verdict_bearing"]]
    assert removed
    data["proofs"] = [proof for proof in data["proofs"] if proof["proof_id"] not in removed]
    data["receipt_hash"] = compute_receipt_hash(Receipt.model_validate(data))
    receipt_path.write_text(json.dumps(data), encoding="utf-8")

    result = verify(receipt_path=receipt_path, level=VerificationLevel.HASH_ONLY)

    assert result.status == VerificationStatus.UNVERIFIED_NO_VERDICT
    assert result.reason_code == ReasonCode.UNVERIFIED_NO_VERDICT
    assert missing_kind.value in result.missing_proof_ids or any(proof_id in result.missing_proof_ids for proof_id in removed)


def test_partial_coverage_never_passes() -> None:
    coverage = CoverageManifest(cells=[("scenario", "probe")], complete=False, missing=["scenario:probe"])
    envelope = decide(proofs=[], coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x"))
    assert envelope.status == Status.UNVERIFIED_NO_VERDICT
    assert envelope.reason_code == ReasonCode.COVERAGE_INCOMPLETE


def test_complete_coverage_requires_probe_proof_for_each_cell() -> None:
    def proof(kind: ProofKind, *, assertions: list[Assertion] | None = None, meta: dict[str, object] | None = None) -> Proof:
        artifact_hash = hash_obj({"kind": kind.value, "assertions": [item.model_dump(mode="json") for item in assertions or []], "meta": meta or {}})
        return Proof(
            proof_id=f"proof:{kind.value}:{artifact_hash.removeprefix('sha256:')[:24]}",
            phase="test",
            kind=kind,
            verdict_bearing=True,
            inputs_hash=artifact_hash,
            artifact_hash=artifact_hash,
            assertions=assertions or [],
            meta=meta or {},
        )

    assertion = Assertion(metric="max_drawdown", op="<=", threshold="0.08", observed="0.01", scenario_id="s1", bar=1, holds=True)
    proofs = [
        proof(kind, assertions=[assertion] if kind is ProofKind.PROBE else [], meta={"scenario_id": "s1", "probe_id": "p1"} if kind is ProofKind.PROBE else {})
        for kind in REQUIRED_PROOFS[Status.PASS]
        if kind is not ProofKind.DECISION
    ]
    coverage = CoverageManifest(cells=[("s1", "p1"), ("s2", "p1")], complete=True, missing=[])
    envelope = decide(proofs=proofs, coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x", chain_status=ChainStatus.CHAINED))

    assert envelope.status == Status.UNVERIFIED_NO_VERDICT
    assert envelope.reason_code == ReasonCode.COVERAGE_INCOMPLETE
    assert envelope.coverage.complete is False
    assert envelope.coverage.missing == ["s2:p1:missing_probe_proof"]


def test_reduce_size_tier_caps_position() -> None:
    def proof(kind: ProofKind, *, assertions: list[Assertion] | None = None, meta: dict[str, object] | None = None) -> Proof:
        artifact_hash = hash_obj({"kind": kind.value, "assertions": [item.model_dump(mode="json") for item in assertions or []], "meta": meta or {}})
        return Proof(
            proof_id=f"proof:{kind.value}:{artifact_hash.removeprefix('sha256:')[:24]}",
            phase="test",
            kind=kind,
            verdict_bearing=True,
            inputs_hash=artifact_hash,
            artifact_hash=artifact_hash,
            assertions=assertions or [],
            meta=meta or {},
        )

    breach = Assertion(metric="max_drawdown", op="<=", threshold="0.08", observed="0.16", scenario_id="s1", bar=7, holds=False)
    proofs = [
        proof(
            kind,
            assertions=[breach] if kind is ProofKind.PROBE else [],
            meta={"scenario_id": "s1", "probe_id": "p1", "breach_action": "reduce_size", "adjusted_size_cap": "0.5"} if kind is ProofKind.PROBE else {},
        )
        for kind in REQUIRED_PROOFS[Status.REDUCE_SIZE]
        if kind is not ProofKind.DECISION
    ]
    coverage = CoverageManifest(cells=[("s1", "p1")], complete=True, missing=[])

    envelope = decide(proofs=proofs, coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x", chain_status=ChainStatus.CHAINED))

    assert envelope.status == Status.REDUCE_SIZE
    assert envelope.verdict_tier == VerdictTier.REDUCE_SIZE
    assert envelope.adjusted_size_cap == "0.5"
    assert envelope.reason_code == ReasonCode.NEW_BLOCK_BREACH
    assert any(proof_id.startswith("proof:decision:") for proof_id in envelope.required_proof_ids)

    receipt = receipt_module.issue_receipt(
        envelope=envelope,
        proofs=proofs,
        coverage=coverage,
        package_hash="sha256:package",
        baseline_name="baseline",
        baseline_hash="sha256:baseline",
        candidate_name="candidate",
        candidate_hash="sha256:candidate",
        spec_hash="sha256:spec",
        spec_source_path="fixtures/specs/redline_spec.json",
        suite_id="suite",
        scenario_ids=["s1"],
        suite_lock_hash="sha256:suite",
        suite_source_path="fixtures/suites/demo_suite.json",
        engine_source_tree_hash="sha256:engine",
        runner_lock_hash="sha256:runner",
        package_adapter_id="python_strategy_sandbox",
        package_identity_lock_hash="sha256:identity-lock",
        package_identity_lock_path="playbook_identity.lock",
    )
    assert receipt is not None
    assert receipt.result.status == Status.REDUCE_SIZE
    assert receipt.decision.verdict_tier == VerdictTier.REDUCE_SIZE
    assert receipt.decision.adjusted_size_cap == "0.5"


def test_reduce_size_requires_explicit_probe_metadata() -> None:
    def proof(kind: ProofKind, *, assertions: list[Assertion] | None = None, meta: dict[str, object] | None = None) -> Proof:
        artifact_hash = hash_obj({"kind": kind.value, "assertions": [item.model_dump(mode="json") for item in assertions or []], "meta": meta or {}})
        return Proof(
            proof_id=f"proof:{kind.value}:{artifact_hash.removeprefix('sha256:')[:24]}",
            phase="test",
            kind=kind,
            verdict_bearing=True,
            inputs_hash=artifact_hash,
            artifact_hash=artifact_hash,
            assertions=assertions or [],
            meta=meta or {},
        )

    breach = Assertion(metric="max_drawdown", op="<=", threshold="0.08", observed="0.16", scenario_id="s1", bar=7, holds=False)
    proofs = [
        proof(kind, assertions=[breach] if kind is ProofKind.PROBE else [], meta={"scenario_id": "s1", "probe_id": "p1"} if kind is ProofKind.PROBE else {})
        for kind in REQUIRED_PROOFS[Status.WITHHELD]
        if kind is not ProofKind.DECISION
    ]
    coverage = CoverageManifest(cells=[("s1", "p1")], complete=True, missing=[])

    envelope = decide(proofs=proofs, coverage=coverage, context=DecisionContext(suite_id="suite", spec_hash="sha256:x", chain_status=ChainStatus.CHAINED))

    assert envelope.status == Status.WITHHELD
    assert envelope.verdict_tier == VerdictTier.BLOCK
    assert envelope.adjusted_size_cap is None


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


def test_probe_parameter_semantics_are_schema_invalid(tmp_path: Path) -> None:
    spec_data = json.loads(SPEC.read_text())
    spec_data["probes"][0]["params"]["max_drawdown"] = "999"
    bad_drawdown_spec = tmp_path / "bad-drawdown-spec.json"
    bad_drawdown_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(bad_drawdown_spec)

    spec_data = json.loads(SPEC.read_text())
    spec_data["probes"][2]["params"]["max_trades"] = "999999"
    bad_budget_spec = tmp_path / "bad-budget-spec.json"
    bad_budget_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(bad_budget_spec)

    spec_data = json.loads(SPEC.read_text())
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"]["before_bar"] = "not-an-int"
            probe["params"]["bar_lt"] = "4"
    bad_alias_spec = tmp_path / "bad-alias-spec.json"
    bad_alias_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(bad_alias_spec)

    spec_data = json.loads(SPEC.read_text())
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"].pop("before_bar", None)
            probe["params"]["bar_lt"] = "3.0"
    bad_decimal_alias_spec = tmp_path / "bad-decimal-alias-spec.json"
    bad_decimal_alias_spec.write_text(json.dumps(spec_data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_spec(bad_decimal_alias_spec)

    text_spec = tmp_path / "unsafe-redline.txt"
    text_spec.write_text("Max drawdown <= 999%; no entry before bar 3; trade budget 20.", encoding="utf-8")
    with pytest.raises(ValidationError):
        compile_spec(text_spec)


def test_no_entry_when_unknown_scenario_fails_closed(tmp_path: Path) -> None:
    spec_data = json.loads(SPEC.read_text())
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"]["scenario_id"] = "not-in-suite"
    spec_path = tmp_path / "unknown-scenario-spec.json"
    spec_path.write_text(json.dumps(spec_data), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown scenario_id"):
        run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=spec_path, out_dir=tmp_path / "run")


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
    schema = json.loads((tmp_path / "spec.v2.2.schema.json").read_text(encoding="utf-8"))
    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    for probe in spec_data["probes"]:
        probe["block"] = False
    errors = list(Draft202012Validator(schema).iter_errors(spec_data))
    assert errors


def test_exported_spec_schema_rejects_probe_parameter_bounds(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    schema = json.loads((tmp_path / "spec.v2.2.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    def assert_rejected(spec_data: dict[str, object]) -> None:
        assert list(validator.iter_errors(spec_data))

    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    spec_data["probes"][0]["params"]["max_drawdown"] = "999"
    assert_rejected(spec_data)

    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    spec_data["probes"][2]["params"]["max_trades"] = "999999"
    assert_rejected(spec_data)

    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"]["before_bar"] = "not-an-int"
            probe["params"]["bar_lt"] = "4"
    assert_rejected(spec_data)

    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"].pop("before_bar", None)
            probe["params"]["bar_lt"] = "3.0"
    assert_rejected(spec_data)

    spec_data = json.loads(SPEC.read_text(encoding="utf-8"))
    spec_data["version"] = "redline.spec.v2.2"
    for probe in spec_data["probes"]:
        if probe["type"] == "no_entry_when":
            probe["params"]["scenario_id"] = "not-in-suite"
    assert_rejected(spec_data)


def test_exported_schemas_disclose_runtime_unique_id_constraints(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    spec_schema = json.loads((tmp_path / "spec.v2.2.schema.json").read_text(encoding="utf-8"))
    suite_schema = json.loads((tmp_path / "suite.v2.schema.json").read_text(encoding="utf-8"))
    assert spec_schema["properties"]["probes"]["x-unique-by"] == "id"
    assert spec_schema["properties"]["probes"]["x-runtime-constraints"][0]["name"] == "unique_probe_ids"
    assert suite_schema["properties"]["scenarios"]["x-unique-by"] == "id"
    assert suite_schema["properties"]["scenarios"]["x-runtime-constraints"][0]["name"] == "unique_scenario_ids"


def test_spec_v22_compiler_exports_execution_cost_contract(tmp_path: Path) -> None:
    text_spec = tmp_path / "risk-policy.txt"
    text_spec.write_text("Max drawdown <= 10%; trade budget <= 4.", encoding="utf-8")

    compiled = compile_spec(text_spec)

    assert compiled.version == "redline.spec.v2.2"
    assert compiled.fill_model == "next_bar_open"
    assert compiled.fee_bps == "0"
    assert compiled.slippage_bps == "0"

    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)
    schema = json.loads((schema_dir / "spec.v2.2.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    payload = compiled.model_dump(mode="json")
    validator.validate(payload)
    assert schema["properties"]["fill_model"]["const"] == "next_bar_open"

    invalid_fill_model = {**payload, "fill_model": "same_bar_close"}
    assert list(validator.iter_errors(invalid_fill_model))
    invalid_fee = {**payload, "fee_bps": "-1"}
    assert list(validator.iter_errors(invalid_fee))
    invalid_slippage = {**payload, "slippage_bps": "10000.1"}
    assert list(validator.iter_errors(invalid_slippage))


def test_spec_v22_execution_cost_params_feed_replay(tmp_path: Path) -> None:
    zero_cost_spec = json.loads(SPEC.read_text(encoding="utf-8"))
    zero_cost_spec["version"] = "redline.spec.v2.2"
    zero_cost_spec["fee_bps"] = "0"
    zero_cost_spec["slippage_bps"] = "0"
    zero_cost_spec["fill_model"] = "next_bar_open"
    zero_cost_path = tmp_path / "zero-cost-spec.json"
    zero_cost_path.write_text(json.dumps(zero_cost_spec, sort_keys=True), encoding="utf-8")

    costed_spec = {**zero_cost_spec, "fee_bps": "10", "slippage_bps": "20"}
    costed_path = tmp_path / "costed-spec.json"
    costed_path.write_text(json.dumps(costed_spec, sort_keys=True), encoding="utf-8")

    zero_cost = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=zero_cost_path, out_dir=None)
    costed = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=costed_path, out_dir=None)

    assert zero_cost.receipt is not None
    assert costed.receipt is not None
    loaded_costed_spec = load_spec(costed_path)
    assert loaded_costed_spec.version == "redline.spec.v2.2"
    assert costed.receipt.spec.spec_hash == hash_obj(loaded_costed_spec)
    assert costed.traces[0].points[-1].nav < zero_cost.traces[0].points[-1].nav
    assert costed.traces[1].points[-1].nav < zero_cost.traces[1].points[-1].nav


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


def test_sandbox_rejects_default_arg_open_alias(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_default_open")
    secret = tmp_path / "outside-open-secret.bin"
    secret.write_bytes(b"\xcf")
    (package / "candidate_default_open" / "strategy.py").write_text(
        f"EXTERNAL = {str(secret)!r}\n\n"
        "def signal(bar, state, config, f=open):\n"
        "    byte = f(EXTERNAL, 'rb').read(1)[0]\n"
        "    return byte % 2\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_default_open",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_function_repr_address_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_repr_entropy")
    (package / "candidate_repr_entropy" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    text = str(signal)\n"
        "    addr = int(text.rsplit('x', 1)[1].rstrip('>'), 16)\n"
        "    if int(bar['i']) < int(config.get('entry_bar', 0)):\n"
        "        return 0\n"
        "    return ((addr // 16) % 1000) / 1000\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_repr_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_config_format_address_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_config_format_entropy")
    (package / "candidate_config_format_entropy" / "config.json").write_text(
        json.dumps({"entry_bar": 4, "leverage": "0.5", "fmt": "%s"}),
        encoding="utf-8",
    )
    (package / "candidate_config_format_entropy" / "strategy.py").write_text(
        "from decimal import Decimal\n\n"
        "def signal(bar, state, config):\n"
        "    i = int(bar['i'])\n"
        "    if i < int(config.get('entry_bar', 0)):\n"
        "        return 0\n"
        "    text = config['fmt'] % signal\n"
        "    tail = text.rsplit('0x', 1)[1].split('>', 1)[0]\n"
        "    return Decimal((int(tail, 16) // 4096) % 7) / Decimal('100')\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_config_format_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_poisoned_numeric_modulo_format_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_poisoned_modulo_entropy")
    (package / "candidate_poisoned_modulo_entropy" / "config.json").write_text(
        json.dumps({"entry_bar": 4, "leverage": "0.5", "fmt": "%s"}),
        encoding="utf-8",
    )
    (package / "candidate_poisoned_modulo_entropy" / "strategy.py").write_text(
        "from decimal import Decimal\n\n"
        "def signal(bar, state, config):\n"
        "    i = int(bar['i'])\n"
        "    if i < int(config.get('entry_bar', 0)):\n"
        "        return 0\n"
        "    fmt = 1\n"
        "    fmt = config['fmt']\n"
        "    target = 1\n"
        "    target = signal\n"
        "    text = fmt % target\n"
        "    tail = text.rsplit('0x', 1)[1].split('>', 1)[0]\n"
        "    return Decimal((int(tail, 16) // 4096) % 7) / Decimal('100')\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_poisoned_modulo_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_object_signal_return(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_object_signal")
    (package / "candidate_object_signal" / "strategy.py").write_text(
        "class Signal:\n"
        "    pass\n\n"
        "def signal(bar, state, config):\n"
        "    return Signal()\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_object_signal",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_set_identity_hash_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_set_entropy")
    (package / "candidate_set_entropy" / "strategy.py").write_text(
        "class Token:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n\n"
        "def signal(bar, state, config):\n"
        "    left = Token(0)\n"
        "    right = Token(1)\n"
        "    for item in {left, right}:\n"
        "        return item.value\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_set_entropy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_allows_numeric_modulo_strategy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_modulo_rebalance")
    (package / "candidate_modulo_rebalance" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    i = int(bar['i'])\n"
        "    return 1 if i % 2 == 0 else 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_modulo_rebalance",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.reason_code != ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is not None


def test_sandbox_rejects_stdout_pollution(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_print")
    (package / "candidate_print" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    print('protocol noise')\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_print",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
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


def test_reject_decision_proof_bundle_is_verifiable(tmp_path: Path) -> None:
    out_dir = tmp_path / "reject-run"
    artifacts = run_redline(
        package_dir=PACKAGE,
        baseline="baseline",
        candidate="candidate_malicious",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=out_dir,
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    decision_proof = next(proof for proof in artifacts.proofs if proof.kind == ProofKind.DECISION)
    assert "--envelope envelope.json" in (decision_proof.reproduce or "")
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert decision_proof.proof_id in report["proof_ids"]
    assert any(proof["proof_id"] == decision_proof.proof_id for proof in report["proofs"])

    result = CliRunner().invoke(
        app,
        [
            "verify-proof",
            "--envelope",
            str(out_dir / "envelope.json"),
            "--proof-id",
            decision_proof.proof_id,
            "--proofs-dir",
            str(out_dir / "proofs"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "proof_verified"

    non_decision_path = next(path for path in sorted((out_dir / "proofs").glob("*.json")) if not path.name.startswith("proof_decision_"))
    original_non_decision = non_decision_path.read_text(encoding="utf-8")
    tampered_non_decision = json.loads(original_non_decision)
    tampered_non_decision["artifact_hash"] = "sha256:" + "0" * 64
    non_decision_path.write_text(json.dumps(tampered_non_decision), encoding="utf-8")
    tampered_non_decision_result = CliRunner().invoke(
        app,
        [
            "verify-proof",
            "--envelope",
            str(out_dir / "envelope.json"),
            "--proof-id",
            decision_proof.proof_id,
            "--proofs-dir",
            str(out_dir / "proofs"),
            "--json",
        ],
    )
    assert tampered_non_decision_result.exit_code == 4
    assert json.loads(tampered_non_decision_result.output)["reason_code"] == ReasonCode.RECEIPT_MISMATCH
    non_decision_path.write_text(original_non_decision, encoding="utf-8")

    extra_decision_path = out_dir / "proofs" / "proof_decision_000000000000000000000000.json"
    extra_decision = json.loads((out_dir / "proofs" / f"{decision_proof.proof_id.replace(':', '_')}.json").read_text(encoding="utf-8"))
    extra_decision["proof_id"] = "proof:decision:" + "0" * 24
    extra_decision_path.write_text(json.dumps(extra_decision), encoding="utf-8")
    extra_decision_result = CliRunner().invoke(
        app,
        [
            "verify-proof",
            "--envelope",
            str(out_dir / "envelope.json"),
            "--proof-id",
            decision_proof.proof_id,
            "--proofs-dir",
            str(out_dir / "proofs"),
            "--json",
        ],
    )
    assert extra_decision_result.exit_code == 4
    assert json.loads(extra_decision_result.output)["reason_code"] == ReasonCode.RECEIPT_MISMATCH
    extra_decision_path.unlink()

    proof_path = out_dir / "proofs" / f"{decision_proof.proof_id.replace(':', '_')}.json"
    tampered = json.loads(proof_path.read_text(encoding="utf-8"))
    tampered["artifact_hash"] = "sha256:" + "0" * 64
    proof_path.write_text(json.dumps(tampered), encoding="utf-8")
    tampered_result = CliRunner().invoke(
        app,
        [
            "verify-proof",
            "--envelope",
            str(out_dir / "envelope.json"),
            "--proof-id",
            decision_proof.proof_id,
            "--proofs-dir",
            str(out_dir / "proofs"),
            "--json",
        ],
    )
    assert tampered_result.exit_code == 4
    assert json.loads(tampered_result.output)["reason_code"] == ReasonCode.RECEIPT_MISMATCH


@pytest.mark.parametrize(
    ("status", "reason_code"),
    [(Status.PASS, ReasonCode.PASS), (Status.WITHHELD, ReasonCode.NEW_BLOCK_BREACH)],
)
def test_envelope_verifier_rejects_receipt_backed_statuses(tmp_path: Path, status: Status, reason_code: ReasonCode) -> None:
    proofs_dir = tmp_path / "proofs"
    proofs_dir.mkdir()
    fake_artifact_hash = hash_obj({"status": status.value, "kind": ProofKind.PACKAGE_CANONICAL.value})
    fake_proof = Proof(
        proof_id=f"proof:{ProofKind.PACKAGE_CANONICAL.value}:{fake_artifact_hash.removeprefix('sha256:')[:24]}",
        phase="import",
        kind=ProofKind.PACKAGE_CANONICAL,
        verdict_bearing=True,
        inputs_hash=fake_artifact_hash,
        artifact_hash=fake_artifact_hash,
    )
    coverage = CoverageManifest(cells=[("s1", "p1")], complete=True, missing=[])
    decision_id = decision_proof_id(status=status, reason_code=reason_code, proof_ids=[fake_proof.proof_id], coverage=coverage)
    envelope = DecisionEnvelope(
        status=status,
        reason_code=reason_code,
        chain_status=ChainStatus.CHAINED,
        required_proof_ids=[decision_id],
        satisfied_proof_ids=[decision_id],
        coverage=coverage,
        capabilities=Capabilities(scenario_count=1),
    )
    decision_proof = make_decision_proof(envelope=envelope, proofs=[fake_proof], envelope_bundle=True)
    assert decision_proof.proof_id == decision_id
    (tmp_path / "envelope.json").write_text(envelope.model_dump_json(indent=2) + "\n", encoding="utf-8")
    for proof in [fake_proof, decision_proof]:
        (proofs_dir / f"{proof.proof_id.replace(':', '_')}.json").write_text(proof.model_dump_json(indent=2) + "\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "verify-proof",
            "--envelope",
            str(tmp_path / "envelope.json"),
            "--proof-id",
            decision_id,
            "--proofs-dir",
            str(proofs_dir),
            "--json",
        ],
    )
    assert result.exit_code == 4
    assert json.loads(result.output)["reason_code"] == ReasonCode.RECEIPT_MISMATCH


def test_extreme_numeric_signal_fails_closed(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_extreme")
    (package / "candidate_extreme" / "strategy.py").write_text(
        "from decimal import Decimal\n\n"
        "def signal(bar, state, config):\n"
        "    return Decimal('1e1000000')\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    out_dir = tmp_path / "run"
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(package),
            "--baseline",
            "baseline",
            "--candidate",
            "candidate_extreme",
            "--suite",
            str(SUITE),
            "--spec",
            str(SPEC),
            "--out",
            str(out_dir),
            "--json",
        ],
    )
    assert result.exit_code == 4, result.output
    payload = json.loads(result.output)
    assert payload["status"] == Status.REJECT
    assert payload["reason_code"] == ReasonCode.NONFINITE_VALUE
    assert (out_dir / "envelope.json").exists()
    assert not (out_dir / "receipt.json").exists()


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
    write_identity_lock(package)
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
    write_identity_lock(package)
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
    write_identity_lock(package)
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


def test_sandbox_rejects_private_module_reexport_eval_access(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_argparse_sys_eval")
    (package / "candidate_argparse_sys_eval" / "strategy.py").write_text(
        "import argparse\n\n"
        "def signal(bar, state, config):\n"
        "    state['entropy'] = argparse._sys.modules['built' + 'ins'].eval(\"__import__('os').urandom(1)[0]\")\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_argparse_sys_eval",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_file_write_in_python_fallback(tmp_path: Path) -> None:
    package = tmp_path / "package"
    marker = tmp_path / "outside-marker"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_write")
    (package / "candidate_import_time_write" / "strategy.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('escaped', encoding='utf-8')\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_write",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_import_time_fileio_write_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-fileio-marker"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_fileio")
    (package / "candidate_import_time_fileio" / "strategy.py").write_text(
        "from io import FileIO\n"
        f"FileIO({str(marker)!r}, 'wb').write(b'escaped')\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_fileio",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_import_time_loader_write_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-loader-marker"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_loader_write")
    (package / "candidate_import_time_loader_write" / "strategy.py").write_text(
        f"__loader__.set_data({str(marker)!r}, b'escaped')\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_loader_write",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_import_time_loader_read_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    secret = tmp_path / "outside-loader-secret"
    secret.write_text("7", encoding="utf-8")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_loader_read")
    (package / "candidate_import_time_loader_read" / "strategy.py").write_text(
        f"ENTRY = int(__loader__.get_data({str(secret)!r}).decode())\n\n"
        "def signal(bar, state, config):\n"
        "    return 0 if int(bar['i']) < ENTRY else 1\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_loader_read",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_linecache_read(tmp_path: Path) -> None:
    package = tmp_path / "package"
    secret = tmp_path / "outside-linecache-secret"
    secret.write_text("9\n", encoding="utf-8")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_linecache")
    (package / "candidate_import_time_linecache" / "strategy.py").write_text(
        "import linecache\n"
        f"SECRET_SIGNAL = int(linecache.getline({str(secret)!r}, 1).strip() or '9')\n\n"
        "def signal(bar, state, config):\n"
        "    return SECRET_SIGNAL\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_linecache",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_configparser_read(tmp_path: Path) -> None:
    package = tmp_path / "package"
    secret = tmp_path / "outside-secret.ini"
    secret.write_text("[secret]\nallow=1\n", encoding="utf-8")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_configparser")
    (package / "candidate_import_time_configparser" / "strategy.py").write_text(
        "import configparser\n"
        "parser = configparser.ConfigParser()\n"
        f"parser.read({str(secret)!r}, encoding='utf-8')\n"
        "ALLOW = int(parser['secret']['allow'])\n\n"
        "def signal(bar, state, config):\n"
        "    return ALLOW\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_configparser",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_runpy_read(tmp_path: Path) -> None:
    package = tmp_path / "package"
    payload = tmp_path / "outside_payload.py"
    payload.write_text("ALLOW = 1\n", encoding="utf-8")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_runpy")
    (package / "candidate_import_time_runpy" / "strategy.py").write_text(
        "import runpy\n"
        f"payload = runpy.run_path({str(payload)!r})\n"
        "ALLOW = int(payload['ALLOW'])\n\n"
        "def signal(bar, state, config):\n"
        "    return ALLOW\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_runpy",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_genericpath_metadata(tmp_path: Path) -> None:
    package = tmp_path / "package"
    marker = tmp_path / "outside-state.bin"
    marker.write_bytes(b"12345678")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_genericpath")
    (package / "candidate_import_time_genericpath" / "strategy.py").write_text(
        "from genericpath import getsize as gs\n"
        f"ENTRY = 4 if gs({str(marker)!r}) == 8 else 1\n\n"
        "def signal(bar, state, config):\n"
        "    i = int(bar['i'])\n"
        "    if i < ENTRY:\n"
        "        return 0\n"
        "    if i >= int(config.get('exit_bar', 999999)):\n"
        "        return 0\n"
        "    return 1\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_genericpath",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_runtime_genericpath_metadata(tmp_path: Path) -> None:
    package = tmp_path / "package"
    marker = tmp_path / "outside-state.bin"
    marker.write_bytes(b"12345678")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_runtime_genericpath")
    (package / "candidate_runtime_genericpath" / "strategy.py").write_text(
        "from genericpath import getsize as gs\n\n"
        "def signal(bar, state, config):\n"
        f"    entry = 4 if gs({str(marker)!r}) == 8 else 1\n"
        "    i = int(bar['i'])\n"
        "    if i < entry:\n"
        "        return 0\n"
        "    if i >= int(config.get('exit_bar', 999999)):\n"
        "        return 0\n"
        "    return 1\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_runtime_genericpath",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None


def test_sandbox_rejects_import_time_logging_filehandler_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-logging-marker"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_logging")
    (package / "candidate_import_time_logging" / "strategy.py").write_text(
        "import logging\n"
        f"handler = logging.FileHandler({str(marker)!r})\n"
        "handler.close()\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_logging",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_import_time_path_unlink_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-path-marker"
    marker.write_text("keep", encoding="utf-8")
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_path_unlink")
    (package / "candidate_import_time_path_unlink" / "strategy.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).unlink()\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_path_unlink",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert marker.read_text(encoding="utf-8") == "keep"


def test_sandbox_rejects_import_time_path_mkdir_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-path-dir"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_path_mkdir")
    (package / "candidate_import_time_path_mkdir" / "strategy.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).mkdir()\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_path_mkdir",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_import_time_sqlite_write_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-import-time.db"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_import_time_sqlite")
    (package / "candidate_import_time_sqlite" / "strategy.py").write_text(
        "import sqlite3\n"
        f"con = sqlite3.connect({str(marker)!r})\n"
        "con.execute('create table t(x)')\n"
        "con.execute('insert into t values (1)')\n"
        "con.commit()\n"
        "con.close()\n\n"
        "def signal(bar, state, config):\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_import_time_sqlite",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_runtime_sqlite_write_in_python_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDLINE_DISABLE_OS_SANDBOX", "1")
    package = tmp_path / "package"
    marker = tmp_path / "outside-runtime.db"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_runtime_sqlite")
    (package / "candidate_runtime_sqlite" / "strategy.py").write_text(
        "import sqlite3\n\n"
        "def signal(bar, state, config):\n"
        "    if not state:\n"
        f"        con = sqlite3.connect({str(marker)!r})\n"
        "        con.execute('create table t(x)')\n"
        "        con.execute('insert into t values (1)')\n"
        "        con.commit()\n"
        "        con.close()\n"
        "        state['done'] = True\n"
        "    return 0\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_runtime_sqlite",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.CANDIDATE_SANDBOX_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_sandbox_rejects_object_address_entropy(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    shutil.copytree(package / "candidate_good", package / "candidate_object_entropy")
    (package / "candidate_object_entropy" / "strategy.py").write_text(
        "def signal(bar, state, config):\n"
        "    return hash(str(object())) % 2\n",
        encoding="utf-8",
    )
    write_identity_lock(package)
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
    write_identity_lock(package)
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


def test_verdict_path_rejects_spoofed_probe_identity_before_side_effect(monkeypatch, tmp_path: Path) -> None:
    marker = tmp_path / "probe-marker.txt"
    monkeypatch.setenv("REDLINE_TRIPWIRE_SECRET", "leaked-env")

    class SpoofedProbe:
        __module__ = "redline.probes.evil"

        def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
            marker.write_text(os.environ["REDLINE_TRIPWIRE_SECRET"], encoding="utf-8")
            return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[])

    monkeypatch.setitem(PROBE_REGISTRY, ProbeType.MAX_DRAWDOWN, SpoofedProbe())
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.VERDICT_PATH_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_verdict_path_rejects_monkeypatched_trusted_probe_method(monkeypatch, tmp_path: Path) -> None:
    marker = tmp_path / "trusted-method-marker"
    original_evaluate = MaxDrawdownProbe.evaluate

    def evil_evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        marker.mkdir()
        return original_evaluate(self, baseline=baseline, candidate=candidate, params=params)

    monkeypatch.setattr(MaxDrawdownProbe, "evaluate", evil_evaluate)
    with pytest.raises(TypeError):
        TRUSTED_PROBE_EVALUATE[ProbeType.MAX_DRAWDOWN] = evil_evaluate  # type: ignore[index]
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.VERDICT_PATH_VIOLATION
    assert artifacts.receipt is None
    assert not marker.exists()


def test_verdict_path_tripwire_blocks_directory_creation(tmp_path: Path) -> None:
    marker = tmp_path / "blocked-dir"
    with pytest.raises(VerdictPathViolation):
        with verdict_path_tripwire():
            marker.mkdir()
    assert not marker.exists()


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


def test_verdict_path_import_gate_passes_current_repo() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-verdict-path-imports.py"), str(ROOT)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "verdict path import gate passed" in result.stdout


def test_verdict_path_import_gate_rejects_forbidden_imports(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "src/redline/probes").mkdir(parents=True)
    (root / "src/redline/probes/__init__.py").write_text("", encoding="utf-8")
    (root / "src/redline/proof_kernel.py").write_text("import requests\n", encoding="utf-8")
    (root / "src/redline/verifier.py").write_text("__import__('openai')\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-verdict-path-imports.py"), str(root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "forbidden import requests" in result.stderr
    assert "forbidden dynamic import openai" in result.stderr


def test_purity_gate_bans_entropy_and_float_set(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "src/redline/engine_adapter").mkdir(parents=True)
    (root / "src/redline/probes").mkdir(parents=True)
    (root / "src/redline/probes/__init__.py").write_text("", encoding="utf-8")
    (root / "src/redline/engine_adapter/deterministic.py").write_text("import datetime\n", encoding="utf-8")
    (root / "src/redline/proof_kernel.py").write_text("import random\n", encoding="utf-8")
    (root / "src/redline/receipt.py").write_text("value = {1, 2}\n", encoding="utf-8")
    (root / "src/redline/runner.py").write_text("value = set([1, 2])\n", encoding="utf-8")
    (root / "src/redline/tripwire.py").write_text("value = frozenset([1])\n", encoding="utf-8")
    (root / "src/redline/verifier.py").write_text("value = float('1.0')\n", encoding="utf-8")
    (root / "src/redline/probes/behavior.py").write_text("value = {item for item in [1, 2]}\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-verdict-path-imports.py"), str(root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "forbidden import datetime" in result.stderr
    assert "forbidden import random" in result.stderr
    assert "forbidden deterministic builtin call float()" in result.stderr
    assert "forbidden deterministic builtin call frozenset()" in result.stderr
    assert "forbidden deterministic builtin call set()" in result.stderr
    assert "forbidden set literal in verdict path" in result.stderr
    assert "forbidden set comprehension in verdict path" in result.stderr


def test_replay_hash_is_stable() -> None:
    suite = load_suite(SUITE)
    engine = DeterministicReplayEngine()
    scenario = suite.scenarios[0]
    first = engine.replay(package=PACKAGE / "candidate_good", scenario=scenario, role="candidate")
    hashes = {engine.replay(package=PACKAGE / "candidate_good", scenario=scenario, role="candidate").artifact_hash for _ in range(100)}
    assert hashes == {first.artifact_hash}


def test_next_bar_fill_kills_lookahead_strategy(tmp_path: Path) -> None:
    package = tmp_path / "lookahead_package"
    package.mkdir()
    (package / "config.json").write_text("{}\n", encoding="utf-8")
    (package / "strategy.py").write_text(
        textwrap.dedent(
            """
            def signal(bar, state, config):
                if bar["i"] == 1:
                    return 1
                return 0
            """
        ).lstrip(),
        encoding="utf-8",
    )
    scenario_path = tmp_path / "lookahead.csv"
    scenario_path.write_text(
        textwrap.dedent(
            """
            timestamp,open,high,low,close
            2026-01-01T00:00:00Z,100,100,100,100
            2026-01-01T01:00:00Z,100,200,100,200
            2026-01-01T02:00:00Z,200,200,200,200
            """
        ).lstrip(),
        encoding="utf-8",
    )

    trace = DeterministicReplayEngine().replay(
        package=package,
        scenario=Scenario(id="lookahead-only", path=str(scenario_path)),
        role="candidate",
    )

    assert trace.points[1].position == Decimal("0")
    assert trace.points[1].nav == Decimal("10000")
    assert trace.points[2].position == Decimal("1")
    assert trace.points[-1].nav == Decimal("10000")
    assert trace.trade_count == 1


def test_fees_slippage_reduce_pnl_deterministically(tmp_path: Path) -> None:
    scenario_path = tmp_path / "fees_slippage.csv"
    scenario_path.write_text(
        textwrap.dedent(
            """
            timestamp,open,high,low,close
            2026-01-01T00:00:00Z,100,100,100,100
            2026-01-01T01:00:00Z,100,110,100,110
            2026-01-01T02:00:00Z,110,110,110,110
            """
        ).lstrip(),
        encoding="utf-8",
    )

    def run_with_config(config: dict[str, str]) -> ReplayTrace:
        package = tmp_path / ("package_" + str(len(list(tmp_path.iterdir()))))
        package.mkdir()
        (package / "config.json").write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
        (package / "strategy.py").write_text(
            textwrap.dedent(
                """
                def signal(bar, state, config):
                    if bar["i"] == 0:
                        return 2
                    return 0
                """
            ).lstrip(),
            encoding="utf-8",
        )
        return DeterministicReplayEngine().replay(
            package=package,
            scenario=Scenario(id="fees-slippage", path=str(scenario_path)),
            role="candidate",
        )

    no_cost = run_with_config({})
    costed = run_with_config({"fee_bps": "10", "slippage_bps": "20"})
    repeat = run_with_config({"fee_bps": "10", "slippage_bps": "20"})

    assert no_cost.points[-1].nav == Decimal("12000")
    assert costed.points[-1].nav == Decimal("11761.2000")
    assert costed.points[-1].nav < no_cost.points[-1].nav
    assert costed.artifact_hash == repeat.artifact_hash
    assert costed.trade_count == 2


def test_run_receipt_proofs_and_traces_are_bit_identical_100x() -> None:
    receipt_hashes: set[str] = set()
    report_hashes: set[str] = set()
    proof_fingerprints: set[tuple[str, ...]] = set()
    trace_fingerprints: set[tuple[str, ...]] = set()

    for _ in range(100):
        artifacts = run_redline(
            package_dir=PACKAGE,
            baseline="baseline",
            candidate="candidate_good",
            suite_path=SUITE,
            spec_path=SPEC,
            out_dir=None,
        )
        assert artifacts.receipt is not None
        receipt_hashes.add(artifacts.receipt.receipt_hash)
        report_hashes.add(artifacts.report_json["report_hash"])
        proof_fingerprints.add(tuple(proof.artifact_hash for proof in artifacts.receipt.proofs))
        trace_fingerprints.add(tuple(trace.artifact_hash for trace in artifacts.traces))

    assert receipt_hashes == {"sha256:426312eeddd82c552a747df781bf12e2573280fcb7b9ab442f277a2fb76645d6"}
    assert len(report_hashes) == 1
    assert len(proof_fingerprints) == 1
    assert len(trace_fingerprints) == 1


def test_spec_hash_is_invariant_to_json_key_order(tmp_path: Path) -> None:
    def reverse_keys(value: object) -> object:
        if isinstance(value, dict):
            return {key: reverse_keys(value[key]) for key in reversed(list(value.keys()))}
        if isinstance(value, list):
            return [reverse_keys(item) for item in value]
        return value

    original = json.loads(SPEC.read_text(encoding="utf-8"))
    reordered_path = tmp_path / "redline_spec_reordered.json"
    reordered_path.write_text(json.dumps(reverse_keys(original), indent=2), encoding="utf-8")

    assert hash_obj(load_spec(reordered_path)) == hash_obj(load_spec(SPEC))


def test_replay_hash_is_stable_across_parent_hash_seeds() -> None:
    suite = load_suite(SUITE)
    scenario = suite.scenarios[0]
    expected = DeterministicReplayEngine().replay(package=PACKAGE / "candidate_good", scenario=scenario, role="candidate").artifact_hash
    script = (
        "from pathlib import Path\n"
        "from redline.engine_adapter import DeterministicReplayEngine\n"
        "from redline.runner import load_suite\n"
        f"root = Path({str(ROOT)!r})\n"
        "suite = load_suite(root / 'fixtures/suites/demo_suite.json')\n"
        f"scenario_id = {scenario.id!r}\n"
        "scenario = next(item for item in suite.scenarios if item.id == scenario_id)\n"
        "trace = DeterministicReplayEngine().replay(package=root / 'fixtures/demo_pack/candidate_good', scenario=scenario, role='candidate')\n"
        "print(trace.artifact_hash)\n"
    )
    for seed in ("random", "1", "31337"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(ROOT / "src")}
        proc = subprocess.run([sys.executable, "-c", script], check=False, capture_output=True, text=True, cwd=ROOT, env=env, timeout=10)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == expected


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


def test_proof_tamper_gets_proof_specific_code(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path)
    assert artifacts.receipt is not None
    proof = next(item for item in artifacts.receipt.proofs if item.kind == ProofKind.PACKAGE_CANONICAL)
    proof_path = tmp_path / "proofs" / f"{proof.proof_id.replace(':', '_')}.json"
    sidecar = json.loads(proof_path.read_text(encoding="utf-8"))
    sidecar["artifact_hash"] = "sha256:" + "0" * 64
    proof_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = verify_proof(receipt_path=tmp_path / "receipt.json", proof_id=proof.proof_id)

    assert result.status == "proof_mismatch"
    assert result.reason_code == ReasonCode.PROOF_HASH_MISMATCH


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
    assert mismatch.reason_code == ReasonCode.PROOF_HASH_MISMATCH


def test_lookahead_proof_fields_are_replayed_by_verify_proof(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    run_dir = tmp_path / "run"
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=run_dir)
    assert artifacts.receipt is not None
    proof = next(item for item in artifacts.receipt.proofs if item.kind == ProofKind.REPLAY)

    assert proof.fill_model == "next_bar_open"
    assert proof.lookahead_guard == "structural_next_bar"
    assert proof.fees_modeled is True
    verified = verify_proof(receipt_path=run_dir / "receipt.json", proof_id=proof.proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert verified.status == "proof_verified"

    receipt_data = json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))
    receipt_proof = next(item for item in receipt_data["proofs"] if item["proof_id"] == proof.proof_id)
    receipt_proof["fees_modeled"] = False
    receipt_data["receipt_hash"] = ""
    tampered_receipt = Receipt.model_validate(receipt_data)
    receipt_data["receipt_hash"] = compute_receipt_hash(tampered_receipt)
    (run_dir / "receipt.json").write_text(json.dumps(receipt_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sidecar_path = run_dir / "proofs" / f"{proof.proof_id.replace(':', '_')}.json"
    sidecar_proof = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar_proof["fees_modeled"] = False
    sidecar_path.write_text(json.dumps(sidecar_proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    mismatch = verify_proof(receipt_path=run_dir / "receipt.json", proof_id=proof.proof_id, package=package, suite_path=SUITE, spec_path=SPEC)
    assert mismatch.status == "proof_mismatch"
    assert mismatch.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_verify_proof_requires_all_sidecars_for_decision_replay(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    decision_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.DECISION)
    probe_id = next(proof.proof_id for proof in artifacts.receipt.proofs if proof.kind == ProofKind.PROBE)
    (tmp_path / "run" / "proofs" / f"{probe_id.replace(':', '_')}.json").unlink()

    result = verify_proof(receipt_path=tmp_path / "run" / "receipt.json", proof_id=decision_id, package=package, suite_path=SUITE, spec_path=SPEC)

    assert result.status == "proof_mismatch"
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


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


def test_cli_check_package_defaults_to_replayed_and_hash_only_is_explicit(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    runner = CliRunner()

    replayed = runner.invoke(app, ["check", str(tmp_path / "run" / "receipt.json"), "--package", str(PACKAGE), "--json"])
    assert replayed.exit_code == 10
    payload = json.loads(replayed.stdout)
    assert payload["verification_level"] == VerificationLevel.REPLAYED.value
    assert payload["reason_code"] == ReasonCode.BASELINE_GENESIS.value

    hash_only = runner.invoke(app, ["check", str(tmp_path / "run" / "receipt.json"), "--package", str(PACKAGE), "--hash-only", "--json"])
    assert hash_only.exit_code == 6
    payload = json.loads(hash_only.stdout)
    assert payload["verification_level"] == VerificationLevel.HASH_ONLY.value
    assert payload["reason_code"] == ReasonCode.UNVERIFIED_NO_VERDICT.value

    both = runner.invoke(app, ["check", str(tmp_path / "run" / "receipt.json"), "--rerun", "--hash-only", "--json"])
    assert both.exit_code == 2
    assert json.loads(both.stdout)["reason_code"] == ReasonCode.SCHEMA_INVALID.value


def test_cli_check_package_default_replay_checks_proof_sidecars(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    next((tmp_path / "run" / "proofs").glob("proof_probe_*.json")).unlink()
    result = CliRunner().invoke(app, ["check", str(tmp_path / "run" / "receipt.json"), "--package", str(PACKAGE), "--json"])
    assert result.exit_code == 4
    payload = json.loads(result.stdout)
    assert payload["verification_level"] == VerificationLevel.REPLAYED.value
    assert payload["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value


def test_mcp_verify_receipt_alias_matches_check_surface(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None

    check = redline_check_receipt(str(tmp_path / "run" / "receipt.json"), pkg_path=str(PACKAGE), rerun=True)
    verify_alias = redline_verify_receipt(str(tmp_path / "run" / "receipt.json"), pkg_path=str(PACKAGE), rerun=True)

    assert verify_alias == check
    assert verify_alias["schema_version"] == "redline.mcp.check.v1"
    assert verify_alias["verification_level"] == VerificationLevel.REPLAYED.value
    assert verify_alias["trust_source"] == "untrusted_tool_input"


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
    untrusted_verify_alias = redline_verify_receipt(
        str(tmp_path / "chained" / "receipt.json"),
        pkg_path=str(package),
        rerun=True,
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert untrusted_verify_alias == untrusted_check
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
    extra_sidecar = tmp_path / "chained" / "proofs" / "zz_extra_unreferenced_duplicate.json"
    shutil.copy2(next((tmp_path / "chained" / "proofs").glob("proof_probe_*.json")), extra_sidecar)
    extra_sidecar_export = redline_export_if_clean(
        str(tmp_path / "chained" / "receipt.json"),
        str(package),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
        report_path=str(tmp_path / "chained" / "report.json"),
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert extra_sidecar_export["export_allowed"] is False
    assert extra_sidecar_export["verification"]["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value


def test_duplicate_baseline_ledger_key_blocks_successor_publish_and_mcp(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="baseline-policy", key_id="baseline-key", public_key=public_key, issuer="baseline-ci")
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
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="baseline-policy", key_id="baseline-key", issuer="baseline-ci")
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
    assert chained.envelope.status == Status.PASS
    _sign_run_checkpoint(tmp_path / "chained", private_key, policy_id="baseline-policy", key_id="baseline-key", issuer="baseline-ci")
    _append_duplicate_ledger_key_and_resign(tmp_path / "baseline", private_key, policy_id="baseline-policy", key_id="baseline-key", issuer="baseline-ci")

    baseline_result = verify(
        receipt_path=tmp_path / "baseline" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        ledger_attestation_path=tmp_path / "baseline" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        level=VerificationLevel.REPLAYED,
    )
    assert baseline_result.status == VerificationStatus.REJECTED
    assert baseline_result.reason_code == ReasonCode.RECEIPT_MISMATCH
    successor = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "successor-after-tamper",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        baseline_trust_policy_path=policy_path,
    )
    assert successor.receipt is None
    assert successor.envelope.reason_code == ReasonCode.BASELINE_UNCHAINED
    chained_result = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        ledger_attestation_path=tmp_path / "chained" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        level=VerificationLevel.REPLAYED,
    )
    assert chained_result.status == VerificationStatus.REJECTED
    assert chained_result.reason_code == ReasonCode.BASELINE_UNCHAINED
    preflight = publish_preflight(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        report_path=tmp_path / "chained" / "report.json",
        ledger_attestation_path=tmp_path / "chained" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
    )
    assert preflight.ok is False
    assert preflight.reason_code == ReasonCode.BASELINE_UNCHAINED
    monkeypatch.setenv("REDLINE_TRUST_POLICY_HASH", policy.policy_hash)
    export = redline_export_if_clean(
        str(tmp_path / "chained" / "receipt.json"),
        str(package),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
        report_path=str(tmp_path / "chained" / "report.json"),
        ledger_attestation_path=str(tmp_path / "chained" / "issuance-ledger.attestation.json"),
        trust_policy_path=str(policy_path),
        baseline_receipt_path=str(tmp_path / "baseline" / "receipt.json"),
    )
    assert export["export_allowed"] is False
    assert export["verification"]["reason_code"] == ReasonCode.BASELINE_UNCHAINED.value


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


def test_compile_out_of_scope_intent_does_not_generate_gate(tmp_path: Path) -> None:
    text_spec = tmp_path / "profit.txt"
    text_spec.write_text("帮我把杠杆调到能赚最多，越激进越好。", encoding="utf-8")

    try:
        compile_spec(text_spec)
    except OutOfScopeError as exc:
        assert "out_of_scope" in str(exc)
    else:
        raise AssertionError("out-of-scope intent must not generate a RedlineSpec")

    cli_result = CliRunner().invoke(app, ["compile", str(text_spec), "--json"])
    assert cli_result.exit_code == 2
    payload = json.loads(cli_result.stdout)
    assert payload["reason_code"] == ReasonCode.OUT_OF_SCOPE.value
    mcp_result = redline_compile_spec(str(text_spec))
    assert mcp_result["schema_version"] == "redline.mcp.error.v1"
    assert mcp_result["reason_code"] == ReasonCode.OUT_OF_SCOPE.value

    mixed_spec = tmp_path / "mixed.txt"
    mixed_spec.write_text("Max drawdown <= 8%; then tune leverage to maximize profit.", encoding="utf-8")
    try:
        compile_spec(mixed_spec)
    except OutOfScopeError:
        pass
    else:
        raise AssertionError("mixed supported and unsupported intent must fail closed")


def test_qwen_out_of_scope_does_not_fallback_to_local_compile(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 8%; no entry before bar 3; trade budget 20.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps({"status": "out_of_scope"})}}]}).encode()

    try:
        compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    except OutOfScopeError:
        pass
    else:
        raise AssertionError("qwen out_of_scope must not fall back to local compile")


def test_import_write_lock_and_receipt_bind_playbook_identity(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)

    imported = import_package(package, write_lock=True)

    assert imported.identity_lock_hash is not None
    lock_path = identity_lock_path(package)
    assert lock_path.exists()
    lock = build_identity_lock(package)
    assert imported.identity_lock_hash == lock.lock_hash
    assert "baseline/strategy.py" in {item.path for item in lock.locked_files}
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is not None
    assert artifacts.receipt.package.identity_lock_hash == lock.lock_hash
    result = verify(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )
    assert result.reason_code == ReasonCode.BASELINE_GENESIS


def test_replayed_rejects_tampered_playbook_identity_lock_source(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    write_identity_lock(package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is not None
    (package / "baseline" / "strategy.py").write_text(
        (package / "baseline" / "strategy.py").read_text(encoding="utf-8") + "\n# tamper\n",
        encoding="utf-8",
    )

    result = verify(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )

    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED


def test_playbook_identity_lock_rejects_forged_adapter_contract(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    write_identity_lock(package)
    lock_path = identity_lock_path(package)
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    data["adapter_id"] = "evil_adapter"
    data["canonical_tar_rules"] = "evil.rules"
    data["identity_hash"] = hash_obj({"adapter_id": data["adapter_id"], "canonical_tar_rules": data["canonical_tar_rules"], "locked_files": data["locked_files"]})
    data["lock_hash"] = ""
    data["lock_hash"] = hash_obj(data)
    lock_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(CanonicalizationError):
        load_identity_lock(package)

    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )

    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.RECEIPT_BINDING_FAILED


def test_missing_playbook_identity_lock_is_fail_closed(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    identity_lock_path(package).unlink()

    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )

    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    imported = CliRunner().invoke(app, ["import", str(package), "--json"])
    assert imported.exit_code == 4
    payload = json.loads(imported.stdout)
    assert payload["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value
    initialized = CliRunner().invoke(app, ["import", str(package), "--write-lock", "--json"])
    assert initialized.exit_code == 0
    payload = json.loads(initialized.stdout)
    assert payload["identity_lock_hash"].startswith("sha256:")


def test_unlocked_new_playbook_source_is_fail_closed(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    new_candidate = package / "candidate_unlocked"
    shutil.copytree(package / "candidate_good", new_candidate)

    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_unlocked",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )

    assert artifacts.receipt is None
    assert artifacts.envelope.status == Status.REJECT
    assert artifacts.envelope.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    imported = CliRunner().invoke(app, ["import", str(package), "--json"])
    assert imported.exit_code == 4
    assert json.loads(imported.stdout)["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value
    refreshed = CliRunner().invoke(app, ["import", str(package), "--write-lock", "--json"])
    assert refreshed.exit_code == 0


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
    missing_suite = redline_run_suite(str(PACKAGE), suite_path=str(tmp_path / "missing-suite.json"), spec_path=str(SPEC))
    assert missing_suite["schema_version"] == "redline.mcp.error.v1"
    assert missing_suite["reason_code"] == ReasonCode.DATA_MISSING.value
    missing_spec = redline_run_suite(str(PACKAGE), suite_path=str(SUITE), spec_path=str(tmp_path / "missing-spec.json"))
    assert missing_spec["schema_version"] == "redline.mcp.error.v1"
    assert missing_spec["reason_code"] == ReasonCode.DATA_MISSING.value
    missing_package_export = redline_export_if_clean(
        receipt_path=str(ROOT / "artifacts/demo/pass/receipt.json"),
        pkg_path=str(tmp_path / "missing-package"),
        suite_path=str(SUITE),
        spec_path=str(SPEC),
    )
    assert missing_package_export["schema_version"] == "redline.mcp.export_if_clean.v1"
    assert missing_package_export["export_allowed"] is False
    assert missing_package_export["verification"]["status"] in {VerificationStatus.BAD_INPUT.value, VerificationStatus.REJECTED.value}
    malformed_receipt = tmp_path / "malformed-receipt.json"
    malformed_receipt.write_text("{not json", encoding="utf-8")
    malformed_export = redline_export_if_clean(receipt_path=str(malformed_receipt), pkg_path=str(PACKAGE))
    assert malformed_export["schema_version"] == "redline.mcp.export_if_clean.v1"
    assert malformed_export["export_allowed"] is False
    assert malformed_export["verification"]["status"] == VerificationStatus.BAD_INPUT.value


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


def test_qwen_compile_accepts_no_entry_bar_lt_alias(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        content = {
            "version": "redline.spec.v2.1",
            "spec_id": "qwen-compiled",
            "probes": [
                {"id": "drawdown_limit", "type": "max_drawdown", "params": {"max_drawdown": "0.07"}, "block": True},
                {"id": "no_entry_when_crash", "type": "no_entry_when", "params": {"scenario_id": "btc-crash-2024-03-05", "bar_lt": "4", "max_abs_position": "0"}, "block": True},
                {"id": "trade_budget", "type": "trade_budget", "params": {"max_trades": "12"}, "block": True},
            ],
        }
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode()

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    assert compiled.compiler == "qwen"
    assert compiled.degraded_reason is None
    assert compiled.probes[1].params["bar_lt"] == "4"


def test_qwen_compile_discards_decimal_bar_lt_alias(tmp_path: Path) -> None:
    text_spec = tmp_path / "intent.txt"
    text_spec.write_text("Max drawdown <= 7%; avoid entry before bar 4; trade budget 12.", encoding="utf-8")

    def transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        content = {
            "version": "redline.spec.v2.1",
            "spec_id": "qwen-compiled",
            "probes": [
                {"id": "drawdown_limit", "type": "max_drawdown", "params": {"max_drawdown": "0.07"}, "block": True},
                {"id": "no_entry_when_crash", "type": "no_entry_when", "params": {"scenario_id": "btc-crash-2024-03-05", "bar_lt": "3.0", "max_abs_position": "0"}, "block": True},
                {"id": "trade_budget", "type": "trade_budget", "params": {"max_trades": "12"}, "block": True},
            ],
        }
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode()

    compiled = compile_spec(text_spec, use_qwen=True, qwen_model="qwen-test", qwen_api_key="test-key", qwen_transport=transport)
    assert compiled.compiler == "json-fallback"
    assert compiled.degraded_reason == "qwen_semantic_sanity_failed"


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
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="demo-policy", key_id="demo-key", public_key=public_key, issuer="demo-ci")
    policy_path = tmp_path / "demo-trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    _sign_run_checkpoint(tmp_path / "good", private_key, policy_id="demo-policy", key_id="demo-key", issuer="demo-ci")
    unpinned_demo_result = publish_preflight(
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-demo-unpinned",
        ledger_attestation_path=tmp_path / "good" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        allow_demo_baseline_genesis=True,
    )
    assert unpinned_demo_result.ok is False
    assert unpinned_demo_result.state == "TRUST_POLICY_REQUIRED"
    wrong_pin_demo_result = publish_preflight(
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-demo-wrong-pin",
        ledger_attestation_path=tmp_path / "good" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        trust_policy_hash="sha256:" + "0" * 64,
        allow_demo_baseline_genesis=True,
    )
    assert wrong_pin_demo_result.ok is False
    assert wrong_pin_demo_result.state == "TRUST_POLICY_REQUIRED"
    report_path = tmp_path / "good" / "report.json"
    original_report = report_path.read_text(encoding="utf-8")
    report_data = json.loads(original_report)
    report_data["receipt_hash"] = "sha256:" + "0" * 64
    report_path.write_text(json.dumps(report_data), encoding="utf-8")
    tampered_report_verify = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        report_path=report_path,
        ledger_checkpoint_path=tmp_path / "good" / "issuance-ledger.checkpoint.json",
        allow_demo_preview=True,
    )
    assert tampered_report_verify.ok is False
    assert tampered_report_verify.state == "ANNOTATION_RECEIPT_INVALID"
    assert tampered_report_verify.reason_code == ReasonCode.RECEIPT_MISMATCH
    report_path.write_text(original_report, encoding="utf-8")
    proof_backup = tmp_path / "good-proof-backup"
    shutil.copytree(tmp_path / "good" / "proofs", proof_backup)
    probe_sidecar = next((tmp_path / "good" / "proofs").glob("proof_probe_*.json"))
    probe_sidecar.unlink()
    missing_demo_sidecar_verify = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=tmp_path / "good" / "receipt.json",
        package=PACKAGE,
        report_path=tmp_path / "good" / "report.json",
        ledger_checkpoint_path=tmp_path / "good" / "issuance-ledger.checkpoint.json",
        allow_demo_preview=True,
    )
    assert missing_demo_sidecar_verify.ok is False
    assert missing_demo_sidecar_verify.state == "ANNOTATION_RECEIPT_INVALID"
    assert missing_demo_sidecar_verify.reason_code == ReasonCode.RECEIPT_MISMATCH
    shutil.rmtree(tmp_path / "good" / "proofs")
    shutil.copytree(proof_backup, tmp_path / "good" / "proofs")
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
    extra_sidecar = tmp_path / "chained" / "proofs" / "zz_extra_unreferenced_duplicate.json"
    shutil.copy2(next((tmp_path / "chained" / "proofs").glob("proof_probe_*.json")), extra_sidecar)
    extra_sidecar_verify = verify(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        level=VerificationLevel.REPLAYED,
    )
    assert extra_sidecar_verify.status == VerificationStatus.REJECTED
    assert extra_sidecar_verify.reason_code == ReasonCode.RECEIPT_MISMATCH
    extra_sidecar_publish = publish_preflight(
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-extra-sidecar",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert extra_sidecar_publish.ok is False
    assert extra_sidecar_publish.reason_code == ReasonCode.RECEIPT_MISMATCH
    extra_sidecar.unlink()

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
    assert publish.preflight_transcript_path == str(tmp_path / "publish" / "preflight-transcript.jsonl")
    assert publish.preflight_transcript_hash == sha256_bytes((tmp_path / "publish" / "preflight-transcript.jsonl").read_bytes())
    preflight_entries = [
        json.loads(line)
        for line in (tmp_path / "publish" / "preflight-transcript.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [entry["step_id"] for entry in preflight_entries] == [
        "package-hash",
        "verify-replayed",
        "load-ledger-checkpoint",
        "trust-policy",
        "annotate-package",
    ]
    for entry in preflight_entries:
        assert entry["entry_hash"] == hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
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
        trust_policy_hash=policy.policy_hash,
    )
    assert annotation_result.ok is True
    assert annotation_result.reason_code == ReasonCode.PASS
    metadata_forged_annotation_path = tmp_path / "forged-metadata-annotation.json"
    metadata_forged_annotation = PackageAnnotation.model_validate(json.loads((tmp_path / "publish" / "redline-annotation.json").read_text()))
    metadata_forged_annotation = metadata_forged_annotation.model_copy(
        update={
            "strength_summary": "forged sponsor-ready claim",
            "chain_status": ChainStatus.GENESIS,
            "verification_level": VerificationLevel.HASH_ONLY,
            "annotation_hash": "",
        }
    )
    metadata_forged_annotation = metadata_forged_annotation.model_copy(update={"annotation_hash": hash_obj(metadata_forged_annotation)})
    metadata_forged_annotation_path.write_text(metadata_forged_annotation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    metadata_forged_annotation_result = verify_annotation(
        annotation_path=metadata_forged_annotation_path,
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        report_path=tmp_path / "chained" / "report.json",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_checkpoint_path=tmp_path / "chained" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert metadata_forged_annotation_result.ok is False
    assert metadata_forged_annotation_result.state == "ANNOTATION_BINDING_MISMATCH"
    assert metadata_forged_annotation_result.reason_code == ReasonCode.RECEIPT_MISMATCH
    unpinned_annotation_result = verify_annotation(
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
    assert unpinned_annotation_result.ok is False
    assert unpinned_annotation_result.state == "ANNOTATION_TRUST_POLICY_REQUIRED"
    tampered_annotation_path = tmp_path / "tampered-trust-annotation.json"
    tampered_annotation = PackageAnnotation.model_validate(json.loads((tmp_path / "publish" / "redline-annotation.json").read_text()))
    tampered_annotation = tampered_annotation.model_copy(
        update={"trust_policy_id": "forged-policy", "trusted_ledger_key_id": "forged-key", "annotation_hash": ""}
    )
    tampered_annotation = tampered_annotation.model_copy(update={"annotation_hash": hash_obj(tampered_annotation)})
    tampered_annotation_path.write_text(tampered_annotation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    tampered_annotation_result = verify_annotation(
        annotation_path=tampered_annotation_path,
        receipt_path=tmp_path / "chained" / "receipt.json",
        package=package,
        report_path=tmp_path / "chained" / "report.json",
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_checkpoint_path=tmp_path / "chained" / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=attestation_path,
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert tampered_annotation_result.ok is False
    assert tampered_annotation_result.state == "ANNOTATION_ATTESTATION_MISMATCH"
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
        trust_policy_hash=policy.policy_hash,
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
        trust_policy_hash=policy.policy_hash,
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


def test_trust_policy_hash_rejects_tamper_and_revocation() -> None:
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="policy", key_id="key", public_key=public_key, issuer="ci")
    assert verify_trust_policy(policy)
    tampered = policy.model_copy(update={"keys": [policy.keys[0].model_copy(update={"issuer": "attacker"})]})
    assert not verify_trust_policy(tampered)

    checkpoint = LedgerCheckpoint(
        ledger_path="issuance-ledger.jsonl",
        ledger_hash="sha256:" + "1" * 64,
        ledger_tail_hash="sha256:" + "2" * 64,
        ledger_entry_count=1,
        subject_receipt_hashes=["sha256:" + "3" * 64],
        checkpoint_hash="",
    )
    checkpoint = checkpoint.model_copy(update={"checkpoint_hash": hash_obj(checkpoint)})
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="ci",
        trust_policy_id="policy",
        key_id="key",
        issuer="ci",
    )
    assert verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy=policy)
    revoked_policy = policy.model_copy(update={"keys": [policy.keys[0].model_copy(update={"revoked": True})]})
    revoked_policy = revoked_policy.model_copy(update={"policy_hash": hash_obj(revoked_policy.model_copy(update={"policy_hash": ""}))})
    assert verify_trust_policy(revoked_policy)
    assert not verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy=revoked_policy)


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
        trust_policy_hash=policy.policy_hash,
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


@pytest.mark.parametrize(
    ("extra_args", "expected_state"),
    [
        (["--final-publish"], "FINAL_PUBLISH_REQUIRES_EXECUTE"),
        (["--execute"], "EXECUTE_CONFIRMATION_REQUIRED"),
        (["--execute", "--final-publish", "--yes-i-understand-redline-is-wrapper-only"], "FINAL_PUBLISH_CONFIRMATION_REQUIRED"),
        (
            ["--execute", "--final-publish", "--yes-i-understand-redline-is-wrapper-only", "--yes-final-publish"],
            "FINAL_PUBLISH_CONFIRMATION_REQUIRED",
        ),
    ],
)
def test_publish_cli_final_execute_guards_fail_closed(monkeypatch, tmp_path: Path, extra_args: list[str], expected_state: str) -> None:
    monkeypatch.delenv("REDLINE_ALLOW_FINAL_PUBLISH", raising=False)
    result = CliRunner().invoke(
        app,
        [
            "publish",
            str(PACKAGE),
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--out",
            str(tmp_path / "publish"),
            "--json",
            *extra_args,
        ],
    )

    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == expected_state
    assert payload["reason_code"] == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value


def test_publish_execute_requires_bitget_credentials_after_clean_preflight(monkeypatch, tmp_path: Path) -> None:
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        monkeypatch.delenv(key, raising=False)
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    policy = json.loads((tmp_path / "trust-policy.json").read_text(encoding="utf-8"))
    monkeypatch.setenv("REDLINE_TRUST_POLICY", str(tmp_path / "trust-policy.json"))
    monkeypatch.setenv("REDLINE_TRUST_POLICY_HASH", policy["policy_hash"])

    result = CliRunner().invoke(
        app,
        [
            "publish",
            str(package),
            str(tmp_path / "run" / "receipt.json"),
            "--suite",
            str(SUITE),
            "--spec",
            str(SPEC),
            "--out",
            str(tmp_path / "publish"),
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--ledger-attestation",
            str(tmp_path / "run" / "issuance-ledger.attestation.json"),
            "--execute",
            "--yes-i-understand-redline-is-wrapper-only",
            "--json",
        ],
    )

    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "BITGET_CREDENTIALS_REQUIRED"
    assert payload["reason_code"] == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value


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


def test_publish_preflight_rejects_archive_output_hardlink_alias(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is not None
    before_hash = hash_tree(package)
    out_dir = tmp_path / "publish"
    out_dir.mkdir()
    archive_path = out_dir / "annotated-package.tar.gz"
    strategy_path = package / "candidate_good" / "strategy.py"
    before_content = strategy_path.read_text(encoding="utf-8")
    os.link(strategy_path, archive_path)

    result = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=out_dir,
        allow_demo_baseline_genesis=True,
    )

    assert result.ok is False
    assert result.state == "OUTPUT_PATH_INVALID"
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    assert hash_tree(package) == before_hash
    assert strategy_path.read_text(encoding="utf-8") == before_content


def test_publish_preflight_rejects_annotation_output_aliases(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "run",
    )
    assert artifacts.receipt is not None
    before_hash = hash_tree(package)
    strategy_path = package / "candidate_good" / "strategy.py"
    before_content = strategy_path.read_text(encoding="utf-8")
    out_dir = tmp_path / "publish"
    out_dir.mkdir()
    os.link(strategy_path, out_dir / "redline-annotation.json")

    result = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=out_dir,
        allow_demo_baseline_genesis=True,
    )

    assert result.ok is False
    assert result.state == "OUTPUT_PATH_INVALID"
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    assert not (out_dir / "annotated-package.tar.gz").exists()
    assert hash_tree(package) == before_hash
    assert strategy_path.read_text(encoding="utf-8") == before_content


def test_publish_preflight_rejects_transcript_symlink_without_external_write(tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    out_dir = tmp_path / "publish"
    out_dir.mkdir()
    victim = tmp_path / "victim.jsonl"
    victim.write_text("keep-me\n", encoding="utf-8")
    os.symlink(victim, out_dir / "preflight-transcript.jsonl")

    result = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=out_dir,
        allow_demo_baseline_genesis=True,
    )

    assert result.ok is False
    assert result.state == "OUTPUT_PATH_INVALID"
    assert result.reason_code == ReasonCode.RECEIPT_BINDING_FAILED
    assert victim.read_text(encoding="utf-8") == "keep-me\n"
    assert not (out_dir / "redline-annotation.json").exists()
    assert not (out_dir / "annotated-package.tar.gz").exists()


def test_run_redline_replaces_proofs_symlink_without_touching_target(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    keep = victim / "keep.json"
    keep.write_text('{"keep":true}\n', encoding="utf-8")
    os.symlink(victim, out_dir / "proofs")

    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=out_dir)

    assert artifacts.receipt is not None
    assert keep.read_text(encoding="utf-8") == '{"keep":true}\n'
    assert sorted(path.name for path in victim.iterdir()) == ["keep.json"]
    assert not (out_dir / "proofs").is_symlink()
    assert any((out_dir / "proofs").glob("proof_*.json"))


def test_run_redline_removes_legacy_receipt_tmp_symlink_without_clobber(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep-me\n", encoding="utf-8")
    os.symlink(victim, out_dir / "receipt.json.tmp")

    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=out_dir)

    assert artifacts.receipt is not None
    assert victim.read_text(encoding="utf-8") == "keep-me\n"
    assert not (out_dir / "receipt.json.tmp").exists()
    assert (out_dir / "receipt.json").exists()


def test_doctor_json_runs_backend_smoke() -> None:
    result = CliRunner().invoke(
        app,
        [
            "doctor",
            "--package",
            str(PACKAGE),
            "--suite",
            str(SUITE),
            "--spec",
            str(SPEC),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "redline.doctor.v1"
    assert payload["ok"] is True
    checks = {check["name"]: check for check in payload["checks"]}
    assert checks["reason-exit-coverage"]["ok"] is True
    assert checks["required-proofs-coverage"]["ok"] is True
    assert checks["fixture-inputs"]["evidence"]["scenario_count"] == "2"
    assert checks["deterministic-pass-smoke"]["evidence"]["reason_code"] == ReasonCode.BASELINE_GENESIS.value
    assert checks["withheld-smoke"]["evidence"]["reason_code"] == ReasonCode.NEW_BLOCK_BREACH.value
    assert checks["checked-in-demo-artifacts"]["evidence"]["pass_reason_code"] == ReasonCode.BASELINE_GENESIS.value
    assert checks["checked-in-demo-artifacts"]["evidence"]["withheld_reason_code"] == ReasonCode.NEW_BLOCK_BREACH.value
    assert checks["checked-in-sponsor-fixture"]["ok"] is True
    assert checks["checked-in-sponsor-fixture"]["evidence"]["package_hash"] == checks["fixture-inputs"]["evidence"]["package_hash"]
    assert checks["checked-in-sponsor-fixture"]["evidence"]["metrics_output_hash"]
    assert checks["checked-in-sponsor-fixture"]["evidence"]["package_archive_hash"]
    assert int(checks["schema-export-smoke"]["evidence"]["schema_count"]) >= 17


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


def test_run_rejects_output_inside_package_before_write(tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    out_dir = package / "redline-out"

    result = CliRunner().invoke(app, ["run", str(package), "--candidate", "candidate_good", "--out", str(out_dir), "--json"])

    assert result.exit_code == 4
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "redline.cli.error.v1"
    assert payload["reason_code"] == ReasonCode.RECEIPT_BINDING_FAILED.value
    assert not out_dir.exists()


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
            return 200, json.dumps({"run_id": "run-1", "version_id": "draft-1", "status": "completed", "metrics_output": metrics_output}).encode()
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
    run = adapter.run(version_id=upload.evidence["draft_id"])
    assert run.ok is True
    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id=upload.evidence["draft_id"],
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


def test_bitget_sponsor_poll_records_get_readback_transcript(tmp_path: Path) -> None:
    calls: list[tuple[str, str, dict[str, str], bytes]] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append((method, url, headers, body))
        return 200, json.dumps({"run_id": "run-42", "version_id": "version-42", "status": "completed"}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="poll-access-key",
        secret_key="poll-secret-key",
        passphrase="poll-passphrase",
        transcript_path=tmp_path / "poll-transcript.jsonl",
        transport=transport,
    )

    result = adapter.poll(run_id="run-42")

    assert result.ok is True
    assert result.state == SponsorState.RUN_COMPLETED
    assert result.evidence["run_id"] == "run-42"
    assert calls[0][0] == "GET"
    assert calls[0][1] == "https://api.bitget.com/api/v1/playbook/run?run_id=run-42"
    assert calls[0][3] == b""
    assert calls[0][2]["ACCESS-SIGN"]
    assert calls[0][2]["Content-Type"] == "application/json"
    transcript = (tmp_path / "poll-transcript.jsonl").read_text(encoding="utf-8")
    assert "poll-access-key" not in transcript
    assert "poll***-key" in transcript
    assert "/api/v1/playbook/run?run_id=run-42" in transcript


@pytest.mark.parametrize(
    ("case", "expected_reason"),
    [
        ("transport_exception", ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED),
        ("non_json", ReasonCode.SPONSOR_READBACK_MISMATCH),
        ("http_error", ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED),
        ("bitget_code_error", ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED),
        ("data_not_object", ReasonCode.SPONSOR_READBACK_MISMATCH),
    ],
)
def test_bitget_sponsor_http_failures_fail_closed(tmp_path: Path, case: str, expected_reason: ReasonCode) -> None:
    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        if case == "transport_exception":
            raise TimeoutError("timeout")
        if case == "non_json":
            return 200, b"{not-json"
        if case == "http_error":
            return 500, b'{"error":"server"}'
        if case == "bitget_code_error":
            return 200, b'{"code":"40001","msg":"denied","data":{}}'
        if case == "data_not_object":
            return 200, b'{"code":"00000","data":[]}'
        raise AssertionError(case)

    adapter = BitgetSponsorAdapter(
        access_key="failure-access-key",
        secret_key="fail-sec",
        passphrase="failure-passphrase",
        transcript_path=tmp_path / f"{case}-transcript.jsonl",
        transport=transport,
    )

    result = adapter.poll(run_id="run-failure")

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == expected_reason
    assert result.evidence["transcript_hash"] == sha256_bytes((tmp_path / f"{case}-transcript.jsonl").read_bytes())


def test_bitget_sponsor_upload_rejects_request_hash_mismatch(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert url.endswith("/api/v1/playbook/upload")
        return 200, json.dumps({"draft_id": "draft-1", "request_hash": "sha256:" + "0" * 64}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="request-access-key",
        secret_key="request-secret-key",
        passphrase="request-passphrase",
        transcript_path=tmp_path / "request-transcript.jsonl",
        transport=transport,
    )

    result = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert result.evidence["request_hash"].startswith("sha256:")
    assert result.evidence["response_request_hash"] == "sha256:" + "0" * 64


def test_bitget_sponsor_run_rejects_request_hash_mismatch(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append(url)
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"draft_id": "draft-1"}).encode()
        if url.endswith("/api/v1/playbook/run"):
            return 200, json.dumps({"run_id": "run-1", "request_hash": "sha256:" + "0" * 64}).encode()
        raise AssertionError(url)

    adapter = BitgetSponsorAdapter(
        access_key="request-access-key",
        secret_key="request-secret-key",
        passphrase="request-passphrase",
        transcript_path=tmp_path / "request-transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    assert upload.ok is True

    result = adapter.run(version_id="draft-1")

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert len(calls) == 2


def test_bitget_sponsor_poll_request_hash_binds_run_id(tmp_path: Path) -> None:
    hashes: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        return 200, json.dumps({"run_id": url.rsplit("=", 1)[-1], "version_id": "version-1", "status": "completed"}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="poll-access-key",
        secret_key="poll-secret-key",
        passphrase="poll-passphrase",
        transcript_path=tmp_path / "poll-transcript.jsonl",
        transport=transport,
    )

    hashes.append(adapter.poll(run_id="run-A").evidence["request_hash"])
    hashes.append(adapter.poll(run_id="run-B").evidence["request_hash"])

    assert hashes[0] != hashes[1]


def test_bitget_sponsor_transcript_rejects_symlink_output(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    transcript_path = tmp_path / "transcript.jsonl"
    os.symlink(victim, transcript_path)

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        return 200, json.dumps({"run_id": "run-1", "version_id": "version-1", "status": "completed"}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="poll-access-key",
        secret_key="poll-secret-key",
        passphrase="poll-passphrase",
        transcript_path=transcript_path,
        transport=transport,
    )

    with pytest.raises(CanonicalizationError):
        adapter.poll(run_id="run-1")
    assert victim.read_text(encoding="utf-8") == "keep\n"


def test_bitget_sponsor_session_identity_mismatch_fails_before_next_request(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append(url)
        if url.endswith("/api/v1/playbook/upload"):
            return 200, b'{"draft_id":"draft-1","version_id":"version-1"}'
        raise AssertionError("session mismatch must block before follow-up sponsor request")

    adapter = BitgetSponsorAdapter(
        access_key="identity-access-key",
        secret_key="id-sec",
        passphrase="identity-passphrase",
        transcript_path=tmp_path / "identity-transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    assert upload.ok is True

    run = adapter.run(version_id="wrong-version")

    assert run.ok is False
    assert run.state == SponsorState.MISMATCH
    assert run.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert run.evidence["expected_version_id"] == "draft-1"
    assert calls == ["https://api.bitget.com/api/v1/playbook/upload"]


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
            return 200, json.dumps({"run_id": "run-1", "version_id": "draft-1", "status": "completed", "metrics_output": {"unexpected": True}}).encode()
        return 404, b"{}"

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    run = adapter.run(version_id=upload.evidence["draft_id"])
    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id=upload.evidence["draft_id"],
        expected_metrics_output_hash=artifacts.receipt.result.result_hash,
        expected_package_hash=artifacts.receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence["package_archive_hash"],
    )
    assert readback.ok is False
    assert readback.state == SponsorState.MISMATCH
    assert readback.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_bitget_sponsor_live_readback_requires_observed_package_hashes(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"draft_id": "draft-1"}).encode()
        if url.endswith("/api/v1/playbook/run") and method == "POST":
            return 200, json.dumps({"run_id": "run-1", "version_id": "draft-1", "status": "started"}).encode()
        if "/api/v1/playbook/run?" in url and method == "GET":
            return 200, json.dumps(
                {
                    "code": "00000",
                    "data": {
                        "run_id": "run-1",
                        "version_id": "draft-1",
                        "status": "completed",
                        "metrics_output": {"return": 0},
                    },
                }
            ).encode()
        return 404, b"{}"

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    assert upload.ok is True
    run = adapter.run(version_id="draft-1")
    assert run.ok is True
    adapter.proof_eligible = True

    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id="draft-1",
        expected_package_hash=artifacts.receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence["package_archive_hash"],
    )

    assert readback.ok is False
    assert readback.state == SponsorState.MISMATCH
    assert readback.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert readback.evidence["readback_package_binding"] == "missing"


def _publish_ready_bitget_adapter(tmp_path: Path, publish_payload: dict[str, str]) -> BitgetSponsorAdapter:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"draft_id": "draft-1", "version_id": "version-1"}).encode()
        if url.endswith("/api/v1/playbook/run") and method == "POST":
            return 200, json.dumps({"run_id": "run-1", "status": "started"}).encode()
        if "/api/v1/playbook/run?" in url and method == "GET":
            metrics_output = {
                "status": artifacts.receipt.result.status,
                "breaches": [assertion.model_dump(mode="json") for assertion in artifacts.receipt.result.new_breaches],
            }
            return 200, json.dumps(
                {
                    "code": "00000",
                    "data": {
                        "run_id": "run-1",
                        "version_id": "draft-1",
                        "status": "completed",
                        "metrics_output": metrics_output,
                        "package_hash": artifacts.receipt.package.identity_hash,
                        "package_archive_hash": sha256_bytes(archive.read_bytes()),
                    },
                }
            ).encode()
        if url.endswith("/api/v1/playbook/publish"):
            return 200, json.dumps({"code": "00000", "data": publish_payload}).encode()
        return 404, b"{}"

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    assert upload.ok is True
    run = adapter.run(version_id=upload.evidence["draft_id"])
    assert run.ok is True
    adapter.proof_eligible = True
    readback = adapter.readback(
        run_id=run.evidence["run_id"],
        expected_version_id=upload.evidence["draft_id"],
        expected_package_hash=artifacts.receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence["package_archive_hash"],
    )
    assert readback.ok is True
    assert readback.state == SponsorState.READBACK_VERIFIED
    return adapter


def test_bitget_sponsor_run_requires_upload_session(tmp_path: Path) -> None:
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append(url)
        return 200, json.dumps({"run_id": "run-1"}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )

    result = adapter.run(version_id="version-1")

    assert result.ok is False
    assert result.state == SponsorState.LOCAL_PASS_REQUIRED
    assert result.evidence["required_step"] == "upload"
    assert calls == []


def test_bitget_sponsor_run_requires_uploaded_runnable_id(tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "package.tar.gz")
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append(url)
        if url.endswith("/api/v1/playbook/upload"):
            return 200, json.dumps({"suggested_version": "1.0.1"}).encode()
        return 200, json.dumps({"run_id": "run-1"}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )
    upload = adapter.upload(envelope=artifacts.envelope, package_hash=artifacts.receipt.package.identity_hash, package_archive=archive)
    assert upload.ok is True

    result = adapter.run(version_id="version-1")

    assert result.ok is False
    assert result.state == SponsorState.LOCAL_PASS_REQUIRED
    assert result.evidence["required_step"] == "upload.draft_id_or_version_id"
    assert len(calls) == 1


def test_bitget_sponsor_publish_requires_verified_readback_session(tmp_path: Path) -> None:
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        calls.append(url)
        return 200, json.dumps({"code": "00000", "data": {"status": "ok", "publish_id": "publish-1"}}).encode()

    adapter = BitgetSponsorAdapter(
        access_key="abcd1234secret5678",
        secret_key="secret-key-1",
        passphrase="passphrase-1",
        transcript_path=tmp_path / "transcript.jsonl",
        transport=transport,
    )

    result = adapter.publish(draft_id="draft-1")

    assert result.ok is False
    assert result.state == SponsorState.LOCAL_PASS_REQUIRED
    assert result.evidence["required_step"] == "readback"
    assert calls == []


def test_bitget_sponsor_publish_rejects_draft_id_mismatch_before_request(tmp_path: Path) -> None:
    adapter = _publish_ready_bitget_adapter(tmp_path, {"status": "ok", "publish_id": "publish-1"})
    before_transcript = (tmp_path / "transcript.jsonl").read_text(encoding="utf-8")

    result = adapter.publish(draft_id="wrong-draft")

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert result.evidence["expected_draft_id"] == "draft-1"
    assert (tmp_path / "transcript.jsonl").read_text(encoding="utf-8") == before_transcript


def test_bitget_publish_accepts_documented_version_id_success(tmp_path: Path) -> None:
    adapter = _publish_ready_bitget_adapter(tmp_path, {"status": "published", "version_id": "version-2", "version": "1.0.1"})

    result = adapter.publish(draft_id="draft-1")

    assert result.ok is True
    assert result.state == SponsorState.PUBLISHED
    assert result.evidence["version_id"] == "version-2"


def test_bitget_publish_rejects_failed_terminal_status(tmp_path: Path) -> None:
    adapter = _publish_ready_bitget_adapter(tmp_path, {"status": "failed", "publish_id": "publish-1"})

    result = adapter.publish(draft_id="draft-1")

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert result.evidence["transcript_hash"] == sha256_bytes((tmp_path / "transcript.jsonl").read_bytes())


def test_bitget_publish_requires_durable_publish_identifier(tmp_path: Path) -> None:
    adapter = _publish_ready_bitget_adapter(tmp_path, {"status": "ok"})

    result = adapter.publish(draft_id="draft-1")

    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_sponsor_evidence_verifier() -> None:
    result = validate_sponsor_evidence_shape(ROOT / "artifacts/sponsor/demo-readback.json")
    assert result.ok is False
    assert result.state == SponsorState.RECORDED_ATTESTATION_VALID
    assert result.reason_code == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED


def test_checked_in_sponsor_fixture_binds_current_demo_package(tmp_path: Path) -> None:
    data = json.loads((ROOT / "artifacts/sponsor/demo-readback.json").read_text(encoding="utf-8"))
    receipt = load_receipt(ROOT / "artifacts/demo/pass/receipt.json")
    package_hash = hash_tree(PACKAGE)
    archive = make_package_archive(package_dir=PACKAGE, out_path=tmp_path / "package.tar.gz")

    assert package_hash == receipt.package.identity_hash
    assert data["package_hash"] == receipt.package.identity_hash
    assert data["package_archive_hash"] == sha256_bytes(archive.read_bytes())
    assert data["metrics_output_hash"].startswith("sha256:")
    if data.get("expected_metrics_output_hash") is not None:
        assert data["expected_metrics_output_hash"] == data["metrics_output_hash"]


def test_receipt_bound_package_archive_is_independent_of_receipt_path_form(tmp_path: Path) -> None:
    absolute_archive, absolute_annotation = make_receipt_bound_package_archive(
        receipt_path=ROOT / "artifacts/demo/pass/receipt.json",
        package=PACKAGE,
        annotation_path=tmp_path / "absolute" / "redline-annotation.json",
        out_path=tmp_path / "absolute" / "annotated-package.tar.gz",
        package_hash=hash_tree(PACKAGE),
    )
    relative_archive, relative_annotation = make_receipt_bound_package_archive(
        receipt_path=Path("artifacts/demo/pass/receipt.json"),
        package=PACKAGE,
        annotation_path=tmp_path / "relative" / "redline-annotation.json",
        out_path=tmp_path / "relative" / "annotated-package.tar.gz",
        package_hash=hash_tree(PACKAGE),
    )

    assert absolute_annotation.receipt_path == "artifacts/demo/pass/receipt.json"
    assert relative_annotation.receipt_path == "artifacts/demo/pass/receipt.json"
    assert absolute_annotation.annotation_hash == relative_annotation.annotation_hash
    assert sha256_bytes(absolute_archive.read_bytes()) == sha256_bytes(relative_archive.read_bytes())


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


def test_live_sponsor_readback_requires_observed_package_binding(tmp_path: Path) -> None:
    metrics_output = {"status": "pass", "breaches": []}
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": hash_obj(metrics_output),
        "expected_version_id": "version-live-1",
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
    assert result.evidence["readback_package_binding"] == "missing"


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
    )
    assert result.ok is False
    assert result.state == SponsorState.MISMATCH
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    assert result.evidence["expected_package_archive_hash"] == "sha256:" + "0" * 64


def test_verify_sponsor_run_cli_binds_clean_package_archive(monkeypatch, tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "archive" / "package.tar.gz")
    archive_hash = sha256_bytes(archive.read_bytes())
    metrics_hash = hash_obj({"fixture": "sponsor-cli", "receipt_hash": artifacts.receipt.receipt_hash})
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": metrics_hash,
        "expected_version_id": "version-live-1",
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
                    "metrics_output_hash": evidence["metrics_output_hash"],
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
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--trust-policy",
            str(tmp_path / "trust-policy.json"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["state"] == SponsorState.READBACK_VERIFIED.value


def test_verify_sponsor_run_cli_package_archive_is_independent_of_ledger_attestation(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="custom-attestation-policy", key_id="custom-attestation-key", public_key=public_key, issuer="custom-ci")
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
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id=policy.policy_id, key_id="custom-attestation-key", issuer="custom-ci")
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
    checkpoint = LedgerCheckpoint.model_validate(json.loads((tmp_path / "run" / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8")))
    default_attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="custom-ci",
        trust_policy_id=policy.policy_id,
        key_id="custom-attestation-key",
        issuer="custom-ci",
        signed_at="2026-06-10T00:00:00Z",
    )
    default_attestation_path = tmp_path / "run" / "issuance-ledger.attestation.json"
    default_attestation_path.write_text(default_attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    alt_attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="custom-ci",
        trust_policy_id=policy.policy_id,
        key_id="custom-attestation-key",
        issuer="custom-ci",
        signed_at="2026-06-10T00:00:01Z",
    )
    alt_attestation_path = tmp_path / "alt-ledger.attestation.json"
    alt_attestation_path.write_text(alt_attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    default_archive, _default_annotation = make_receipt_bound_package_archive(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        annotation_path=tmp_path / "default-archive" / "redline-annotation.json",
        out_path=tmp_path / "default-archive" / "annotated-package.tar.gz",
        ledger_attestation_path=default_attestation_path,
    )
    alt_archive, _alt_annotation = make_receipt_bound_package_archive(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        annotation_path=tmp_path / "alt-archive" / "redline-annotation.json",
        out_path=tmp_path / "alt-archive" / "annotated-package.tar.gz",
        ledger_attestation_path=alt_attestation_path,
    )
    default_archive_hash = sha256_bytes(default_archive.read_bytes())
    alt_archive_hash = sha256_bytes(alt_archive.read_bytes())
    assert default_archive_hash != alt_archive_hash
    clean_archive = make_package_archive(package_dir=package, out_path=tmp_path / "clean-package.tar.gz")
    clean_archive_hash = sha256_bytes(clean_archive.read_bytes())
    metrics_hash = hash_obj({"fixture": "custom-attestation", "receipt_hash": artifacts.receipt.receipt_hash})
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-2",
        "version_id": "version-live-2",
        "status": "completed",
        "metrics_output_hash": metrics_hash,
        "expected_version_id": "version-live-2",
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": clean_archive_hash,
        "source_kind": "live",
        "proof_eligible": True,
        "transcript_hash": "sha256:" + "4" * 64,
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
                    "metrics_output_hash": evidence["metrics_output_hash"],
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
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--ledger-attestation",
            str(alt_attestation_path),
            "--trust-policy",
            str(policy_path),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["evidence"]["package_archive_hash"] == clean_archive_hash


def test_verify_sponsor_run_cli_replays_report_and_proof_sidecars_before_credentials(monkeypatch, tmp_path: Path) -> None:
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        monkeypatch.delenv(key, raising=False)
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "archive" / "package.tar.gz")
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": artifacts.receipt.result.result_hash,
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": artifacts.receipt.result.result_hash,
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": sha256_bytes(archive.read_bytes()),
        "source_kind": "live",
        "proof_eligible": True,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    proof_sidecar = next((tmp_path / "run" / "proofs").glob("proof_probe_*.json"))
    proof_backup = proof_sidecar.read_text(encoding="utf-8")
    proof_sidecar.unlink()
    missing_sidecar = CliRunner().invoke(
        app,
        [
            "verify-sponsor-run",
            str(evidence_path),
            "--receipt",
            str(tmp_path / "run" / "receipt.json"),
            "--package",
            str(package),
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--trust-policy",
            str(tmp_path / "trust-policy.json"),
            "--json",
        ],
    )
    assert missing_sidecar.exit_code == 4
    missing_payload = json.loads(missing_sidecar.stdout)
    assert missing_payload["state"] == SponsorState.MISMATCH.value
    assert missing_payload["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value

    proof_sidecar.write_text(proof_backup, encoding="utf-8")
    report_path = tmp_path / "run" / "report.json"
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    report_payload["receipt_hash"] = "sha256:" + "0" * 64
    report_path.write_text(json.dumps(report_payload), encoding="utf-8")
    tampered_report = CliRunner().invoke(
        app,
        [
            "verify-sponsor-run",
            str(evidence_path),
            "--receipt",
            str(tmp_path / "run" / "receipt.json"),
            "--package",
            str(package),
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--trust-policy",
            str(tmp_path / "trust-policy.json"),
            "--json",
        ],
    )
    assert tampered_report.exit_code == 4
    tampered_payload = json.loads(tampered_report.stdout)
    assert tampered_payload["state"] == SponsorState.MISMATCH.value
    assert tampered_payload["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value


def test_verify_sponsor_run_cli_requires_receipt_package_binding(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_ACCESS_KEY", "access")
    monkeypatch.setenv("REDLINE_BITGET_SECRET_KEY", "secret")
    monkeypatch.setenv("REDLINE_BITGET_PASSPHRASE", "passphrase")
    result = CliRunner().invoke(app, ["verify-sponsor-run", str(ROOT / "artifacts/sponsor/demo-readback.json"), "--json"])

    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "RECEIPT_PACKAGE_BINDING_REQUIRED"
    assert payload["reason_code"] == ReasonCode.DATA_MISSING.value


def test_verify_sponsor_run_cli_rejects_tampered_receipt_before_credentials(monkeypatch, tmp_path: Path) -> None:
    for key in [
        "REDLINE_BITGET_ACCESS_KEY",
        "REDLINE_BITGET_SECRET_KEY",
        "REDLINE_BITGET_PASSPHRASE",
        "BITGET_ACCESS_KEY",
        "BITGET_SECRET_KEY",
        "BITGET_PASSPHRASE",
    ]:
        monkeypatch.delenv(key, raising=False)
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "archive" / "package.tar.gz")
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": artifacts.receipt.result.result_hash,
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": artifacts.receipt.result.result_hash,
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": sha256_bytes(archive.read_bytes()),
        "source_kind": "live",
        "proof_eligible": True,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    receipt_path = tmp_path / "run" / "receipt.json"
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["result"]["result_hash"] = "sha256:" + "0" * 64
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "verify-sponsor-run",
            str(evidence_path),
            "--receipt",
            str(receipt_path),
            "--package",
            str(package),
            "--json",
        ],
    )
    assert result.exit_code == 4
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == SponsorState.MISMATCH.value
    assert payload["reason_code"] == ReasonCode.RECEIPT_MISMATCH.value


def test_verify_sponsor_run_cli_local_base_url_is_not_live_proof(monkeypatch, tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=package, out_path=tmp_path / "archive" / "package.tar.gz")
    archive_hash = sha256_bytes(archive.read_bytes())
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-local-1",
        "version_id": "version-local-1",
        "status": "completed",
        "metrics_output_hash": artifacts.receipt.result.result_hash,
        "expected_version_id": "version-local-1",
        "expected_metrics_output_hash": artifacts.receipt.result.result_hash,
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": archive_hash,
        "source_kind": "live",
        "proof_eligible": True,
        "transcript_hash": "sha256:" + "3" * 64,
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    def fake_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert url.startswith("http://127.0.0.1:18987/")
        payload = {
            "code": "00000",
            "data": {
                "run_id": evidence["run_id"],
                "version_id": evidence["expected_version_id"],
                "status": "completed",
                "metrics_output_hash": evidence["expected_metrics_output_hash"],
                "package_hash": evidence["package_hash"],
                "package_archive_hash": archive_hash,
            },
        }
        return 200, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr(bitget_module, "_urllib_transport", fake_transport)
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
            "--baseline-receipt",
            str(tmp_path / "baseline" / "receipt.json"),
            "--trust-policy",
            str(tmp_path / "trust-policy.json"),
            "--out-transcript",
            str(tmp_path / "transcript.jsonl"),
            "--base-url",
            "http://127.0.0.1:18987",
            "--json",
        ],
    )
    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == SponsorState.RECORDED_ATTESTATION_VALID.value
    assert payload["reason_code"] == ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value
    assert payload["evidence"]["proof_eligible"] == "false"


def test_execute_sponsor_readback_keeps_platform_metrics_separate_from_receipt_hash(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="sponsor-policy", key_id="sponsor-key", public_key=public_key, issuer="sponsor-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    write_identity_lock(package)
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
    observed_run_ids: list[str] = []

    class FakeAdapter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def upload(self, *, envelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None):
            with tarfile.open(package_archive, "r:gz") as tar:
                assert ".redline/redline-annotation.json" not in tar.getnames()
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
            observed_run_ids.append(version_id)
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
        trust_policy_hash=policy.policy_hash,
    )
    assert observed_run_ids == ["draft-1"]
    assert observed_expected_hashes == [None]
    assert result.ok is False
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH
    sponsor_proofs = sorted((tmp_path / "publish" / "proofs").glob("proof_sponsor_readback_*.json"))
    assert sponsor_proofs
    proof = json.loads(sponsor_proofs[0].read_text())
    assert proof["kind"] == ProofKind.SPONSOR_READBACK.value
    assert proof["meta"]["receipt_hash"] == artifacts.receipt.receipt_hash
    annotation = PackageAnnotation.model_validate(json.loads((tmp_path / "publish" / "redline-annotation.json").read_text(encoding="utf-8")))
    assert proof["meta"]["annotation_hash"] == annotation.annotation_hash
    assert proof["meta"]["annotation_file_hash"] == sha256_bytes((tmp_path / "publish" / "redline-annotation.json").read_bytes())


def test_execute_sponsor_readback_rejects_sponsor_readback_symlink(monkeypatch, tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    publish = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=tmp_path / "trust-policy.json",
        trust_policy_hash=json.loads((tmp_path / "trust-policy.json").read_text(encoding="utf-8"))["policy_hash"],
    )
    assert publish.ok is True
    victim = tmp_path / "readback-victim.json"
    victim.write_text("keep\n", encoding="utf-8")
    os.symlink(victim, tmp_path / "publish" / "sponsor-readback.json")

    class FakeAdapter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def upload(self, *, envelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None):
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.UPLOAD_ACCEPTED,
                evidence={"draft_id": "draft-1", "package_archive_hash": "sha256:" + "4" * 64},
            )

        def run(self, *, version_id: str):
            return surfaces_module.SponsorStepResult(ok=True, state=SponsorState.RUN_STARTED, evidence={"run_id": "run-1"})

        def readback(self, **kwargs: object):
            return surfaces_module.SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "run_id": "run-1",
                    "version_id": "draft-1",
                    "status": "completed",
                    "metrics_output_hash": "sha256:" + "9" * 64,
                    "package_hash": artifacts.receipt.package.identity_hash,
                    "package_archive_hash": "sha256:" + "4" * 64,
                    "transcript_hash": "sha256:" + "8" * 64,
                },
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", FakeAdapter)

    with pytest.raises(CanonicalizationError):
        execute_sponsor_readback(
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
            trust_policy_path=tmp_path / "trust-policy.json",
            trust_policy_hash=json.loads((tmp_path / "trust-policy.json").read_text(encoding="utf-8"))["policy_hash"],
        )
    assert victim.read_text(encoding="utf-8") == "keep\n"


def test_execute_sponsor_readback_rejects_proofs_symlink(monkeypatch, tmp_path: Path) -> None:
    package, artifacts = _make_chained_pass_fixture(tmp_path)
    assert artifacts.receipt is not None
    publish = publish_preflight(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish",
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=tmp_path / "trust-policy.json",
        trust_policy_hash=json.loads((tmp_path / "trust-policy.json").read_text(encoding="utf-8"))["policy_hash"],
    )
    assert publish.ok is True
    outside = tmp_path / "outside-proofs"
    outside.mkdir()
    os.symlink(outside, tmp_path / "publish" / "proofs")

    class FakeAdapter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def upload(self, *, envelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None):
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.UPLOAD_ACCEPTED,
                evidence={"draft_id": "draft-1", "package_archive_hash": "sha256:" + "4" * 64},
            )

        def run(self, *, version_id: str):
            return surfaces_module.SponsorStepResult(ok=True, state=SponsorState.RUN_STARTED, evidence={"run_id": "run-1"})

        def readback(self, **kwargs: object):
            return surfaces_module.SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "run_id": "run-1",
                    "version_id": "draft-1",
                    "status": "completed",
                    "metrics_output_hash": "sha256:" + "9" * 64,
                    "package_hash": artifacts.receipt.package.identity_hash,
                    "package_archive_hash": "sha256:" + "4" * 64,
                    "transcript_hash": "sha256:" + "8" * 64,
                },
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", FakeAdapter)

    with pytest.raises(CanonicalizationError):
        execute_sponsor_readback(
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
            trust_policy_path=tmp_path / "trust-policy.json",
            trust_policy_hash=json.loads((tmp_path / "trust-policy.json").read_text(encoding="utf-8"))["policy_hash"],
        )
    assert list(outside.iterdir()) == []


def test_execute_sponsor_readback_final_publish_uses_publish_transcript_hash(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="sponsor-policy", key_id="sponsor-key", public_key=public_key, issuer="sponsor-ci")
    policy_path = tmp_path / "trust-policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "baseline")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / "baseline", private_key, policy_id="sponsor-policy", key_id="sponsor-key", issuer="sponsor-ci")
    write_identity_lock(package)
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

    class FakeAdapter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def upload(self, *, envelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None):
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.UPLOAD_ACCEPTED,
                evidence={"version_id": "version-1", "draft_id": "draft-1", "package_archive_hash": "sha256:" + "4" * 64},
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
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.READBACK_VERIFIED,
                evidence={
                    "run_id": run_id,
                    "version_id": expected_version_id or "",
                    "metrics_output_hash": "sha256:" + "9" * 64,
                    "package_hash": expected_package_hash or "",
                    "package_archive_hash": expected_package_archive_hash or "",
                    "transcript_hash": "sha256:" + "1" * 64,
                },
            )

        def publish(self, *, draft_id: str, bump_type: str = "patch"):
            return surfaces_module.SponsorStepResult(
                ok=True,
                state=SponsorState.PUBLISHED,
                evidence={"publish_id": "publish-1", "draft_id": draft_id, "transcript_hash": "sha256:" + "2" * 64},
            )

    monkeypatch.setattr(surfaces_module, "BitgetSponsorAdapter", FakeAdapter)
    result = execute_sponsor_readback(
        receipt_path=tmp_path / "run" / "receipt.json",
        package=package,
        out_dir=tmp_path / "publish",
        access_key="access",
        secret_key="secret",
        passphrase="pass",
        final_publish=True,
        suite_path=SUITE,
        spec_path=SPEC,
        baseline_receipt_path=tmp_path / "baseline" / "receipt.json",
        ledger_attestation_path=tmp_path / "run" / "issuance-ledger.attestation.json",
        trust_policy_path=policy_path,
        trust_policy_hash=policy.policy_hash,
    )
    assert result.ok is True
    assert result.state == SponsorState.PUBLISHED
    assert result.evidence["transcript_hash"] == "sha256:" + "2" * 64


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
    write_identity_lock(package)
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
        trust_policy_hash=policy.policy_hash,
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
    result = CliRunner().invoke(
        app,
        [
            "verify-sponsor-run",
            str(ROOT / "artifacts/sponsor/demo-readback.json"),
            "--receipt",
            str(ROOT / "artifacts/demo/pass/receipt.json"),
            "--package",
            str(ROOT / "fixtures/demo_pack"),
            "--json",
        ],
    )
    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == "BITGET_CREDENTIALS_REQUIRED"
    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)
    schema = json.loads((schema_dir / "sponsor-step-result.v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)


def test_verify_sponsor_run_cli_preserves_amber_exit_after_successful_sponsor(monkeypatch, tmp_path: Path) -> None:
    artifacts = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / "run")
    assert artifacts.receipt is not None
    archive = make_package_archive(package_dir=PACKAGE, out_path=tmp_path / "archive" / "package.tar.gz")
    evidence = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": "run-live-1",
        "version_id": "version-live-1",
        "status": "completed",
        "metrics_output_hash": artifacts.receipt.result.result_hash,
        "expected_version_id": "version-live-1",
        "expected_metrics_output_hash": artifacts.receipt.result.result_hash,
        "package_hash": artifacts.receipt.package.identity_hash,
        "package_archive_hash": sha256_bytes(archive.read_bytes()),
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
            str(PACKAGE),
            "--json",
        ],
    )
    assert result.exit_code == 10
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["state"] == SponsorState.READBACK_VERIFIED.value
    assert payload["reason_code"] == ReasonCode.BASELINE_GENESIS.value
    assert payload["evidence"]["verification_reason_code"] == ReasonCode.BASELINE_GENESIS.value


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


def test_verify_sponsor_script_preserves_amber_exit_after_successful_sponsor(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "if [ \"$1 $2 $3\" = \"run redline check\" ]; then\n"
        "  printf '%s\\n' '{\"schema_version\":\"redline.verify.v1\",\"status\":\"unverified_no_verdict\",\"reason_code\":\"BASELINE_GENESIS\"}'\n"
        "  exit 10\n"
        "fi\n"
        "if [ \"$1 $2 $3\" = \"run redline verify-sponsor-run\" ]; then\n"
        "  printf '%s\\n' '{\"ok\":true,\"state\":\"READBACK_VERIFIED\",\"reason_code\":\"PASS\"}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 99\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    result = subprocess.run(
        [
            str(ROOT / "scripts/verify-sponsor-run.sh"),
            "evidence.json",
            "receipt.json",
            "package",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 10
    payload = json.loads(result.stdout)
    assert payload["receipt_exit_code"] == 10
    assert payload["sponsor_exit_code"] == 0
    assert payload["sponsor_readback"]["state"] == "READBACK_VERIFIED"


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
    data["expected_metrics_output_hash"] = data["metrics_output_hash"]
    data["metrics_output_hash"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    result = validate_sponsor_evidence_shape(path)
    assert result.ok is False
    assert result.reason_code == ReasonCode.SPONSOR_READBACK_MISMATCH


def test_public_json_surfaces_have_schemas(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    expected = {
        "decision-envelope.v1.schema.json",
        "doctor-result.v1.schema.json",
        "edit-provenance.v1.schema.json",
        "execution-evidence.v1.schema.json",
        "execution-ledger-entry.v1.schema.json",
        "ledger-attestation.v1.schema.json",
        "ledger-checkpoint.v1.schema.json",
        "package-annotation.v1.schema.json",
        "package-import.v1.schema.json",
        "playbook-identity-lock.v1.schema.json",
        "proof.v1.schema.json",
        "proof-verification.v1.schema.json",
        "publish-preflight.v1.schema.json",
        "receipt.v3.3.schema.json",
        "release-attestation.v1.schema.json",
        "report.v1.schema.json",
        "sponsor-readback-evidence.v1.schema.json",
        "sponsor-step-result.v1.schema.json",
        "spec.v2.2.schema.json",
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


def test_public_json_artifacts_validate_against_exported_schemas(tmp_path: Path) -> None:
    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)

    def validate(schema_name: str, payload: object) -> None:
        schema = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(payload)

    for run_name in ["pass", "withheld"]:
        run_dir = ROOT / "artifacts/demo" / run_name
        validate("receipt.v3.3.schema.json", json.loads((run_dir / "receipt.json").read_text(encoding="utf-8")))
        validate("decision-envelope.v1.schema.json", json.loads((run_dir / "envelope.json").read_text(encoding="utf-8")))
        validate("ledger-checkpoint.v1.schema.json", json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8")))
        for proof_path in sorted((run_dir / "proofs").glob("*.json")):
            validate("proof.v1.schema.json", json.loads(proof_path.read_text(encoding="utf-8")))

    validate("sponsor-readback-evidence.v1.schema.json", json.loads((ROOT / "artifacts/sponsor/demo-readback.json").read_text(encoding="utf-8")))
    verification = verify(
        receipt_path=ROOT / "artifacts/demo/withheld/receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        level=VerificationLevel.REPLAYED,
    )
    validate("verification-result.v1.schema.json", verification.model_dump(mode="json"))
    preflight = publish_preflight(
        receipt_path=ROOT / "artifacts/demo/pass/receipt.json",
        package=PACKAGE,
        suite_path=SUITE,
        spec_path=SPEC,
        out_dir=tmp_path / "publish-preflight",
        allow_demo_baseline_genesis=True,
    )
    validate("publish-preflight.v1.schema.json", preflight.model_dump(mode="json"))
    doctor_result = cli_module._run_doctor(package=PACKAGE, suite=SUITE, spec=SPEC)
    validate("doctor-result.v1.schema.json", doctor_result.model_dump(mode="json"))


def test_checked_in_demo_reports_validate_and_bind_receipts(tmp_path: Path) -> None:
    schema_dir = tmp_path / "schemas"
    export_schemas(schema_dir)
    report_schema = json.loads((schema_dir / "report.v1.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(report_schema)

    for run_name in ["pass", "withheld"]:
        run_dir = ROOT / "artifacts/demo" / run_name
        report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
        receipt = Receipt.model_validate(json.loads((run_dir / "receipt.json").read_text(encoding="utf-8")))
        envelope = DecisionEnvelope.model_validate(json.loads((run_dir / "envelope.json").read_text(encoding="utf-8")))
        sidecar_proofs = [
            Proof.model_validate(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted((run_dir / "proofs").glob("*.json"))
        ]

        validator.validate(report)
        ReportJson.model_validate(report)
        assert report["envelope"] == envelope.model_dump(mode="json")
        assert report["receipt_hash"] == receipt.receipt_hash
        assert report["strength_summary"] == receipt.strength_summary
        assert report["proof_ids"] == [proof.proof_id for proof in receipt.proofs]
        assert sorted(report["proof_ids"]) == sorted(proof.proof_id for proof in sidecar_proofs)
        hash_payload = {key: value for key, value in report.items() if key != "report_hash"}
        hash_payload["receipt_hash"] = None
        assert report["report_hash"] == hash_obj(hash_payload)
        assert report["report_hash"] == receipt.report.report_hash


def test_composite_action_runs_against_caller_workspace() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert 'allow-amber-baseline-genesis:' in action
    assert 'default: candidate_good' in action
    assert 'default: "false"' in action
    assert "astral-sh/setup-uv@v8.2.0" in action
    assert "working-directory: ${{ github.workspace }}" in action
    assert 'REDLINE_ACTION_PACKAGE: ${{ inputs.package }}' in action
    assert 'resolve_workspace_path()' in action
    assert 'hash_package_tree()' in action
    assert 'candidate.relative_to(workspace)' in action
    assert 'echo "package_hash=$package_hash"' in action
    assert 'echo "demo_package_hash=$demo_package_hash"' in action
    assert 'uv --project "$GITHUB_ACTION_PATH" run redline run "$package_path"' in action
    assert '[ "$REDLINE_ACTION_PACKAGE" = "fixtures/demo_pack" ]' in action
    assert '[ "$REDLINE_ACTION_PACKAGE_HASH" = "$REDLINE_ACTION_DEMO_PACKAGE_HASH" ]' in action
    assert '${{ github.workspace }}/${{ inputs.package }}' not in action
    assert "path: ${{ steps.redline.outputs.out_path }}" in action
    assert "${{ github.workspace }}/${{ inputs.out }}" not in action


def test_composite_action_workspace_path_resolver_rejects_escape_and_metachar_execution(tmp_path: Path) -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    run_section = action.split("    - name: Run Redline", 1)[1].split("    - uses: actions/upload-artifact@v4", 1)[0]
    run_block = textwrap.dedent(run_section.split("      run: |\n", 1)[1])
    resolver = run_block.split('echo "out_path=$GITHUB_WORKSPACE/artifacts/action-redline"', 1)[0]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "marker"

    def resolve(raw: str) -> subprocess.CompletedProcess[str]:
        script = (
            resolver
            + "\n"
            + 'resolved="$(resolve_workspace_path out "$REDLINE_ACTION_OUT")"\n'
            + "code=$?\n"
            + 'printf "%s\\n%s\\n" "$code" "$resolved"\n'
        )
        env = {**os.environ, "GITHUB_WORKSPACE": str(workspace), "REDLINE_ACTION_OUT": raw}
        return subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=False, capture_output=True, text=True)

    escaped = resolve("../outside")
    assert escaped.stdout.splitlines()[0] == "64"
    assert "escapes GITHUB_WORKSPACE" in escaped.stderr

    valid = resolve(f"artifacts/out dir$(touch {marker})")
    valid_lines = valid.stdout.splitlines()
    assert valid_lines[0] == "0"
    assert valid_lines[1] == str(workspace / f"artifacts/out dir$(touch {marker})")
    assert not marker.exists()


def test_composite_action_run_and_enforce_steps_execute_with_fake_uv(tmp_path: Path) -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    run_section = action.split("    - name: Run Redline", 1)[1].split("    - uses: actions/upload-artifact@v4", 1)[0]
    run_block = textwrap.dedent(run_section.split("      run: |\n", 1)[1])
    enforce_section = action.split("    - name: Enforce Redline result", 1)[1]
    enforce_block = textwrap.dedent(enforce_section.split("      run: |\n", 1)[1])
    workspace = tmp_path / "workspace"
    action_path = tmp_path / "action"
    fake_bin = tmp_path / "bin"
    output_path = tmp_path / "github-output.txt"
    log_path = tmp_path / "uv.log"
    (workspace / "fixtures/demo_pack").mkdir(parents=True)
    (workspace / "fixtures/suites").mkdir(parents=True)
    (workspace / "fixtures/specs").mkdir(parents=True)
    (workspace / "fixtures/suites/demo_suite.json").write_text("{}", encoding="utf-8")
    (workspace / "fixtures/specs/redline_spec.json").write_text("{}", encoding="utf-8")
    (action_path / "fixtures/demo_pack").mkdir(parents=True)
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_UV_LOG"
if [ "${4:-}" = "python" ]; then
  cat >/dev/null
  target="${@: -1}"
  if [ "$target" = "$GITHUB_ACTION_PATH/fixtures/demo_pack" ]; then
    printf '%s\n' "$FAKE_DEMO_HASH"
  else
    printf '%s\n' "$FAKE_PACKAGE_HASH"
  fi
  exit 0
fi
if [ "${4:-}" = "redline" ] && [ "${5:-}" = "run" ]; then
  exit "${FAKE_REDLINE_EXIT:-0}"
fi
exit 70
""",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_ACTION_PATH": str(action_path),
        "GITHUB_OUTPUT": str(output_path),
        "REDLINE_ACTION_PACKAGE": "fixtures/demo_pack",
        "REDLINE_ACTION_BASELINE": "baseline",
        "REDLINE_ACTION_CANDIDATE": "candidate_good",
        "REDLINE_ACTION_SUITE": "fixtures/suites/demo_suite.json",
        "REDLINE_ACTION_SPEC": "fixtures/specs/redline_spec.json",
        "REDLINE_ACTION_OUT": "artifacts/action-redline",
        "FAKE_PACKAGE_HASH": "sha256:" + "1" * 64,
        "FAKE_DEMO_HASH": "sha256:" + "1" * 64,
        "FAKE_REDLINE_EXIT": "10",
        "FAKE_UV_LOG": str(log_path),
    }

    run_result = subprocess.run(["bash", "-c", run_block], cwd=workspace, env=env, check=False, capture_output=True, text=True)

    assert run_result.returncode == 0, run_result.stderr
    outputs = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
    assert outputs["exit_code"] == "10"
    assert outputs["package_hash"] == env["FAKE_PACKAGE_HASH"]
    assert outputs["demo_package_hash"] == env["FAKE_DEMO_HASH"]
    assert outputs["out_path"] == str(workspace / "artifacts/action-redline")
    uv_log = log_path.read_text(encoding="utf-8")
    assert "redline run" in uv_log
    assert str(workspace / "fixtures/demo_pack") in uv_log

    enforce_script = enforce_block.replace("${{ steps.redline.outputs.exit_code }}", outputs["exit_code"])
    enforce_env = {
        **os.environ,
        "REDLINE_ACTION_ALLOW_AMBER_BASELINE_GENESIS": "true",
        "REDLINE_ACTION_PACKAGE": "fixtures/demo_pack",
        "REDLINE_ACTION_PACKAGE_HASH": outputs["package_hash"],
        "REDLINE_ACTION_DEMO_PACKAGE_HASH": outputs["demo_package_hash"],
    }
    assert subprocess.run(["bash", "-c", enforce_script], check=False, env=enforce_env).returncode == 0
    enforce_env["REDLINE_ACTION_DEMO_PACKAGE_HASH"] = "sha256:" + "2" * 64
    assert subprocess.run(["bash", "-c", enforce_script], check=False, env=enforce_env).returncode == 10
    enforce_env["REDLINE_ACTION_DEMO_PACKAGE_HASH"] = outputs["demo_package_hash"]
    enforce_env["REDLINE_ACTION_ALLOW_AMBER_BASELINE_GENESIS"] = "false"
    assert subprocess.run(["bash", "-c", enforce_script], check=False, env=enforce_env).returncode == 10


def test_composite_action_amber_exception_requires_demo_package_hash(tmp_path: Path) -> None:
    def enforce(package: str, *, allow: str = "true", package_hash: str = "sha256:" + "1" * 64, demo_hash: str = "sha256:" + "1" * 64) -> int:
        marker = tmp_path / "marker"
        script = (
            'code=10\n'
            'if [ "$code" -eq 10 ] && [ "$REDLINE_ACTION_ALLOW_AMBER_BASELINE_GENESIS" = "true" ] && [ "$REDLINE_ACTION_PACKAGE" = "fixtures/demo_pack" ] && [ -n "$REDLINE_ACTION_PACKAGE_HASH" ] && [ "$REDLINE_ACTION_PACKAGE_HASH" = "$REDLINE_ACTION_DEMO_PACKAGE_HASH" ]; then\n'
            "  exit 0\n"
            "fi\n"
            'exit "$code"\n'
        )
        env = {
            **os.environ,
            "REDLINE_ACTION_ALLOW_AMBER_BASELINE_GENESIS": allow,
            "REDLINE_ACTION_PACKAGE": package,
            "REDLINE_ACTION_PACKAGE_HASH": package_hash,
            "REDLINE_ACTION_DEMO_PACKAGE_HASH": demo_hash,
        }
        result = subprocess.run(["bash", "-c", script], check=False, env=env)
        assert not marker.exists()
        return result.returncode

    assert enforce("fixtures/demo_pack") == 0
    assert enforce("fixtures/demo_pack", allow="false") == 10
    assert enforce("fixtures/demo_pack", demo_hash="sha256:" + "2" * 64) == 10
    assert enforce("fixtures/not_demo_pack") == 10
    assert enforce(f"fixtures/demo_pack$(touch {tmp_path / 'marker'})") == 10


def test_ci_checks_sponsor_fixture_and_strict_demo_genesis() -> None:
    workflow = (ROOT / ".github/workflows/redline-ci.yml").read_text(encoding="utf-8")
    assert "actions/checkout@v6" in workflow
    assert "astral-sh/setup-uv@v8.2.0" in workflow
    assert "uv run python scripts/verify-sponsor-fixture.py" in workflow
    assert "bash scripts/deployment-smoke.sh" in workflow
    assert "postgres:18" in workflow
    assert "REDLINE_TEST_POSTGRES_URL" in workflow
    assert "bash scripts/remote-smoke.sh" in workflow
    assert "scripts/remote-production-check.py --require-cors" in workflow
    assert "REDLINE_REMOTE_FRONTEND_ORIGIN" in workflow
    assert "git diff --exit-code -- schemas artifacts/demo artifacts/sponsor" in workflow
    assert 'test "$code" -eq 10' in workflow
    assert 'test "$code" -eq 0 -o "$code" -eq 10' not in workflow
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "render-preflight:" in makefile
    assert "remote-smoke-actions:" in makefile
    assert (ROOT / "scripts/render-blueprint-preflight.sh").is_file()
    assert (ROOT / "scripts/remote-smoke-actions.sh").is_file()


def test_verify_evidence_workflow_guards_zero_key_release_chain() -> None:
    workflow = (ROOT / ".github/workflows/verify-evidence.yml").read_text(encoding="utf-8")
    assert "actions/checkout@v6" in workflow
    assert "astral-sh/setup-uv@v8.2.0" in workflow
    assert "uv sync --frozen --extra dev" in workflow
    assert "uv run python scripts/check-verdict-path-imports.py" in workflow
    assert 'uv run --extra dev pytest -q -k "verdict_path_import_gate or purity"' in workflow
    assert "uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json" in workflow
    assert "scripts/tamper-demo.sh" in workflow
    assert 'test "$code" -ne 0' in workflow
    assert "REDLINE_BITGET" not in workflow
    assert "REDLINE_ATTESTATION_PRIVATE_KEY" not in workflow
    assert "release-demo.sh" not in workflow


def test_zero_key_judge_docs_and_openapi_contract_are_current() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    backend = (ROOT / "BACKEND_COMPLETENESS.md").read_text(encoding="utf-8")
    service_api = (ROOT / "SERVICE_API.md").read_text(encoding="utf-8")
    openapi = json.loads((ROOT / "schemas/service-openapi.json").read_text(encoding="utf-8"))
    paths = openapi["paths"]

    zero_key_commands = [
        "uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json",
        "scripts/tamper-demo.sh",
        "open artifacts/release-demo/current/evidence.html",
    ]

    for text in [readme, backend]:
        assert "评委 60 秒零密钥复核" in text
        assert "demo-only" in text
        assert "paptrading: 1" in text
        assert "非 Bitget Playbook 正式发布" in text
        assert "不需要 Bitget demo credentials" in text
        for command in zero_key_commands:
            assert command in text

    assert "Judge 60-second zero-key review" in service_api
    assert "judge button" in service_api
    assert "EVIDENCE INVALID" in service_api
    for command in zero_key_commands:
        assert command in service_api

    for path in [
        "/v1/release-candidates/{release_id}/evidence.html",
        "/v1/release-candidates/{release_id}/demo-showcase-orders",
        "/v1/release-candidates/{release_id}/jobs/execute-demo",
        "/v1/release-candidates/{release_id}/jobs/{job_id}/events",
        "/v1/release-candidates/{release_id}/jobs/{job_id}/events.ndjson",
        "/v1/judge/console",
    ]:
        assert path in paths


def test_distinct_codes_cover_evidence_chain_surfaces() -> None:
    distinct_codes = {
        "proof": ReasonCode.PROOF_HASH_MISMATCH,
        "ledger": ReasonCode.LEDGER_CHAIN_BROKEN,
        "checkpoint": ReasonCode.CHECKPOINT_MISMATCH,
        "execution": ReasonCode.EXECUTION_LEDGER_BROKEN,
        "merkle": ReasonCode.MERKLE_INCLUSION_FAILED,
        "approval": ReasonCode.APPROVAL_LINK_MISMATCH,
        "approval_consumed": ReasonCode.APPROVAL_CONSUMED,
        "approval_expired": ReasonCode.APPROVAL_EXPIRED,
        "chain": ReasonCode.CHAIN_LINK_MISMATCH,
    }

    assert len(set(distinct_codes.values())) == len(distinct_codes)
    assert ReasonCode.RECEIPT_MISMATCH not in distinct_codes.values()


def test_violation_reason_code_schemas_and_exit_codes_are_in_sync() -> None:
    reason_values = {item.value for item in ReasonCode}
    assert set(cli_module.EXIT_BY_REASON) == set(ReasonCode)
    for schema_name in [
        "decision-envelope.v1.schema.json",
        "proof-verification.v1.schema.json",
        "receipt.v3.3.schema.json",
        "report.v1.schema.json",
        "verification-result.v1.schema.json",
    ]:
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        schema_values = set(schema["$defs"]["ReasonCode"]["enum"])
        assert reason_values <= schema_values


def test_violation_catalog_in_sync(tmp_path: Path) -> None:
    from redline.violations import REASON_META, render_violation_catalog

    assert set(REASON_META) == set(ReasonCode)
    for code, meta in REASON_META.items():
        assert meta.severity in {"blocking", "advisory"}
        assert isinstance(meta.recoverable, bool)
        assert meta.summary
        assert code.value in meta.summary or code is ReasonCode.PASS

    generated = render_violation_catalog()
    checked_in = (ROOT / "docs/VIOLATION_CODES.md").read_text(encoding="utf-8")
    assert checked_in == generated

    result = subprocess.run(
        [sys.executable, "scripts/gen-violation-catalog.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_evidence_html_golden_regenerated_from_code() -> None:
    current = ROOT / "artifacts/release-demo/current"
    runs_dir = current / "service" / "runs"
    html_path = current / "evidence.html"
    assert html_path.exists()
    assert runs_dir.exists()

    run_dirs = sorted(path for path in runs_dir.iterdir() if path.is_dir() and (path / "receipt.json").exists())
    good_run_dir = next(path for path in run_dirs if (path / "execution-evidence.json").exists())
    bad_run_dir = next(path for path in run_dirs if load_receipt(path / "receipt.json").result.status == Status.WITHHELD)

    regenerated_html = render_evidence_comparison_html(
        load_evidence_panel(good_run_dir, title="PASS -> Bitget demo order"),
        load_evidence_panel(bad_run_dir, title="WITHHELD -> blocked before Bitget"),
    )

    assert regenerated_html == html_path.read_text(encoding="utf-8")
    assert HONEST_STATEMENT in regenerated_html
    assert "Bitget 未被调用" in regenerated_html
    assert "passphrase" not in regenerated_html.lower()
    assert "access key" not in regenerated_html.lower()
    for run_dir in [good_run_dir, bad_run_dir]:
        receipt_path = run_dir / "receipt.json"
        receipt = load_receipt(receipt_path)
        assert compute_receipt_hash(receipt) == receipt.receipt_hash
        assert receipt.model_dump_json(indent=2) + "\n" == receipt_path.read_text(encoding="utf-8")


def test_locked_golden_case_manifest_matches_spec() -> None:
    manifest = [
        {"case": "pass-receipt", "artifact": "artifacts/demo/pass/receipt.json", "expected_exit": 10, "reason_code": ReasonCode.BASELINE_GENESIS},
        {"case": "withheld-receipt", "artifact": "artifacts/demo/withheld/receipt.json", "expected_exit": 3, "reason_code": ReasonCode.NEW_BLOCK_BREACH},
        {"case": "tampered-reject", "mutator": "receipt_hash_zero", "expected_exit": 4, "reason_code": ReasonCode.RECEIPT_MISMATCH},
        {"case": "missing-proof-reject", "mutator": "drop_required_verdict_proof", "expected_exit": 6, "reason_code": ReasonCode.UNVERIFIED_NO_VERDICT},
        {"case": "genesis", "artifact": "artifacts/demo/pass/issuance-ledger.checkpoint.json", "expected_exit": 10, "reason_code": ReasonCode.BASELINE_GENESIS},
        {"case": "echo-mismatch", "mutator": "sponsor_request_hash_echo_mismatch", "expected_exit": 8, "reason_code": ReasonCode.SPONSOR_READBACK_MISMATCH},
        {"case": "crash-baseline", "artifact": "fixtures/suites/btc_crash.csv", "expected_exit": 0, "reason_code": ReasonCode.PASS},
        {"case": "crash-candidate", "artifact": "fixtures/suites/btc_crash.csv", "expected_exit": 3, "reason_code": ReasonCode.NEW_BLOCK_BREACH},
        {"case": "chop-baseline", "artifact": "fixtures/suites/btc_chop.csv", "expected_exit": 0, "reason_code": ReasonCode.PASS},
        {"case": "chop-candidate", "artifact": "fixtures/suites/btc_chop.csv", "expected_exit": 0, "reason_code": ReasonCode.PASS},
        {"case": "provenance-locked", "artifact": "fixtures/demo_pack/playbook_identity.lock", "expected_exit": 4, "reason_code": ReasonCode.RECEIPT_BINDING_FAILED},
        {"case": "sponsor-readback-evidence-shape", "artifact": "artifacts/sponsor/demo-readback.json", "expected_exit": 6, "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED},
    ]

    assert [item["case"] for item in manifest] == [
        "pass-receipt",
        "withheld-receipt",
        "tampered-reject",
        "missing-proof-reject",
        "genesis",
        "echo-mismatch",
        "crash-baseline",
        "crash-candidate",
        "chop-baseline",
        "chop-candidate",
        "provenance-locked",
        "sponsor-readback-evidence-shape",
    ]
    assert len(manifest) == 12
    for item in manifest:
        assert isinstance(item["expected_exit"], int)
        assert item["reason_code"] in ReasonCode
        assert ("artifact" in item) ^ ("mutator" in item)
        if "artifact" in item:
            assert (ROOT / str(item["artifact"])).exists()


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
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=None)
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
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    artifacts = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=SUITE, spec_path=SPEC, out_dir=None)
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


def test_verifier_rejects_duplicate_same_key_ledger_entry(tmp_path: Path) -> None:
    source = ROOT / "artifacts/demo/withheld"
    for name in ("receipt.json", "issuance-ledger.jsonl"):
        shutil.copyfile(source / name, tmp_path / name)
    receipt = load_receipt(tmp_path / "receipt.json")
    key_hash = hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )
    ledger_path = tmp_path / "issuance-ledger.jsonl"
    last_entry = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[-1])
    duplicate = {
        "key_hash": key_hash,
        "status": receipt.result.status,
        "receipt_hash": "sha256:" + "1" * 64,
        "previous_entry_hash": last_entry["entry_hash"],
        "written_at": "2026-06-10T00:00:01Z",
    }
    duplicate["entry_hash"] = hash_obj(duplicate)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(duplicate, sort_keys=True))
        fh.write("\n")
    create_ledger_checkpoint(
        ledger_path=ledger_path,
        checkpoint_path=tmp_path / "issuance-ledger.checkpoint.json",
        subject_receipt_hashes=[receipt.receipt_hash],
        ledger_path_label="issuance-ledger.jsonl",
    )

    result = verify(receipt_path=tmp_path / "receipt.json", level=VerificationLevel.HASH_ONLY)

    assert result.status == VerificationStatus.REJECTED
    assert result.reason_code == ReasonCode.RECEIPT_MISMATCH


def test_legacy_v32_receipt_hash_is_back_compatible():
    """Cross-version back-compat: a real pre-v3.3 receipt (committed fixture, issued before
    the v3.3 optional fields existed) must still hash to its stored value under the current
    exclude-none canonical hashing — i.e. it reads as intact, not tampered. This is a frozen
    real-artifact guard (not self-referential): it pins the exact hash a previous release
    produced, so re-introducing the include-none regression fails here."""
    fixture = Path(__file__).parent / "fixtures" / "legacy-receipt-v3.2.json"
    receipt = Receipt.model_validate(json.loads(fixture.read_text(encoding="utf-8")))
    assert receipt.version == "redline.receipt.v3.2"
    assert compute_receipt_hash(receipt) == receipt.receipt_hash
