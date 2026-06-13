from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import CanonicalizationError, hash_file, hash_obj, hash_tree
from redline.models import (
    LedgerCheckpoint,
    LedgerCheckpointAttestation,
    Proof,
    ProofKind,
    ProofVerification,
    ReasonCode,
    Receipt,
    ReportJson,
    Status,
    TrustPolicy,
    VerificationLevel,
    VerificationResult,
    VerificationStatus,
)
from redline.proof_kernel import REQUIRED_PROOFS, decision_envelope_from_receipt, decision_proof_id
from redline.receipt import compute_receipt_hash
from redline.report import render_strength_summary, to_report
from redline.trust import verify_checkpoint_attestation

BAD_INPUT = {ReasonCode.FILE_NOT_FOUND, ReasonCode.PARSE_ERROR, ReasonCode.SCHEMA_INVALID, ReasonCode.VERSION_UNSUPPORTED}
SINGLETON_PROOF_KINDS = {
    ProofKind.PACKAGE_CANONICAL,
    ProofKind.SPEC_COMPILE,
    ProofKind.REPLAY,
    ProofKind.REPLAY_WELLFORMED,
    ProofKind.COVERAGE,
    ProofKind.BASELINE_CALIBRATION,
    ProofKind.CANDIDATE_ABSOLUTE,
    ProofKind.DECISION,
}
NON_VERDICT_PROOF_KINDS = {ProofKind.EDIT_PROVENANCE, ProofKind.SPONSOR_READBACK}


def load_receipt(path: Path) -> Receipt:
    with path.open(encoding="utf-8") as fh:
        return Receipt.model_validate(json.load(fh))


def verify(
    *,
    receipt_path: Path,
    package: Path | None = None,
    level: VerificationLevel | None = None,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
    report_path: Path | None = None,
    ledger_path: Path | None = None,
    ledger_checkpoint_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    trusted_ledger_public_key: str | None = None,
    trust_policy_path: Path | None = None,
    baseline_receipt_path: Path | None = None,
) -> VerificationResult:
    level = level or VerificationLevel.HASH_ONLY
    try:
        if not receipt_path.exists():
            return _bad(ReasonCode.FILE_NOT_FOUND, level)
        with receipt_path.open(encoding="utf-8") as fh:
            payload = json.load(fh)
        if payload.get("version") != "redline.receipt.v3.2":
            return _bad(ReasonCode.VERSION_UNSUPPORTED, level)
        receipt = Receipt.model_validate(payload)
    except (json.JSONDecodeError, OSError):
        return _bad(ReasonCode.PARSE_ERROR, level)
    except ValidationError:
        return _bad(ReasonCode.SCHEMA_INVALID, level)

    recomputed = compute_receipt_hash(receipt)
    if recomputed != receipt.receipt_hash:
        return _reject(receipt, ReasonCode.RECEIPT_MISMATCH, level)
    status = Status(receipt.result.status)
    missing = _missing_required_proof_ids(receipt, status)
    if missing:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED_NO_VERDICT,
            reason_code=ReasonCode.UNVERIFIED_NO_VERDICT,
            verification_level=level,
            receipt_hash=receipt.receipt_hash,
            strength_summary=receipt.strength_summary,
            chain_status=receipt.baseline.chain_status,
            edit_provenance_present=True,
            proof_coverage="incomplete",
            missing_proof_ids=missing,
        )
    binding_error = _receipt_binding_error(receipt)
    if binding_error is not None:
        return _reject(receipt, binding_error, level)
    default_ledger_path = receipt_path.parent / "issuance-ledger.jsonl"
    default_checkpoint_path = receipt_path.parent / "issuance-ledger.checkpoint.json"
    default_attestation_path = receipt_path.parent / "issuance-ledger.attestation.json"
    if level == VerificationLevel.REPLAYED and ledger_path is not None and ledger_path.resolve() != default_ledger_path.resolve():
        return _reject(receipt, ReasonCode.RECEIPT_MISMATCH, level)
    ledger_error = _ledger_error(
        receipt=receipt,
        ledger_path=ledger_path or default_ledger_path,
        checkpoint_path=(ledger_checkpoint_path or default_checkpoint_path) if level == VerificationLevel.REPLAYED else ledger_checkpoint_path,
        attestation_path=(ledger_attestation_path or default_attestation_path) if trusted_ledger_public_key is not None or trust_policy_path is not None else ledger_attestation_path,
        trusted_ledger_public_key=trusted_ledger_public_key,
        trust_policy_path=trust_policy_path,
    )
    if ledger_error is not None:
        return _reject(receipt, ledger_error, level)
    if not receipt.coverage.complete:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED_NO_VERDICT,
            reason_code=ReasonCode.COVERAGE_INCOMPLETE,
            verification_level=level,
            receipt_hash=receipt.receipt_hash,
            strength_summary=receipt.strength_summary,
            chain_status=receipt.baseline.chain_status,
            edit_provenance_present=True,
            proof_coverage="incomplete",
            missing_proof_ids=receipt.coverage.missing,
        )
    if render_strength_summary(receipt) != receipt.strength_summary:
        return _reject(receipt, ReasonCode.RECEIPT_MISMATCH, level)
    if level == VerificationLevel.REPLAYED and package is None:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED_NO_VERDICT,
            reason_code=ReasonCode.UNVERIFIED_NO_VERDICT,
            verification_level=level,
            receipt_hash=receipt.receipt_hash,
            strength_summary=receipt.strength_summary,
            chain_status=receipt.baseline.chain_status,
            edit_provenance_present=True,
            proof_coverage="complete",
        )
    if level == VerificationLevel.HASH_ONLY:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED_NO_VERDICT,
            reason_code=ReasonCode.UNVERIFIED_NO_VERDICT,
            verification_level=level,
            receipt_hash=receipt.receipt_hash,
            strength_summary=receipt.strength_summary,
            chain_status=receipt.baseline.chain_status,
            edit_provenance_present=True,
            proof_coverage="complete",
        )
    if level == VerificationLevel.REPLAYED and package is not None:
        if suite_path is None or spec_path is None:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED_NO_VERDICT,
                reason_code=ReasonCode.DATA_MISSING,
                verification_level=level,
                receipt_hash=receipt.receipt_hash,
                strength_summary=receipt.strength_summary,
                chain_status=receipt.baseline.chain_status,
                edit_provenance_present=True,
                proof_coverage="complete",
            )
        try:
            package_hash = hash_tree(package)
        except CanonicalizationError as exc:
            return _reject(receipt, exc.reason_code, level)
        except (OSError, ValueError):
            return _bad(ReasonCode.FILE_NOT_FOUND, level)
        if package_hash != receipt.package.identity_hash:
            return _reject(receipt, ReasonCode.RECEIPT_BINDING_FAILED, level)
        proofs_error = _external_proofs_error(receipt=receipt, proofs_dir=receipt_path.parent / "proofs")
        if proofs_error is not None:
            return _reject(receipt, proofs_error, level)
        replay_error = _replay_error(
            receipt=receipt,
            package=package,
            suite_path=suite_path,
            spec_path=spec_path,
            report_path=report_path or receipt_path.parent / "report.json",
            baseline_receipt_path=baseline_receipt_path or receipt_path.parent / "baseline-receipt.json",
            trust_policy_path=trust_policy_path,
        )
        if replay_error is not None:
            return _reject(receipt, replay_error, level)
    if receipt.decision.reason_code == ReasonCode.BASELINE_GENESIS:
        return _unverified(receipt, ReasonCode.BASELINE_GENESIS, level)
    if Status(receipt.result.status) == Status.PASS and trusted_ledger_public_key is None and trust_policy_path is None:
        return _unverified(receipt, ReasonCode.BASELINE_UNCHAINED, level)
    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason_code=receipt.decision.reason_code,
        verification_level=level,
        receipt_hash=receipt.receipt_hash,
        strength_summary=receipt.strength_summary,
        chain_status=receipt.baseline.chain_status,
        edit_provenance_present=True,
        proof_coverage="complete",
    )


def verify_proof(
    *,
    receipt_path: Path,
    proof_id: str,
    proofs_dir: Path | None = None,
    package: Path | None = None,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
    baseline_receipt_path: Path | None = None,
    trust_policy_path: Path | None = None,
) -> ProofVerification:
    try:
        receipt = load_receipt(receipt_path)
    except Exception:
        return ProofVerification(status="proof_unreplayable", proof_id=proof_id, reason_code=ReasonCode.PARSE_ERROR)
    if compute_receipt_hash(receipt) != receipt.receipt_hash:
        return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    if _receipt_binding_error(receipt) is not None:
        return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    receipt_proof = next((proof for proof in receipt.proofs if proof.proof_id == proof_id), None)
    if receipt_proof is None:
        return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    proofs_root = proofs_dir or receipt_path.parent / "proofs"
    proof_path = proofs_root / f"{proof_id.replace(':', '_')}.json"
    try:
        external = Proof.model_validate(json.loads(proof_path.read_text(encoding="utf-8")))
    except Exception:
        return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    if external != receipt_proof:
        return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    if package is None:
        return ProofVerification(status="proof_unreplayable", proof_id=proof_id, artifact_hash=receipt_proof.artifact_hash, reason_code=ReasonCode.DATA_MISSING)
    if package is not None:
        if suite_path is None or spec_path is None:
            return ProofVerification(status="proof_unreplayable", proof_id=proof_id, reason_code=ReasonCode.DATA_MISSING)
        if _external_proofs_error(receipt=receipt, proofs_dir=proofs_root) is not None:
            return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
        try:
            from redline.runner import run_redline

            rerun = run_redline(
                package_dir=package,
                baseline=receipt.baseline.package_name,
                candidate=receipt.candidate.package_name,
                suite_path=suite_path,
                spec_path=spec_path,
                out_dir=None,
                edit_provenance=receipt.edit_provenance,
                baseline_receipt_path=baseline_receipt_path,
                baseline_trust_policy_path=trust_policy_path,
            )
        except Exception:
            return ProofVerification(status="proof_unreplayable", proof_id=proof_id, reason_code=ReasonCode.ENGINE_FAILURE)
        rerun_proofs = rerun.receipt.proofs if rerun.receipt is not None else rerun.proofs
        rerun_proof = next((proof for proof in rerun_proofs if proof.proof_id == proof_id), None)
        if rerun_proof != receipt_proof:
            return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)
    return ProofVerification(status="proof_verified", proof_id=proof_id, artifact_hash=receipt_proof.artifact_hash)


def _missing_required_proof_ids(receipt: Receipt, status: Status) -> list[str]:
    required_kinds = REQUIRED_PROOFS[status]
    proofs_by_kind = {}
    for proof in receipt.proofs:
        if proof.verdict_bearing:
            proofs_by_kind.setdefault(proof.kind, []).append(proof.proof_id)
    expected_ids: list[str] = []
    missing: list[str] = []
    for kind in required_kinds:
        ids = proofs_by_kind.get(kind, [])
        if not ids:
            missing.append(kind.value)
        expected_ids.extend(ids)
    if set(expected_ids) != set(receipt.decision.required_proof_ids):
        missing.extend(sorted(set(receipt.decision.required_proof_ids).symmetric_difference(expected_ids)))
    return sorted(set(missing))


def _receipt_binding_error(receipt: Receipt) -> ReasonCode | None:
    if receipt.package.manifest_hash != receipt.package.identity_hash:
        return ReasonCode.RECEIPT_MISMATCH
    proof_ids = [proof.proof_id for proof in receipt.proofs]
    if len(set(proof_ids)) != len(proof_ids):
        return ReasonCode.RECEIPT_MISMATCH
    for proof in receipt.proofs:
        if proof.kind in NON_VERDICT_PROOF_KINDS and proof.verdict_bearing:
            return ReasonCode.RECEIPT_MISMATCH
    for kind in SINGLETON_PROOF_KINDS:
        matches = [proof for proof in receipt.proofs if proof.kind is kind]
        if len(matches) > 1:
            return ReasonCode.RECEIPT_MISMATCH
    if receipt.result.result_hash != hash_obj({"status": receipt.result.status, "breaches": receipt.result.new_breaches}):
        return ReasonCode.RECEIPT_MISMATCH
    package_proof = _single_proof(receipt, ProofKind.PACKAGE_CANONICAL)
    if package_proof is not None:
        expected_package_artifact = hash_obj(
            {
                "package_hash": receipt.package.identity_hash,
                "baseline_hash": receipt.baseline.package_hash,
                "candidate_hash": receipt.candidate.package_hash,
            }
        )
        if package_proof.artifact_hash != expected_package_artifact:
            return ReasonCode.RECEIPT_MISMATCH
    coverage_proof = _single_proof(receipt, ProofKind.COVERAGE)
    if coverage_proof is not None and coverage_proof.artifact_hash != hash_obj(receipt.coverage):
        return ReasonCode.RECEIPT_MISMATCH
    decision_proof = _single_proof(receipt, ProofKind.DECISION)
    if decision_proof is not None:
        non_decision_ids = [proof.proof_id for proof in receipt.proofs if proof.kind is not ProofKind.DECISION]
        expected_decision_id = decision_proof_id(
            status=Status(receipt.result.status),
            reason_code=receipt.decision.reason_code,
            proof_ids=non_decision_ids,
            coverage=receipt.coverage,
        )
        if decision_proof.proof_id != expected_decision_id:
            return ReasonCode.RECEIPT_MISMATCH
        expected_envelope = decision_envelope_from_receipt(receipt)
        if decision_proof.artifact_hash != hash_obj(expected_envelope):
            return ReasonCode.RECEIPT_MISMATCH
    return None


def _replay_error(
    *,
    receipt: Receipt,
    package: Path,
    suite_path: Path,
    spec_path: Path,
    report_path: Path,
    baseline_receipt_path: Path,
    trust_policy_path: Path | None,
) -> ReasonCode | None:
    try:
        from redline.runner import load_spec, load_suite, run_redline

        spec = load_spec(spec_path)
        suite = load_suite(suite_path)
        suite_lock_hash = suite.suite_lock_hash or hash_obj(suite)
        if hash_obj(spec) != receipt.spec.spec_hash or suite_lock_hash != receipt.suite.suite_lock_hash:
            return ReasonCode.RECEIPT_BINDING_FAILED
        if receipt.baseline.chain_status.value == "chained" and not baseline_receipt_path.exists():
            return ReasonCode.DATA_MISSING
        rerun = run_redline(
            package_dir=package,
            baseline=receipt.baseline.package_name,
            candidate=receipt.candidate.package_name,
            suite_path=suite_path,
            spec_path=spec_path,
            out_dir=None,
            edit_provenance=receipt.edit_provenance,
            baseline_receipt_path=baseline_receipt_path if receipt.baseline.chain_status.value == "chained" else None,
            baseline_trust_policy_path=trust_policy_path if receipt.baseline.chain_status.value == "chained" else None,
        )
    except Exception:
        return ReasonCode.ENGINE_FAILURE
    if rerun.receipt is None:
        return rerun.envelope.reason_code
    if rerun.envelope.status != Status(receipt.result.status):
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if rerun.envelope.reason_code != receipt.decision.reason_code:
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if rerun.envelope.coverage != receipt.coverage:
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if set(rerun.envelope.required_proof_ids) != set(receipt.decision.required_proof_ids):
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if _proof_fingerprint(rerun.receipt.proofs) != _proof_fingerprint(receipt.proofs):
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if render_strength_summary(rerun.receipt) != receipt.strength_summary:
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    if rerun.receipt.report.report_hash != receipt.report.report_hash:
        return ReasonCode.ENGINE_IDENTITY_MISMATCH
    expected_report = to_report(envelope=rerun.envelope, receipt=receipt, traces=rerun.traces)
    report_error = _external_report_error(report_path=report_path, expected_report=expected_report, receipt=receipt)
    if report_error is not None:
        return report_error
    return None


def _proof_fingerprint(proofs: list[Proof]) -> list[str]:
    return sorted(hash_obj(proof) for proof in proofs)


def _single_proof(receipt: Receipt, kind: ProofKind) -> Proof | None:
    matches = [proof for proof in receipt.proofs if proof.kind is kind]
    if len(matches) != 1:
        return None
    return matches[0]


def _ledger_error(
    *,
    receipt: Receipt,
    ledger_path: Path,
    checkpoint_path: Path | None = None,
    attestation_path: Path | None = None,
    trusted_ledger_public_key: str | None = None,
    trust_policy_path: Path | None = None,
) -> ReasonCode | None:
    if not ledger_path.exists():
        return ReasonCode.RECEIPT_MISMATCH
    key_hash = hash_obj(
        {
            "package_hash": receipt.package.identity_hash,
            "candidate_hash": receipt.candidate.package_hash,
            "suite_lock_hash": receipt.suite.suite_lock_hash,
            "spec_hash": receipt.spec.spec_hash,
        }
    )
    matched = False
    seen_key = False
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
                    return ReasonCode.RECEIPT_MISMATCH
                expected_entry_hash = hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
                if entry_hash != expected_entry_hash or entry.get("previous_entry_hash") != previous_entry_hash:
                    return ReasonCode.RECEIPT_MISMATCH
                previous_entry_hash = entry_hash
                if entry.get("key_hash") != key_hash:
                    continue
                if seen_key:
                    return ReasonCode.RECEIPT_MISMATCH
                seen_key = True
                if entry.get("status") != receipt.result.status:
                    return ReasonCode.RECEIPT_MISMATCH
                if entry.get("receipt_hash") != receipt.receipt_hash:
                    return ReasonCode.RECEIPT_MISMATCH
                matched = True
    except (OSError, json.JSONDecodeError):
        return ReasonCode.RECEIPT_MISMATCH
    if not matched:
        return ReasonCode.RECEIPT_MISMATCH
    if checkpoint_path is not None:
        checkpoint_error = _ledger_checkpoint_error(
            receipt=receipt,
            ledger_path=ledger_path,
            checkpoint_path=checkpoint_path,
            ledger_tail_hash=previous_entry_hash,
            ledger_entry_count=entry_count,
            attestation_path=attestation_path,
            trusted_ledger_public_key=trusted_ledger_public_key,
            trust_policy_path=trust_policy_path,
        )
        if checkpoint_error is not None:
            return checkpoint_error
    return None


def _ledger_checkpoint_error(
    *,
    receipt: Receipt,
    ledger_path: Path,
    checkpoint_path: Path,
    ledger_tail_hash: str,
    ledger_entry_count: int,
    attestation_path: Path | None,
    trusted_ledger_public_key: str | None,
    trust_policy_path: Path | None,
) -> ReasonCode | None:
    if not checkpoint_path.exists():
        return ReasonCode.RECEIPT_MISMATCH
    try:
        checkpoint = LedgerCheckpoint.model_validate(json.loads(checkpoint_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return ReasonCode.RECEIPT_MISMATCH
    expected_checkpoint_hash = hash_obj(checkpoint.model_copy(update={"checkpoint_hash": ""}))
    if checkpoint.checkpoint_hash != expected_checkpoint_hash:
        return ReasonCode.RECEIPT_MISMATCH
    if checkpoint.ledger_hash != hash_file(ledger_path):
        return ReasonCode.RECEIPT_MISMATCH
    if checkpoint.ledger_tail_hash != ledger_tail_hash or checkpoint.ledger_entry_count != ledger_entry_count:
        return ReasonCode.RECEIPT_MISMATCH
    if receipt.receipt_hash not in checkpoint.subject_receipt_hashes:
        return ReasonCode.RECEIPT_MISMATCH
    trust_policy = None
    if trust_policy_path is not None:
        try:
            trust_policy = TrustPolicy.model_validate(json.loads(trust_policy_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValidationError):
            return ReasonCode.RECEIPT_MISMATCH
    if trusted_ledger_public_key is not None or trust_policy is not None:
        if attestation_path is None or not attestation_path.exists():
            return ReasonCode.RECEIPT_MISMATCH
        try:
            attestation = LedgerCheckpointAttestation.model_validate(json.loads(attestation_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValidationError):
            return ReasonCode.RECEIPT_MISMATCH
        try:
            attested = verify_checkpoint_attestation(
                checkpoint=checkpoint,
                attestation=attestation,
                trusted_public_key_text=trusted_ledger_public_key,
                trust_policy=trust_policy,
            )
        except ValueError:
            return ReasonCode.RECEIPT_MISMATCH
        if not attested:
            return ReasonCode.RECEIPT_MISMATCH
    return None


def _external_proofs_error(*, receipt: Receipt, proofs_dir: Path) -> ReasonCode | None:
    if not proofs_dir.exists():
        return ReasonCode.RECEIPT_MISMATCH
    for proof in receipt.proofs:
        proof_id = proof.proof_id
        proof_path = proofs_dir / f"{proof_id.replace(':', '_')}.json"
        try:
            external = Proof.model_validate(json.loads(proof_path.read_text(encoding="utf-8")))
        except Exception:
            return ReasonCode.RECEIPT_MISMATCH
        if external != proof:
            return ReasonCode.RECEIPT_MISMATCH
    return None


def _external_report_error(*, report_path: Path, expected_report: dict, receipt: Receipt) -> ReasonCode | None:
    if not report_path.exists():
        return ReasonCode.RECEIPT_MISMATCH
    try:
        report_json = json.loads(report_path.read_text(encoding="utf-8"))
        report = ReportJson.model_validate(report_json)
    except (OSError, json.JSONDecodeError, ValidationError):
        return ReasonCode.RECEIPT_MISMATCH
    report_payload = report.model_dump(mode="json")
    recomputed_report_hash = hash_obj({key: value for key, value in {**report_payload, "receipt_hash": None}.items() if key != "report_hash"})
    if recomputed_report_hash != report.report_hash:
        return ReasonCode.RECEIPT_MISMATCH
    if report.report_hash != receipt.report.report_hash:
        return ReasonCode.RECEIPT_MISMATCH
    if report.model_dump(mode="json") != expected_report:
        return ReasonCode.RECEIPT_MISMATCH
    return None


def _bad(reason: ReasonCode, level: VerificationLevel) -> VerificationResult:
    return VerificationResult(status=VerificationStatus.BAD_INPUT, reason_code=reason, verification_level=level)


def _unverified(receipt: Receipt, reason: ReasonCode, level: VerificationLevel) -> VerificationResult:
    return VerificationResult(
        status=VerificationStatus.UNVERIFIED_NO_VERDICT,
        reason_code=reason,
        verification_level=level,
        receipt_hash=receipt.receipt_hash,
        strength_summary=receipt.strength_summary,
        chain_status=receipt.baseline.chain_status,
        edit_provenance_present=True,
        proof_coverage="complete" if receipt.coverage.complete else "incomplete",
        missing_proof_ids=receipt.coverage.missing,
    )


def _reject(receipt: Receipt, reason: ReasonCode, level: VerificationLevel) -> VerificationResult:
    return VerificationResult(
        status=VerificationStatus.REJECTED,
        reason_code=reason,
        verification_level=level,
        receipt_hash=receipt.receipt_hash,
        strength_summary=receipt.strength_summary,
        chain_status=receipt.baseline.chain_status,
        edit_provenance_present=True,
        proof_coverage="complete" if receipt.coverage.complete else "incomplete",
        missing_proof_ids=receipt.coverage.missing,
    )
