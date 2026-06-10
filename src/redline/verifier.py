from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import hash_tree
from redline.models import (
    ProofVerification,
    ReasonCode,
    Receipt,
    Status,
    VerificationLevel,
    VerificationResult,
    VerificationStatus,
)
from redline.proof_kernel import REQUIRED_PROOFS
from redline.receipt import compute_receipt_hash
from redline.report import render_strength_summary

BAD_INPUT = {ReasonCode.FILE_NOT_FOUND, ReasonCode.PARSE_ERROR, ReasonCode.SCHEMA_INVALID, ReasonCode.VERSION_UNSUPPORTED}


def load_receipt(path: Path) -> Receipt:
    with path.open(encoding="utf-8") as fh:
        return Receipt.model_validate(json.load(fh))


def verify(*, receipt_path: Path, package: Path | None = None, level: VerificationLevel | None = None) -> VerificationResult:
    level = level or VerificationLevel.HASH_ONLY
    try:
        if not receipt_path.exists():
            return _bad(ReasonCode.FILE_NOT_FOUND, level)
        receipt = load_receipt(receipt_path)
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
    if level == VerificationLevel.REPLAYED and package is not None:
        try:
            package_hash = hash_tree(package)
        except (OSError, ValueError):
            return _bad(ReasonCode.FILE_NOT_FOUND, level)
        if package_hash != receipt.package.identity_hash:
            return _reject(receipt, ReasonCode.RECEIPT_BINDING_FAILED, level)
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


def verify_proof(*, receipt_path: Path, proof_id: str) -> ProofVerification:
    try:
        receipt = load_receipt(receipt_path)
    except Exception:
        return ProofVerification(status="proof_unreplayable", proof_id=proof_id, reason_code=ReasonCode.PARSE_ERROR)
    for proof in receipt.proofs:
        if proof.proof_id == proof_id:
            return ProofVerification(status="proof_replayed", proof_id=proof_id, artifact_hash=proof.artifact_hash)
    return ProofVerification(status="proof_mismatch", proof_id=proof_id, reason_code=ReasonCode.RECEIPT_MISMATCH)


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


def _bad(reason: ReasonCode, level: VerificationLevel) -> VerificationResult:
    return VerificationResult(status=VerificationStatus.BAD_INPUT, reason_code=reason, verification_level=level)


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
