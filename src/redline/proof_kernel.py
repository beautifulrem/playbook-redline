from __future__ import annotations

from collections.abc import Sequence

from redline.canonical import hash_obj
from redline.models import (
    Capabilities,
    CoverageManifest,
    DecisionContext,
    DecisionEnvelope,
    Proof,
    ProofKind,
    ReasonCode,
    Status,
)

REQUIRED_PROOFS: dict[Status, frozenset[ProofKind]] = {
    Status.PASS: frozenset(
        {
            ProofKind.BASELINE_CALIBRATION,
            ProofKind.REPLAY,
            ProofKind.REPLAY_WELLFORMED,
            ProofKind.COVERAGE,
            ProofKind.CANDIDATE_ABSOLUTE,
            ProofKind.PACKAGE_CANONICAL,
            ProofKind.SPEC_COMPILE,
            ProofKind.DECISION,
        }
    ),
    Status.WITHHELD: frozenset(
        {
            ProofKind.PACKAGE_CANONICAL,
            ProofKind.SPEC_COMPILE,
            ProofKind.REPLAY,
            ProofKind.REPLAY_WELLFORMED,
            ProofKind.COVERAGE,
            ProofKind.PROBE,
            ProofKind.DECISION,
        }
    ),
    Status.REJECT: frozenset({ProofKind.DECISION}),
    Status.UNVERIFIED_NO_VERDICT: frozenset(),
}
assert set(REQUIRED_PROOFS) == set(Status)


def decision_proof_id(*, status: Status, reason_code: ReasonCode, proof_ids: Sequence[str], coverage: CoverageManifest) -> str:
    return "proof:decision:" + hash_obj(
        {
            "status": status.value,
            "reason_code": reason_code.value,
            "proof_ids": sorted(proof_ids),
            "coverage": coverage,
        }
    ).removeprefix("sha256:")[:24]


def decide(
    *,
    proofs: Sequence[Proof],
    required: dict[Status, frozenset[ProofKind]] = REQUIRED_PROOFS,
    coverage: CoverageManifest,
    context: DecisionContext,
) -> DecisionEnvelope:
    proof_list = list(proofs)
    capabilities = Capabilities(scenario_count=len({cell[0] for cell in coverage.cells}))
    if context.reject_reason is not None:
        status = Status.REJECT
        reason_code = context.reject_reason
    elif not coverage.complete:
        status = Status.UNVERIFIED_NO_VERDICT
        reason_code = ReasonCode.PROBE_ERROR if any("errored" in item for item in coverage.missing) else ReasonCode.COVERAGE_INCOMPLETE
    elif _has_block_breach(proof_list):
        status = Status.WITHHELD
        reason_code = ReasonCode.NEW_BLOCK_BREACH
    else:
        status = Status.PASS
        reason_code = ReasonCode.BASELINE_GENESIS if context.chain_status.value == "genesis" else ReasonCode.PASS

    proof_ids_by_kind: dict[ProofKind, list[str]] = {}
    for proof in proof_list:
        if proof.verdict_bearing:
            proof_ids_by_kind.setdefault(proof.kind, []).append(proof.proof_id)

    missing_kinds = [
        kind
        for kind in required[status]
        if kind is not ProofKind.DECISION and not proof_ids_by_kind.get(kind)
    ]
    if missing_kinds and status in {Status.PASS, Status.WITHHELD}:
        status = Status.UNVERIFIED_NO_VERDICT
        reason_code = ReasonCode.UNVERIFIED_NO_VERDICT

    decision_id = decision_proof_id(
        status=status,
        reason_code=reason_code,
        proof_ids=[proof.proof_id for proof in proof_list],
        coverage=coverage,
    )
    required_ids: list[str] = []
    satisfied_ids: list[str] = []
    for kind in sorted(required[status], key=lambda item: item.value):
        if kind is ProofKind.DECISION:
            required_ids.append(decision_id)
            satisfied_ids.append(decision_id)
        else:
            ids = sorted(proof_ids_by_kind.get(kind, []))
            required_ids.extend(ids)
            satisfied_ids.extend(ids)

    return DecisionEnvelope(
        status=status,
        reason_code=reason_code,
        chain_status=context.chain_status,
        required_proof_ids=required_ids,
        satisfied_proof_ids=satisfied_ids,
        coverage=coverage,
        capabilities=capabilities,
    )


def _has_block_breach(proofs: Sequence[Proof]) -> bool:
    for proof in proofs:
        if proof.kind == ProofKind.PROBE:
            for assertion in proof.assertions:
                if not assertion.holds:
                    return True
    return False
