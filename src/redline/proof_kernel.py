from __future__ import annotations

from collections.abc import Iterable, Sequence
from decimal import Decimal, InvalidOperation

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
    VerdictTier,
)

REQUIRED_PROOFS: dict[Status, tuple[ProofKind, ...]] = {
    Status.PASS: (
        ProofKind.BASELINE_CALIBRATION,
        ProofKind.REPLAY,
        ProofKind.REPLAY_WELLFORMED,
        ProofKind.COVERAGE,
        ProofKind.PROBE,
        ProofKind.CANDIDATE_ABSOLUTE,
        ProofKind.PACKAGE_CANONICAL,
        ProofKind.SPEC_COMPILE,
        ProofKind.DECISION,
    ),
    Status.WITHHELD: (
        ProofKind.PACKAGE_CANONICAL,
        ProofKind.SPEC_COMPILE,
        ProofKind.REPLAY,
        ProofKind.REPLAY_WELLFORMED,
        ProofKind.COVERAGE,
        ProofKind.PROBE,
        ProofKind.DECISION,
    ),
    Status.REDUCE_SIZE: (
        ProofKind.PACKAGE_CANONICAL,
        ProofKind.SPEC_COMPILE,
        ProofKind.REPLAY,
        ProofKind.REPLAY_WELLFORMED,
        ProofKind.COVERAGE,
        ProofKind.PROBE,
        ProofKind.DECISION,
    ),
    Status.REJECT: (ProofKind.DECISION,),
    Status.UNVERIFIED_NO_VERDICT: (),
}
assert sorted(REQUIRED_PROOFS, key=lambda item: item.value) == sorted(tuple(Status), key=lambda item: item.value)


def decision_proof_id(
    *,
    status: Status,
    reason_code: ReasonCode,
    proof_ids: Sequence[str],
    coverage: CoverageManifest,
    verdict_tier: VerdictTier | None = None,
    adjusted_size_cap: str | None = None,
) -> str:
    payload = {
        "status": status.value,
        "reason_code": reason_code.value,
        "proof_ids": sorted(proof_ids),
        "coverage": coverage,
    }
    if verdict_tier is not None:
        payload["verdict_tier"] = verdict_tier.value
    if adjusted_size_cap is not None:
        payload["adjusted_size_cap"] = adjusted_size_cap
    return "proof:decision:" + hash_obj(payload).removeprefix("sha256:")[:24]


def decision_envelope_from_receipt(receipt) -> DecisionEnvelope:
    return DecisionEnvelope(
        status=Status(receipt.result.status),
        verdict_tier=receipt.decision.verdict_tier,
        adjusted_size_cap=receipt.decision.adjusted_size_cap,
        reason_code=receipt.decision.reason_code,
        chain_status=receipt.baseline.chain_status,
        required_proof_ids=receipt.decision.required_proof_ids,
        satisfied_proof_ids=receipt.decision.satisfied_proof_ids,
        coverage=receipt.coverage,
        capabilities=receipt.capabilities,
    )


def decide(
    *,
    proofs: Sequence[Proof],
    required: dict[Status, tuple[ProofKind, ...]] = REQUIRED_PROOFS,
    coverage: CoverageManifest,
    context: DecisionContext,
) -> DecisionEnvelope:
    proof_list = list(proofs)
    adjusted_size_cap: str | None = None
    if coverage.complete and (not coverage.cells or _has_duplicates(coverage.cells)):
        coverage = CoverageManifest(cells=_unique_sorted_tuples(coverage.cells), complete=False, missing=[ReasonCode.COVERAGE_INCOMPLETE.value])
    if coverage.complete:
        missing_cells = _missing_probe_coverage_cells(proof_list=proof_list, coverage=coverage)
        if missing_cells:
            coverage = CoverageManifest(cells=coverage.cells, complete=False, missing=missing_cells)
    capabilities = Capabilities(scenario_count=len(_unique_sorted_strings(cell[0] for cell in coverage.cells)))
    if context.reject_reason is not None:
        status = Status.REJECT
        verdict_tier = VerdictTier.BLOCK
        reason_code = context.reject_reason
    elif not coverage.complete or not coverage.cells:
        status = Status.UNVERIFIED_NO_VERDICT
        verdict_tier = VerdictTier.HUMAN_REVIEW
        reason_code = ReasonCode.PROBE_ERROR if any("errored" in item for item in coverage.missing) else ReasonCode.COVERAGE_INCOMPLETE
    elif _has_block_breach(proof_list):
        adjusted_size_cap = _reduce_size_cap_for_breaches(proof_list)
        if adjusted_size_cap is not None:
            status = Status.REDUCE_SIZE
            verdict_tier = VerdictTier.REDUCE_SIZE
        else:
            status = Status.WITHHELD
            verdict_tier = VerdictTier.BLOCK
        reason_code = ReasonCode.NEW_BLOCK_BREACH
    else:
        status = Status.PASS
        verdict_tier = VerdictTier.ALLOW
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
    if missing_kinds and status in (Status.PASS, Status.WITHHELD, Status.REDUCE_SIZE):
        status = Status.UNVERIFIED_NO_VERDICT
        verdict_tier = VerdictTier.HUMAN_REVIEW
        adjusted_size_cap = None
        reason_code = ReasonCode.UNVERIFIED_NO_VERDICT

    decision_id = decision_proof_id(
        status=status,
        reason_code=reason_code,
        proof_ids=[proof.proof_id for proof in proof_list],
        coverage=coverage,
        verdict_tier=verdict_tier,
        adjusted_size_cap=adjusted_size_cap,
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
        verdict_tier=verdict_tier,
        adjusted_size_cap=adjusted_size_cap,
        reason_code=reason_code,
        chain_status=context.chain_status,
        required_proof_ids=required_ids,
        satisfied_proof_ids=satisfied_ids,
        coverage=coverage,
        capabilities=capabilities,
    )


def _has_block_breach(proofs: Sequence[Proof]) -> bool:
    for proof in proofs:
        if proof.kind == ProofKind.PROBE and proof.verdict_bearing:
            for assertion in proof.assertions:
                if not assertion.holds:
                    return True
    return False


def _reduce_size_cap_for_breaches(proofs: Sequence[Proof]) -> str | None:
    caps: list[Decimal] = []
    for proof in proofs:
        if proof.kind is not ProofKind.PROBE or not proof.verdict_bearing:
            continue
        if not any(not assertion.holds for assertion in proof.assertions):
            continue
        if proof.meta.get("breach_action") != "reduce_size":
            return None
        raw_cap = proof.meta.get("adjusted_size_cap")
        if not isinstance(raw_cap, str):
            return None
        try:
            cap = Decimal(raw_cap)
        except InvalidOperation:
            return None
        if not cap.is_finite() or cap <= 0 or cap > 1:
            return None
        caps.append(cap)
    if not caps:
        return None
    text = format(min(caps), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _missing_probe_coverage_cells(*, proof_list: Sequence[Proof], coverage: CoverageManifest) -> list[str]:
    covered: list[tuple[str, str]] = []
    for proof in proof_list:
        if proof.kind is not ProofKind.PROBE or not proof.verdict_bearing:
            continue
        scenario_id = proof.meta.get("scenario_id")
        probe_id = proof.meta.get("probe_id")
        if not isinstance(scenario_id, str) or not isinstance(probe_id, str):
            continue
        if not any(assertion.scenario_id == scenario_id for assertion in proof.assertions):
            continue
        cell = (scenario_id, probe_id)
        if cell not in covered:
            covered.append(cell)
    return [f"{scenario_id}:{probe_id}:missing_probe_proof" for scenario_id, probe_id in coverage.cells if (scenario_id, probe_id) not in covered]


def _has_duplicates(items: Sequence[object]) -> bool:
    seen: list[object] = []
    for item in items:
        if item in seen:
            return True
        seen.append(item)
    return False


def _unique_sorted_strings(items: Iterable[str]) -> list[str]:
    unique: list[str] = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return sorted(unique)


def _unique_sorted_tuples(items: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    unique: list[tuple[str, str]] = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return sorted(unique)


def _same_members(left: Iterable[object], right: Iterable[object]) -> bool:
    left_items = list(left)
    right_items = list(right)
    return all(item in right_items for item in left_items) and all(item in left_items for item in right_items)
