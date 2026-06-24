from __future__ import annotations

from typing import Any

from redline.service.models import ReleaseCandidateResponse, ReleaseState, ReleaseTier


TERMINAL_RELEASE_STATES = frozenset(
    {
        ReleaseState.RELEASED_DEMO,
        ReleaseState.RELEASED_LIVE_GATED,
        ReleaseState.REJECTED,
        ReleaseState.KILLED,
        ReleaseState.BLOCKED_WITHHELD,
        ReleaseState.BLOCKED_UNVERIFIED,
        ReleaseState.BLOCKED_MISSING_EVIDENCE,
        ReleaseState.BLOCKED_RISK_POLICY,
        ReleaseState.BLOCKED_APPROVAL,
        ReleaseState.BLOCKED_EXCHANGE_ERROR,
    }
)

ALLOWED_RELEASE_TRANSITIONS: dict[ReleaseState, frozenset[ReleaseState]] = {
    ReleaseState.DRAFT: frozenset(
        {
            ReleaseState.REDLINE_RUNNING,
        ReleaseState.REDLINE_PASSED,
        ReleaseState.EVIDENCE_COLLECTING,
        ReleaseState.BLOCKED_MISSING_EVIDENCE,
        ReleaseState.BLOCKED_WITHHELD,
        ReleaseState.BLOCKED_UNVERIFIED,
        ReleaseState.KILLED,
        }
    ),
    ReleaseState.REDLINE_RUNNING: frozenset(
        {
            ReleaseState.REDLINE_PASSED,
            ReleaseState.BLOCKED_MISSING_EVIDENCE,
            ReleaseState.BLOCKED_WITHHELD,
            ReleaseState.BLOCKED_UNVERIFIED,
            ReleaseState.KILLED,
        }
    ),
    ReleaseState.REDLINE_PASSED: frozenset(
        {
            ReleaseState.EVIDENCE_COLLECTING,
            ReleaseState.REVIEW_REQUIRED,
            ReleaseState.BLOCKED_MISSING_EVIDENCE,
            ReleaseState.BLOCKED_RISK_POLICY,
            ReleaseState.KILLED,
        }
    ),
    ReleaseState.EVIDENCE_COLLECTING: frozenset(
        {
            ReleaseState.EVIDENCE_COLLECTING,
            ReleaseState.REVIEW_REQUIRED,
            ReleaseState.BLOCKED_MISSING_EVIDENCE,
            ReleaseState.BLOCKED_RISK_POLICY,
            ReleaseState.KILLED,
        }
    ),
    ReleaseState.REVIEW_REQUIRED: frozenset({ReleaseState.APPROVED, ReleaseState.REJECTED, ReleaseState.BLOCKED_MISSING_EVIDENCE, ReleaseState.KILLED}),
    ReleaseState.APPROVED: frozenset(
        {
            ReleaseState.RELEASE_READY,
            ReleaseState.EVIDENCE_COLLECTING,
            ReleaseState.REVIEW_REQUIRED,
            ReleaseState.BLOCKED_MISSING_EVIDENCE,
            ReleaseState.BLOCKED_RISK_POLICY,
            ReleaseState.BLOCKED_EXCHANGE_ERROR,
            ReleaseState.KILLED,
        }
    ),
    ReleaseState.DEMO_EXECUTED: frozenset({ReleaseState.RELEASE_READY, ReleaseState.KILLED}),
    ReleaseState.RELEASE_READY: frozenset({ReleaseState.RELEASED_DEMO, ReleaseState.RELEASED_LIVE_GATED, ReleaseState.KILLED}),
}


class ReleaseTransitionError(ValueError):
    def __init__(self, from_state: ReleaseState, to_state: ReleaseState) -> None:
        super().__init__(f"invalid release transition: {from_state.value} -> {to_state.value}")
        self.from_state = from_state
        self.to_state = to_state


class ReleaseTransitionMissingEvidenceError(ReleaseTransitionError):
    def __init__(self, from_state: ReleaseState, to_state: ReleaseState, missing: tuple[str, ...]) -> None:
        super().__init__(from_state, to_state)
        self.missing = missing


def is_terminal_release_state(state: ReleaseState) -> bool:
    return state in TERMINAL_RELEASE_STATES


def transition_release(
    release: ReleaseCandidateResponse,
    to_state: ReleaseState,
    *,
    updates: dict | None = None,
) -> ReleaseCandidateResponse:
    updated = release.model_copy(update={"state": to_state, **(updates or {})})
    if release.state == to_state:
        missing = _missing_evidence_for_target(updated, to_state)
        if missing:
            raise ReleaseTransitionMissingEvidenceError(release.state, to_state, missing)
        return updated
    if is_terminal_release_state(release.state):
        raise ReleaseTransitionError(release.state, to_state)
    if to_state not in ALLOWED_RELEASE_TRANSITIONS.get(release.state, frozenset()):
        raise ReleaseTransitionError(release.state, to_state)
    missing = _missing_evidence_for_target(updated, to_state)
    if missing:
        raise ReleaseTransitionMissingEvidenceError(release.state, to_state, missing)
    return updated


def _missing_evidence_for_target(release: ReleaseCandidateResponse, to_state: ReleaseState) -> tuple[str, ...]:
    if to_state not in {ReleaseState.REVIEW_REQUIRED, ReleaseState.APPROVED, ReleaseState.RELEASE_READY, ReleaseState.RELEASED_DEMO, ReleaseState.RELEASED_LIVE_GATED}:
        return ()
    missing: list[str] = []
    if release.run_id is None or release.redline_reason_code != "PASS" or not release.redline_receipt_hash or not release.redline_report_hash:
        missing.append("redline_pass")
    if release.risk_policy is None or release.risk_policy_hash is None:
        missing.append("risk_policy")
    policy = release.risk_policy or {}
    if bool(policy.get("require_simulation_evidence", True)) and (release.simulation_evidence is None or release.simulation_evidence_hash is None):
        missing.append("simulation_evidence")
    if to_state in {ReleaseState.APPROVED, ReleaseState.RELEASE_READY, ReleaseState.RELEASED_DEMO, ReleaseState.RELEASED_LIVE_GATED}:
        if bool(policy.get("require_human_approval", True)) and release.approval is None:
            missing.append("human_approval")
    if to_state in {ReleaseState.RELEASE_READY, ReleaseState.RELEASED_DEMO, ReleaseState.RELEASED_LIVE_GATED}:
        if bool(policy.get("require_demo_execution", True)) and (release.execution_evidence is None or release.execution_run_id is None):
            missing.append("demo_execution")
    if to_state is ReleaseState.RELEASED_LIVE_GATED:
        missing.extend(_missing_live_gate_controls(release))
    return tuple(missing)


def _missing_live_gate_controls(release: ReleaseCandidateResponse) -> list[str]:
    missing: list[str] = []
    if release.release_tier not in {ReleaseTier.L1, ReleaseTier.L2}:
        missing.append("l1_release_tier")
    policy = release.risk_policy or {}
    if not bool(policy.get("mainnet_enabled", False)):
        missing.append("mainnet_risk_policy")
    controls = release.metadata.get("live_gate")
    if not isinstance(controls, dict):
        missing.append("live_gate_controls")
        return missing
    if controls.get("confirm_mainnet_order") is not True:
        missing.append("confirm_mainnet_order")
    if controls.get("allow_live_gated_release") is not True:
        missing.append("allow_live_gated_release")
    release_manager_id = _nonempty_text(controls.get("release_manager_id"))
    second_reviewer_id = _nonempty_text(controls.get("second_reviewer_id"))
    if release_manager_id is None:
        missing.append("release_manager")
    if second_reviewer_id is None or second_reviewer_id == release_manager_id or second_reviewer_id == release.created_by:
        missing.append("second_reviewer")
    return missing


def _nonempty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
