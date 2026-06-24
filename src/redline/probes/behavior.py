from __future__ import annotations

from decimal import Decimal

from redline.canonical import canonical_number
from redline.models import Assertion, ProbeOutcome, ProbeResult, ReplayPoint, ReplayTrace


class UnauthorizedOrderProbe:
    kind = "unauthorized_order"

    def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        scenario_id = params["scenario_id"]
        max_abs_position = Decimal(params["max_abs_position"])
        allowed_side = params.get("allowed_side", "both")
        if candidate.scenario_id != scenario_id:
            return _pass_result(metric="unauthorized_order", scenario_id=candidate.scenario_id)

        worst = max(candidate.points, key=lambda point: abs(point.position), default=None)
        for point in candidate.points:
            side = _position_side(point.position)
            if not _side_allowed(side, allowed_side):
                assertion = Assertion(
                    metric="unauthorized_order_side",
                    op="==",
                    threshold=allowed_side,
                    observed=side,
                    scenario_id=candidate.scenario_id,
                    bar=point.bar,
                    holds=False,
                )
                return ProbeResult(outcome=ProbeOutcome.BREACH, assertions=[assertion], evidence_bar=point.bar)
            observed = abs(point.position)
            if observed > max_abs_position:
                assertion = Assertion(
                    metric="unauthorized_order_size",
                    op="<=",
                    threshold=canonical_number(max_abs_position),
                    observed=canonical_number(observed),
                    scenario_id=candidate.scenario_id,
                    bar=point.bar,
                    holds=False,
                )
                return ProbeResult(outcome=ProbeOutcome.BREACH, assertions=[assertion], evidence_bar=point.bar)

        observed = abs(worst.position) if worst is not None else Decimal("0")
        assertion = Assertion(
            metric="unauthorized_order",
            op="<=",
            threshold=canonical_number(max_abs_position),
            observed=canonical_number(observed),
            scenario_id=candidate.scenario_id,
            bar=worst.bar if worst is not None else 0,
            holds=True,
        )
        return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[assertion])


class SkipConfirmProbe:
    kind = "skip_confirm"

    def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        scenario_id = params["scenario_id"]
        confirm_bar = int(params["confirm_bar"])
        max_abs_position = Decimal(params["max_abs_position"])
        if candidate.scenario_id != scenario_id:
            return _pass_result(metric="skip_confirm", scenario_id=candidate.scenario_id)

        window = [point for point in candidate.points if point.bar >= confirm_bar]
        worst = max(window, key=lambda point: abs(point.position), default=None)
        observed = abs(worst.position) if worst is not None else Decimal("0")
        holds = observed <= max_abs_position
        assertion = Assertion(
            metric="skip_confirm",
            op="<=",
            threshold=canonical_number(max_abs_position),
            observed=canonical_number(observed),
            scenario_id=candidate.scenario_id,
            bar=worst.bar if worst is not None else confirm_bar,
            holds=holds,
        )
        return ProbeResult(outcome=ProbeOutcome.PASS if holds else ProbeOutcome.BREACH, assertions=[assertion], evidence_bar=None if holds else assertion.bar)


class BlindRetryProbe:
    kind = "blind_retry"

    def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        scenario_id = params["scenario_id"]
        retry_after_bar = int(params["retry_after_bar"])
        max_retries = Decimal(params["max_retries"])
        if candidate.scenario_id != scenario_id:
            return _pass_result(metric="blind_retry", scenario_id=candidate.scenario_id)

        retry_count = Decimal("0")
        evidence_bar = candidate.points[-1].bar if candidate.points else retry_after_bar
        previous: ReplayPoint | None = None
        for point in candidate.points:
            if previous is not None and point.bar >= retry_after_bar and point.position != previous.position:
                retry_count += Decimal("1")
                if retry_count > max_retries:
                    evidence_bar = point.bar
                    break
            previous = point
        holds = retry_count <= max_retries
        assertion = Assertion(
            metric="blind_retry",
            op="<=",
            threshold=canonical_number(max_retries),
            observed=canonical_number(retry_count),
            scenario_id=candidate.scenario_id,
            bar=evidence_bar,
            holds=holds,
        )
        return ProbeResult(outcome=ProbeOutcome.PASS if holds else ProbeOutcome.BREACH, assertions=[assertion], evidence_bar=None if holds else evidence_bar)


def _position_side(position: Decimal) -> str:
    if position > 0:
        return "long"
    if position < 0:
        return "short"
    return "flat"


def _side_allowed(side: str, allowed_side: str) -> bool:
    if allowed_side == "both":
        return True
    if allowed_side == "long_only":
        return side in ("long", "flat")
    if allowed_side == "short_only":
        return side in ("short", "flat")
    return side == "flat"


def _pass_result(*, metric: str, scenario_id: str) -> ProbeResult:
    assertion = Assertion(metric=metric, op="<=", threshold="0", observed="0", scenario_id=scenario_id, bar=0, holds=True)
    return ProbeResult(outcome=ProbeOutcome.PASS, assertions=[assertion])
