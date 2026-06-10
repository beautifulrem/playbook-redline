from __future__ import annotations

from decimal import Decimal

from redline.canonical import canonical_number
from redline.models import Assertion, ProbeOutcome, ProbeResult, ReplayTrace


class MaxDrawdownProbe:
    kind = "max_drawdown"

    def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        threshold = Decimal(params["max_drawdown"])
        worst = max(candidate.points, key=lambda point: point.drawdown)
        holds = worst.drawdown <= threshold
        assertion = Assertion(
            metric="max_drawdown",
            op="<=",
            threshold=canonical_number(threshold),
            observed=canonical_number(worst.drawdown),
            scenario_id=candidate.scenario_id,
            bar=worst.bar,
            holds=holds,
        )
        return ProbeResult(
            outcome=ProbeOutcome.PASS if holds else ProbeOutcome.BREACH,
            assertions=[assertion],
            evidence_bar=None if holds else worst.bar,
        )


class TradeBudgetProbe:
    kind = "trade_budget"

    def evaluate(self, *, baseline: ReplayTrace, candidate: ReplayTrace, params: dict[str, str]) -> ProbeResult:
        threshold = Decimal(params["max_trades"])
        observed = Decimal(candidate.trade_count)
        holds = observed <= threshold
        assertion = Assertion(
            metric="trade_budget",
            op="<=",
            threshold=canonical_number(threshold),
            observed=canonical_number(observed),
            scenario_id=candidate.scenario_id,
            bar=candidate.points[-1].bar if candidate.points else 0,
            holds=holds,
        )
        return ProbeResult(
            outcome=ProbeOutcome.PASS if holds else ProbeOutcome.BREACH,
            assertions=[assertion],
            evidence_bar=None if holds else assertion.bar,
        )

