from __future__ import annotations

from typing import Any

from redline.canonical import hash_obj
from redline.models import DecisionEnvelope, Receipt, ReplayTrace


def to_report(*, envelope: DecisionEnvelope, receipt: Receipt | None, traces: list[ReplayTrace]) -> dict[str, Any]:
    report = {
        "version": "redline.report.v1",
        "envelope": envelope.model_dump(mode="json"),
        "receipt_hash": receipt.receipt_hash if receipt else None,
        "strength_summary": receipt.strength_summary if receipt else "",
        "traces": [trace.model_dump(mode="json") for trace in traces],
        "proof_ids": [proof.proof_id for proof in receipt.proofs] if receipt else [],
        "proofs": [proof.model_dump(mode="json") for proof in receipt.proofs] if receipt else [],
        "edit_provenance": receipt.edit_provenance.model_dump(mode="json") if receipt else None,
        "publish": receipt.publish.model_dump(mode="json") if receipt else None,
        "coverage_missing": receipt.coverage.missing if receipt else envelope.coverage.missing,
        "verification_level": "replayed" if receipt else None,
    }
    hash_payload = {**report, "receipt_hash": None}
    report["report_hash"] = hash_obj(hash_payload)
    return report


def render_strength_summary(receipt: Receipt) -> str:
    metrics: list[str] = []
    for proof in receipt.proofs:
        for assertion in proof.assertions:
            metrics.append(f"{assertion.metric} {assertion.op} {assertion.threshold} observed {assertion.observed}")
    scenario_count = len(receipt.suite.scenarios)
    return f"tested: {'; '.join(sorted(set(metrics)))}; {scenario_count} anchored scenarios"
