from __future__ import annotations

from typing import Any

from redline.canonical import hash_obj, normalize
from redline.models import DecisionEnvelope, Proof, Receipt, ReplayTrace


def to_report(*, envelope: DecisionEnvelope, receipt: Receipt | None, traces: list[ReplayTrace], proofs: list[Proof] | None = None) -> dict[str, Any]:
    report_proofs = receipt.proofs if receipt else (proofs or [])
    report = {
        "version": "redline.report.v1",
        "envelope": envelope.model_dump(mode="python"),
        "receipt_hash": receipt.receipt_hash if receipt else None,
        "strength_summary": receipt.strength_summary if receipt else "",
        "traces": [trace.model_dump(mode="python") for trace in traces],
        "proof_ids": [proof.proof_id for proof in report_proofs],
        "proofs": [proof.model_dump(mode="python") for proof in report_proofs],
        "edit_provenance": receipt.edit_provenance.model_dump(mode="python") if receipt else None,
        "publish": receipt.publish.model_dump(mode="python") if receipt else None,
        "coverage_missing": receipt.coverage.missing if receipt else envelope.coverage.missing,
        "verification_level": "replayed" if receipt else None,
    }
    report = normalize(report, exclude_none=False)
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
