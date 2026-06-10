from __future__ import annotations

import json
from pathlib import Path

from redline.models import DecisionEnvelope, Receipt, RedlineSpec, Suite, VerificationResult


def export_schemas(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    models = {
        "decision-envelope.v1.schema.json": DecisionEnvelope,
        "receipt.v3.2.schema.json": Receipt,
        "spec.v2.1.schema.json": RedlineSpec,
        "suite.v2.schema.json": Suite,
        "verification-result.v1.schema.json": VerificationResult,
    }
    for filename, model in models.items():
        (out_dir / filename).write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True), encoding="utf-8")

