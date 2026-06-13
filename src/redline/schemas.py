from __future__ import annotations

import json
from pathlib import Path

from redline.models import (
    DecisionEnvelope,
    DoctorResult,
    EditProvenance,
    LedgerCheckpoint,
    LedgerCheckpointAttestation,
    PackageAnnotation,
    PackageImportResult,
    Proof,
    PublishPreflightResult,
    Receipt,
    RedlineSpec,
    ReportJson,
    Suite,
    VerificationResult,
)
from redline.models import ProofVerification
from redline.sponsor.bitget import SponsorReadbackEvidence, SponsorStepResult


def export_schemas(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    models = {
        "decision-envelope.v1.schema.json": DecisionEnvelope,
        "doctor-result.v1.schema.json": DoctorResult,
        "edit-provenance.v1.schema.json": EditProvenance,
        "ledger-attestation.v1.schema.json": LedgerCheckpointAttestation,
        "ledger-checkpoint.v1.schema.json": LedgerCheckpoint,
        "package-annotation.v1.schema.json": PackageAnnotation,
        "package-import.v1.schema.json": PackageImportResult,
        "proof.v1.schema.json": Proof,
        "proof-verification.v1.schema.json": ProofVerification,
        "publish-preflight.v1.schema.json": PublishPreflightResult,
        "receipt.v3.2.schema.json": Receipt,
        "report.v1.schema.json": ReportJson,
        "sponsor-readback-evidence.v1.schema.json": SponsorReadbackEvidence,
        "sponsor-step-result.v1.schema.json": SponsorStepResult,
        "spec.v2.1.schema.json": RedlineSpec,
        "suite.v2.schema.json": Suite,
        "verification-result.v1.schema.json": VerificationResult,
    }
    for filename, model in models.items():
        (out_dir / filename).write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True), encoding="utf-8")
