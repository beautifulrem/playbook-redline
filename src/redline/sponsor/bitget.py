from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from redline.models import DecisionEnvelope, ReasonCode, Status


class SponsorState(StrEnum):
    LOCAL_PASS_REQUIRED = "LOCAL_PASS_REQUIRED"
    ANNOTATED_PACKAGE_READY = "ANNOTATED_PACKAGE_READY"
    UPLOAD_ACCEPTED = "UPLOAD_ACCEPTED"
    RUN_STARTED = "RUN_STARTED"
    RUN_COMPLETED = "RUN_COMPLETED"
    READBACK_VERIFIED = "READBACK_VERIFIED"
    RECORDED_ATTESTATION_VALID = "RECORDED_ATTESTATION_VALID"
    MISMATCH = "MISMATCH"


class SponsorStepResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ok: bool
    state: SponsorState
    evidence: dict[str, str] = Field(default_factory=dict)
    reason_code: ReasonCode | None = None


class SponsorAdapter(Protocol):
    def upload(self, *, envelope: DecisionEnvelope, package_hash: str) -> SponsorStepResult: ...
    def run(self, *, version_id: str) -> SponsorStepResult: ...
    def poll(self, *, run_id: str) -> SponsorStepResult: ...
    def readback(self, *, run_id: str) -> SponsorStepResult: ...


def assert_local_pass(envelope: DecisionEnvelope, call_site: str) -> None:
    if envelope.status != Status.PASS:
        raise RuntimeError(f"{ReasonCode.SPONSOR_READBACK_MISMATCH.value}: {call_site} requires local pass")


class SponsorReadbackEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["redline.sponsor.bitget.readback.v1"] = "redline.sponsor.bitget.readback.v1"
    run_id: str
    version_id: str
    status: str
    metrics_output_hash: str
    expected_version_id: str
    expected_metrics_output_hash: str
    transcript_hash: str

    @field_validator("metrics_output_hash", "expected_metrics_output_hash", "transcript_hash")
    @classmethod
    def _hash_must_be_sha256(cls, value: str) -> str:
        if len(value) != 71 or not value.startswith("sha256:"):
            raise ValueError("expected sha256:<64 hex chars>")
        digest = value.removeprefix("sha256:")
        if any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("expected lowercase hex sha256 digest")
        return value


def validate_sponsor_evidence_shape(path: Path) -> SponsorStepResult:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        evidence = SponsorReadbackEvidence.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValidationError):
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, reason_code=ReasonCode.SCHEMA_INVALID)
    if evidence.status != "completed":
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": evidence.run_id, "status": evidence.status},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if evidence.version_id != evidence.expected_version_id:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": evidence.run_id, "version_id": evidence.version_id},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if evidence.metrics_output_hash != evidence.expected_metrics_output_hash:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": evidence.run_id, "metrics_output_hash": evidence.metrics_output_hash},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    return SponsorStepResult(
        ok=False,
        state=SponsorState.RECORDED_ATTESTATION_VALID,
        evidence={
            "run_id": evidence.run_id,
            "version_id": evidence.version_id,
            "metrics_output_hash": evidence.metrics_output_hash,
            "transcript_hash": evidence.transcript_hash,
        },
        reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
    )
