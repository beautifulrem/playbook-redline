from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from redline.models import DecisionEnvelope, ReasonCode, Status


class SponsorState(StrEnum):
    LOCAL_PASS_REQUIRED = "LOCAL_PASS_REQUIRED"
    ANNOTATED_PACKAGE_READY = "ANNOTATED_PACKAGE_READY"
    UPLOAD_ACCEPTED = "UPLOAD_ACCEPTED"
    RUN_STARTED = "RUN_STARTED"
    RUN_COMPLETED = "RUN_COMPLETED"
    READBACK_VERIFIED = "READBACK_VERIFIED"


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

