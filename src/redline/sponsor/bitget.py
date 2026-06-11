from __future__ import annotations

import gzip
import base64
import hashlib
import hmac
import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from redline.canonical import hash_obj, iter_canonical_files, sha256_bytes
from redline.models import DecisionEnvelope, ReasonCode, Status


class SponsorState(StrEnum):
    LOCAL_PASS_REQUIRED = "LOCAL_PASS_REQUIRED"
    ANNOTATED_PACKAGE_READY = "ANNOTATED_PACKAGE_READY"
    UPLOAD_ACCEPTED = "UPLOAD_ACCEPTED"
    RUN_STARTED = "RUN_STARTED"
    RUN_COMPLETED = "RUN_COMPLETED"
    READBACK_VERIFIED = "READBACK_VERIFIED"
    PUBLISHED = "PUBLISHED"
    RECORDED_ATTESTATION_VALID = "RECORDED_ATTESTATION_VALID"
    MISMATCH = "MISMATCH"


class SponsorStepResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ok: bool
    state: SponsorState
    evidence: dict[str, str] = Field(default_factory=dict)
    reason_code: ReasonCode | None = None


class SponsorAdapter(Protocol):
    def upload(self, *, envelope: DecisionEnvelope, package_hash: str, package_archive: Path, idempotency_key: str | None = None) -> SponsorStepResult: ...
    def run(self, *, version_id: str) -> SponsorStepResult: ...
    def poll(self, *, run_id: str) -> SponsorStepResult: ...
    def readback(
        self,
        *,
        run_id: str,
        expected_version_id: str | None = None,
        expected_metrics_output_hash: str | None = None,
        expected_package_hash: str | None = None,
        expected_package_archive_hash: str | None = None,
    ) -> SponsorStepResult: ...
    def publish(self, *, draft_id: str, bump_type: str = "patch") -> SponsorStepResult: ...


def assert_local_pass(envelope: DecisionEnvelope, call_site: str) -> SponsorStepResult | None:
    if envelope.status != Status.PASS or envelope.reason_code != ReasonCode.PASS:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.LOCAL_PASS_REQUIRED,
            evidence={"call_site": call_site, "status": envelope.status.value, "reason_code": envelope.reason_code.value},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    return None


class SponsorReadbackEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["redline.sponsor.bitget.readback.v1"] = "redline.sponsor.bitget.readback.v1"
    run_id: str
    version_id: str
    status: str
    metrics_output_hash: str
    expected_version_id: str
    expected_metrics_output_hash: str
    package_hash: str
    package_archive_hash: str
    source_kind: Literal["live", "mock", "recorded"]
    proof_eligible: bool
    transcript_hash: str

    @field_validator("metrics_output_hash", "expected_metrics_output_hash", "package_hash", "package_archive_hash", "transcript_hash")
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
            "source_kind": evidence.source_kind,
            "proof_eligible": str(evidence.proof_eligible and evidence.source_kind == "live").lower(),
            "transcript_hash": evidence.transcript_hash,
        },
        reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
    )


def verify_sponsor_readback_evidence(
    *,
    evidence_path: Path,
    adapter: SponsorAdapter,
    expected_package_hash: str | None = None,
    expected_package_archive_hash: str | None = None,
    expected_metrics_output_hash: str | None = None,
) -> SponsorStepResult:
    try:
        evidence = SponsorReadbackEvidence.model_validate(json.loads(evidence_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, reason_code=ReasonCode.SCHEMA_INVALID)
    if expected_package_hash is not None and evidence.package_hash != expected_package_hash:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"package_hash": evidence.package_hash, "expected_package_hash": expected_package_hash},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if expected_metrics_output_hash is not None and evidence.expected_metrics_output_hash != expected_metrics_output_hash:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"metrics_output_hash": evidence.expected_metrics_output_hash, "expected_metrics_output_hash": expected_metrics_output_hash},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if expected_package_archive_hash is not None and evidence.package_archive_hash != expected_package_archive_hash:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"package_archive_hash": evidence.package_archive_hash, "expected_package_archive_hash": expected_package_archive_hash},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    result = adapter.poll(run_id=evidence.run_id)
    if not result.ok:
        return result
    observed = result.evidence
    if observed.get("status") != "completed":
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": evidence.run_id, "status": observed.get("status", "")},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if observed.get("version_id") != evidence.expected_version_id:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": evidence.run_id, "version_id": observed.get("version_id", ""), "expected_version_id": evidence.expected_version_id},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if observed.get("metrics_output_hash") != evidence.expected_metrics_output_hash:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={
                "run_id": evidence.run_id,
                "metrics_output_hash": observed.get("metrics_output_hash", ""),
                "expected_metrics_output_hash": evidence.expected_metrics_output_hash,
            },
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if observed.get("run_id") not in {None, evidence.run_id}:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={"run_id": observed.get("run_id", ""), "expected_run_id": evidence.run_id},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if getattr(adapter, "proof_eligible", False) and (
        observed.get("package_hash") != evidence.package_hash
        or observed.get("package_archive_hash") != evidence.package_archive_hash
    ):
        return SponsorStepResult(
            ok=False,
            state=SponsorState.MISMATCH,
            evidence={
                "run_id": evidence.run_id,
                "package_hash": observed.get("package_hash", ""),
                "expected_package_hash": evidence.package_hash,
                "package_archive_hash": observed.get("package_archive_hash", ""),
                "expected_package_archive_hash": evidence.package_archive_hash,
            },
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    if not getattr(adapter, "proof_eligible", False):
        return SponsorStepResult(
            ok=False,
            state=SponsorState.RECORDED_ATTESTATION_VALID,
            evidence={
                "run_id": evidence.run_id,
                "version_id": evidence.expected_version_id,
                "metrics_output_hash": evidence.expected_metrics_output_hash,
                "source_kind": observed.get("source_kind", evidence.source_kind),
                "proof_eligible": "false",
                "transcript_hash": observed.get("transcript_hash", evidence.transcript_hash),
            },
            reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
        )
    return SponsorStepResult(
        ok=True,
        state=SponsorState.READBACK_VERIFIED,
        evidence={
            "run_id": evidence.run_id,
            "version_id": evidence.expected_version_id,
            "metrics_output_hash": evidence.expected_metrics_output_hash,
            "package_hash": evidence.package_hash,
            "package_archive_hash": evidence.package_archive_hash,
            "source_kind": "live",
            "proof_eligible": "true",
            "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "transcript_hash": observed.get("transcript_hash", evidence.transcript_hash),
        },
    )


Transport = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


class BitgetCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    access_key: str
    secret_key: str
    passphrase: str
    source_kind: Literal["live", "mock"] = "live"


class SponsorTranscript:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        step: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: bytes,
        status_code: int,
        response_body: bytes,
    ) -> None:
        entry = {
            "version": "redline.sponsor.transcript.v1",
            "step": step,
            "method": method,
            "url": _redact_url(url),
            "request_headers": {key: _mask(value) for key, value in sorted(request_headers.items())},
            "request_body_hash": sha256_bytes(request_body),
            "status_code": status_code,
            "response_body_hash": sha256_bytes(response_body),
            "captured_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        entry["entry_hash"] = hash_obj(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True))
            fh.write("\n")

    @property
    def transcript_hash(self) -> str:
        if not self.path.exists():
            return sha256_bytes(b"")
        return sha256_bytes(self.path.read_bytes())


class BitgetSponsorAdapter:
    def __init__(
        self,
        *,
        credentials: BitgetCredentials | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        passphrase: str | None = None,
        transcript_path: Path,
        base_url: str = "https://api.bitget.com",
        transport: Transport | None = None,
    ) -> None:
        if credentials is None:
            if access_key is None or secret_key is None or passphrase is None:
                raise ValueError("Bitget credentials require access_key, secret_key, and passphrase")
            source_kind: Literal["live", "mock"] = "mock" if transport is not None else "live"
            credentials = BitgetCredentials(access_key=access_key, secret_key=secret_key, passphrase=passphrase, source_kind=source_kind)
        self.credentials = credentials
        self.base_url = base_url.rstrip("/")
        self.transport = transport or _urllib_transport
        self.proof_eligible = credentials.source_kind == "live" and transport is None
        self.transcript = SponsorTranscript(transcript_path)
        self._expected_version_id: str | None = None
        self._expected_package_hash: str | None = None
        self._expected_package_archive_hash: str | None = None

    def upload(
        self,
        *,
        envelope: DecisionEnvelope,
        package_hash: str,
        package_archive: Path,
        idempotency_key: str | None = None,
    ) -> SponsorStepResult:
        pass_error = assert_local_pass(envelope, "upload")
        if pass_error is not None:
            return pass_error
        package_archive_hash = sha256_bytes(package_archive.read_bytes())
        self._expected_package_hash = package_hash
        self._expected_package_archive_hash = package_archive_hash
        body, content_type = _multipart_body(
            fields={
                "package_hash": package_hash,
                "package_archive_hash": package_archive_hash,
                "decision_hash": hash_obj(envelope),
            },
            file_field="package",
            file_name=package_archive.name,
            file_bytes=package_archive.read_bytes(),
        )
        result = self._request(
            step=SponsorState.UPLOAD_ACCEPTED,
            method="POST",
            path="/api/v1/playbook/upload",
            body=body,
            extra_headers={
                "Content-Type": content_type,
                "Idempotency-Key": idempotency_key or _idempotency_key(package_hash),
            },
        )
        if not result.ok:
            return result
        response_package_hash = result.evidence.get("package_hash")
        response_archive_hash = result.evidence.get("package_archive_hash")
        result = result.model_copy(
            update={
                "evidence": {
                    **result.evidence,
                    "package_hash": package_hash,
                    "package_archive_hash": package_archive_hash,
                }
            }
        )
        if response_package_hash is not None and response_package_hash != package_hash:
            return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, evidence=result.evidence, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
        if response_archive_hash is not None and response_archive_hash != package_archive_hash:
            return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, evidence=result.evidence, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
        if self.proof_eligible and (response_package_hash != package_hash or response_archive_hash != package_archive_hash):
            return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, evidence=result.evidence, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
        return result

    def run(self, *, version_id: str) -> SponsorStepResult:
        self._expected_version_id = version_id
        return self._json_request(
            step=SponsorState.RUN_STARTED,
            method="POST",
            path="/api/v1/playbook/run",
            payload={"version_id": version_id},
        )

    def poll(self, *, run_id: str) -> SponsorStepResult:
        return self._json_request(
            step=SponsorState.RUN_COMPLETED,
            method="GET",
            path="/api/v1/playbook/run?" + urllib.parse.urlencode({"run_id": run_id}),
            payload=None,
        )

    def readback(
        self,
        *,
        run_id: str,
        expected_version_id: str | None = None,
        expected_metrics_output_hash: str | None = None,
        expected_package_hash: str | None = None,
        expected_package_archive_hash: str | None = None,
    ) -> SponsorStepResult:
        result = self.poll(run_id=run_id)
        if not result.ok:
            return result
        if result.evidence.get("status") != "completed":
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={"run_id": run_id, "status": result.evidence.get("status", "")},
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        expected_version_id = expected_version_id or self._expected_version_id
        expected_package_hash = expected_package_hash or self._expected_package_hash
        expected_package_archive_hash = expected_package_archive_hash or self._expected_package_archive_hash
        if expected_version_id is None or result.evidence.get("version_id") != expected_version_id:
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={**result.evidence, "expected_version_id": expected_version_id or ""},
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        if expected_metrics_output_hash is None or result.evidence.get("metrics_output_hash") != expected_metrics_output_hash:
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={**result.evidence, "expected_metrics_output_hash": expected_metrics_output_hash or ""},
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        if expected_package_hash is None or expected_package_archive_hash is None:
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={**result.evidence, "expected_package_hash": expected_package_hash or "", "expected_package_archive_hash": expected_package_archive_hash or ""},
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        if self.proof_eligible and (
            result.evidence.get("package_hash") != expected_package_hash
            or result.evidence.get("package_archive_hash") != expected_package_archive_hash
        ):
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    **result.evidence,
                    "expected_package_hash": expected_package_hash,
                    "expected_package_archive_hash": expected_package_archive_hash,
                },
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        evidence = {
            **result.evidence,
            "expected_version_id": expected_version_id,
            "expected_metrics_output_hash": expected_metrics_output_hash,
            "package_hash": expected_package_hash,
            "package_archive_hash": expected_package_archive_hash,
            "transcript_hash": self.transcript.transcript_hash,
        }
        if not self.proof_eligible:
            return SponsorStepResult(
                ok=False,
                state=SponsorState.RECORDED_ATTESTATION_VALID,
                evidence=evidence,
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
            )
        return SponsorStepResult(
            ok=True,
            state=SponsorState.READBACK_VERIFIED,
            evidence=evidence,
        )

    def publish(self, *, draft_id: str, bump_type: str = "patch") -> SponsorStepResult:
        result = self._json_request(
            step=SponsorState.PUBLISHED,
            method="POST",
            path="/api/v1/playbook/publish",
            payload={"draft_id": draft_id, "bump_type": bump_type},
        )
        if not result.ok:
            return result
        if self.proof_eligible and not _publish_success_evidence(result.evidence):
            return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, evidence=result.evidence, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
        return result

    def _json_request(self, *, step: SponsorState, method: str, path: str, payload: dict | None) -> SponsorStepResult:
        body = b"" if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._request(step=step, method=method, path=path, body=body, extra_headers={"Content-Type": "application/json"})

    def _request(
        self,
        *,
        step: SponsorState,
        method: str,
        path: str,
        body: bytes,
        extra_headers: dict[str, str],
    ) -> SponsorStepResult:
        url = self.base_url + path
        headers = {**self._auth_headers(method=method, request_path=path, body=body), **extra_headers}
        try:
            status_code, response_body = self.transport(method, url, headers, body)
        except Exception as exc:
            response_body = json.dumps({"error": type(exc).__name__}, sort_keys=True).encode("utf-8")
            self.transcript.append(
                step=step.value,
                method=method,
                url=url,
                request_headers=headers,
                request_body=body,
                status_code=-1,
                response_body=response_body,
            )
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "error": type(exc).__name__,
                    "source_kind": self.credentials.source_kind,
                    "proof_eligible": str(self.proof_eligible).lower(),
                    "transcript_hash": self.transcript.transcript_hash,
                },
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
            )
        self.transcript.append(
            step=step.value,
            method=method,
            url=url,
            request_headers=headers,
            request_body=body,
            status_code=status_code,
            response_body=response_body,
        )
        try:
            payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "source_kind": self.credentials.source_kind,
                    "proof_eligible": str(self.proof_eligible).lower(),
                    "transcript_hash": self.transcript.transcript_hash,
                },
                reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
            )
        if status_code >= 400:
            return SponsorStepResult(
                ok=False,
                state=SponsorState.MISMATCH,
                evidence={
                    "status_code": str(status_code),
                    "source_kind": self.credentials.source_kind,
                    "proof_eligible": str(self.proof_eligible).lower(),
                    "transcript_hash": self.transcript.transcript_hash,
                },
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
            )
        if self.proof_eligible:
            code = str(payload.get("code", ""))
            if code != "00000":
                return SponsorStepResult(
                    ok=False,
                    state=SponsorState.MISMATCH,
                    evidence={
                        "status_code": str(status_code),
                        "bitget_code": code,
                        "source_kind": self.credentials.source_kind,
                        "proof_eligible": "true",
                        "transcript_hash": self.transcript.transcript_hash,
                    },
                    reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
                )
            data = payload.get("data", {})
            if not isinstance(data, dict):
                return SponsorStepResult(
                    ok=False,
                    state=SponsorState.MISMATCH,
                    evidence={
                        "status_code": str(status_code),
                        "bitget_code": code,
                        "source_kind": self.credentials.source_kind,
                        "proof_eligible": "true",
                        "transcript_hash": self.transcript.transcript_hash,
                    },
                    reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
                )
            payload = data
        evidence = {
            "source_kind": self.credentials.source_kind,
            "proof_eligible": str(self.proof_eligible).lower(),
        }
        evidence.update({str(key): str(value) for key, value in payload.items() if key != "metrics_output"})
        if "metrics_output" in payload:
            evidence["metrics_output_hash"] = hash_obj(payload["metrics_output"])
        return SponsorStepResult(ok=True, state=step, evidence=evidence)

    def _auth_headers(self, *, method: str, request_path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(datetime.now(UTC).timestamp() * 1000))
        prehash = (timestamp + method.upper() + request_path).encode("utf-8") + body
        signature = base64.b64encode(hmac.new(self.credentials.secret_key.encode("utf-8"), prehash, hashlib.sha256).digest()).decode("ascii")
        return {
            "ACCESS-KEY": self.credentials.access_key,
            "ACCESS-SIGN": signature,
            "ACCESS-TIMESTAMP": timestamp,
            "ACCESS-PASSPHRASE": self.credentials.passphrase,
        }


def make_package_archive(*, package_dir: Path, out_path: Path) -> Path:
    return _write_package_archive(package_dir=package_dir, out_path=out_path, annotation_path=None)


def make_annotated_package_archive(*, package_dir: Path, annotation_path: Path, out_path: Path) -> Path:
    return _write_package_archive(package_dir=package_dir, out_path=out_path, annotation_path=annotation_path)


def _write_package_archive(*, package_dir: Path, out_path: Path, annotation_path: Path | None) -> Path:
    root = package_dir.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for rel, file_path in iter_canonical_files(root):
                    data = file_path.read_bytes()
                    info = tarfile.TarInfo(rel)
                    info.size = len(data)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tar.addfile(info, io.BytesIO(data))
                if annotation_path is not None:
                    data = annotation_path.read_bytes()
                    info = tarfile.TarInfo(".redline/redline-annotation.json")
                    info.size = len(data)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tar.addfile(info, io.BytesIO(data))
    return out_path


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body if method != "GET" else None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _multipart_body(*, fields: dict[str, str], file_field: str, file_name: str, file_bytes: bytes) -> tuple[bytes, str]:
    boundary = "redline-boundary"
    chunks: list[bytes] = []
    for key, value in sorted(fields.items()):
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name}"\r\n'.encode(),
            b"Content-Type: application/gzip\r\n\r\n",
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _idempotency_key(package_hash: str) -> str:
    return "redline-" + package_hash.removeprefix("sha256:")[:32]


def _publish_success_evidence(evidence: dict[str, str]) -> bool:
    status = evidence.get("status")
    if status is not None and status.lower() not in {"published", "success", "succeeded", "completed", "ok"}:
        return False
    if any(key in evidence and evidence[key] for key in ("publish_id", "published_version_id", "version_id")):
        return True
    return status is not None


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


def _redact_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
