from __future__ import annotations

import html
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import CanonicalizationError, hash_file, hash_obj, hash_tree
from redline.io_safety import append_text, atomic_write_text, ensure_safe_output_dir
from redline.models import (
    ChainStatus,
    EditProvenance,
    LedgerCheckpoint,
    LedgerCheckpointAttestation,
    PackageAnnotation,
    PackageImportResult,
    Proof,
    ProofKind,
    ProbeSpec,
    ProbeType,
    PublishPreflightResult,
    ReasonCode,
    RedlineSpec,
    ReportJson,
    Status,
    VerificationLevel,
    VerificationStatus,
)
from redline.canonical import sha256_bytes
from redline.package_identity import load_identity_lock, write_identity_lock
from redline.proof_kernel import decision_envelope_from_receipt
from redline.sponsor.bitget import BitgetSponsorAdapter, SponsorState, SponsorStepResult, assert_local_pass, make_annotated_package_archive, make_package_archive
from redline.spec_compiler import LLMTransport, compile_text_spec
from redline.verifier import load_receipt, verify


def import_package(path: Path, *, write_lock: bool = False) -> PackageImportResult:
    root = path.resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)
    lock = write_identity_lock(root) if write_lock else load_identity_lock(root)
    files = [
        file_path.relative_to(root).as_posix()
        for file_path in sorted(p for p in root.rglob("*") if p.is_file())
        if "__pycache__" not in file_path.parts and not file_path.name.endswith((".pyc", ".pyo"))
    ]
    return PackageImportResult(
        path=str(root),
        identity_hash=hash_tree(root),
        files=files,
        adapter_id=lock.adapter_id,
        identity_lock_hash=lock.lock_hash,
        identity_lock_path=str(root / "playbook_identity.lock"),
    )


def compile_spec(
    source_path: Path,
    *,
    use_qwen: bool = False,
    qwen_model: str | None = None,
    qwen_base_url: str | None = None,
    qwen_api_key: str | None = None,
    qwen_transport: LLMTransport | None = None,
) -> RedlineSpec:
    if not source_path.exists():
        raise FileNotFoundError(source_path)
    text = source_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        if source_path.suffix.lower() == ".json":
            raise
        return compile_text_spec(
            text=text,
            source_path=source_path,
            use_qwen=use_qwen,
            model=qwen_model,
            base_url=qwen_base_url,
            api_key=qwen_api_key,
            transport=qwen_transport,
        )
    return RedlineSpec.model_validate(payload)


def capture_edit_provenance(
    *,
    tool: str,
    prompt_log: Path,
    baseline: Path | None = None,
    candidate: Path | None = None,
    diff: Path | None = None,
    locked_by: str = "author",
) -> EditProvenance:
    if diff is not None:
        diff_hash = hash_file(diff)
    elif baseline is not None and candidate is not None:
        diff_hash = hash_obj({"baseline": hash_tree(baseline), "candidate": hash_tree(candidate)})
    else:
        diff_hash = hash_obj({"diff": "unavailable"})
    return EditProvenance(
        tool=tool,
        prompt_digest=hash_file(prompt_log),
        diff_hash=diff_hash,
        locked_by=locked_by,
        captured_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )


class _PreflightTranscript:
    def __init__(self, path: Path) -> None:
        self.path = path
        atomic_write_text(self.path, "")

    def append(self, *, step_id: str, command: str, inputs: dict[str, object], output: dict[str, object], exit_code: int) -> None:
        entry = {
            "version": "redline.preflight.transcript.v1",
            "captured_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "step_id": step_id,
            "command": command,
            "input_hash": hash_obj(inputs),
            "output_hash": hash_obj(output),
            "exit_code": exit_code,
        }
        entry = {**entry, "entry_hash": hash_obj(entry)}
        append_text(self.path, json.dumps(entry, sort_keys=True) + "\n")

    @property
    def transcript_hash(self) -> str:
        return sha256_bytes(self.path.read_bytes())


def _with_preflight_transcript(result: PublishPreflightResult, transcript: _PreflightTranscript | None) -> PublishPreflightResult:
    if transcript is None:
        return result
    return result.model_copy(
        update={
            "preflight_transcript_path": str(transcript.path),
            "preflight_transcript_hash": transcript.transcript_hash,
        }
    )


def publish_preflight(
    *,
    receipt_path: Path,
    package: Path,
    suite_path: Path,
    spec_path: Path,
    out_dir: Path,
    report_path: Path | None = None,
    ledger_checkpoint_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    trusted_ledger_public_key: str | None = None,
    trust_policy_path: Path | None = None,
    trust_policy_hash: str | None = None,
    baseline_receipt_path: Path | None = None,
    allow_demo_baseline_genesis: bool = False,
) -> PublishPreflightResult:
    report_path = report_path or receipt_path.parent / "report.json"
    ledger_checkpoint_path = ledger_checkpoint_path or receipt_path.parent / "issuance-ledger.checkpoint.json"
    ledger_attestation_path = ledger_attestation_path or receipt_path.parent / "issuance-ledger.attestation.json"
    if out_dir.resolve() == package.resolve() or package.resolve() in out_dir.resolve().parents:
        return PublishPreflightResult(ok=False, state="OUTPUT_PATH_INSIDE_PACKAGE", reason_code=ReasonCode.RECEIPT_BINDING_FAILED)
    try:
        if out_dir.exists() and not out_dir.is_dir():
            return PublishPreflightResult(ok=False, state="OUTPUT_PATH_INVALID", reason_code=ReasonCode.DATA_MISSING)
        ensure_safe_output_dir(out_dir)
        transcript = _PreflightTranscript(out_dir / "preflight-transcript.jsonl")
    except (CanonicalizationError, OSError) as exc:
        reason = exc.reason_code if isinstance(exc, CanonicalizationError) else ReasonCode.DATA_MISSING
        return PublishPreflightResult(ok=False, state="OUTPUT_PATH_INVALID", reason_code=reason)
    try:
        package_hash = hash_tree(package)
    except FileNotFoundError:
        result = PublishPreflightResult(ok=False, state="PACKAGE_INVALID", reason_code=ReasonCode.FILE_NOT_FOUND)
        transcript.append(
            step_id="package-hash",
            command="hash_tree(package)",
            inputs={"package": str(package)},
            output=result.model_dump(mode="json"),
            exit_code=1,
        )
        return _with_preflight_transcript(result, transcript)
    except (NotADirectoryError, CanonicalizationError) as exc:
        reason = exc.reason_code if isinstance(exc, CanonicalizationError) else ReasonCode.FILE_NOT_FOUND
        result = PublishPreflightResult(ok=False, state="PACKAGE_INVALID", reason_code=reason)
        transcript.append(
            step_id="package-hash",
            command="hash_tree(package)",
            inputs={"package": str(package)},
            output=result.model_dump(mode="json"),
            exit_code=1,
        )
        return _with_preflight_transcript(result, transcript)
    transcript.append(
        step_id="package-hash",
        command="hash_tree(package)",
        inputs={"package": str(package)},
        output={"package_hash": package_hash},
        exit_code=0,
    )
    result = verify(
        receipt_path=receipt_path,
        package=package,
        suite_path=suite_path,
        spec_path=spec_path,
        report_path=report_path,
        ledger_checkpoint_path=ledger_checkpoint_path,
        ledger_attestation_path=ledger_attestation_path,
        trusted_ledger_public_key=trusted_ledger_public_key,
        trust_policy_path=trust_policy_path,
        baseline_receipt_path=baseline_receipt_path,
        level=VerificationLevel.REPLAYED,
    )
    transcript.append(
        step_id="verify-replayed",
        command="verify(level=replayed)",
        inputs={
            "receipt_path": str(receipt_path),
            "package": str(package),
            "suite_path": str(suite_path),
            "spec_path": str(spec_path),
            "report_path": str(report_path),
            "ledger_checkpoint_path": str(ledger_checkpoint_path),
            "ledger_attestation_path": str(ledger_attestation_path),
            "baseline_receipt_path": str(baseline_receipt_path) if baseline_receipt_path is not None else None,
        },
        output=result.model_dump(mode="json"),
        exit_code=0 if result.status == VerificationStatus.VERIFIED else 1,
    )
    if result.status != VerificationStatus.VERIFIED:
        if result.reason_code == ReasonCode.BASELINE_GENESIS and allow_demo_baseline_genesis:
            pass
        elif result.reason_code == ReasonCode.BASELINE_GENESIS:
            return _with_preflight_transcript(PublishPreflightResult(
                ok=False,
                state="CHAINED_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            ), transcript)
        elif result.reason_code == ReasonCode.BASELINE_UNCHAINED:
            return _with_preflight_transcript(PublishPreflightResult(
                ok=False,
                state="TRUSTED_LEDGER_CHECKPOINT_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            ), transcript)
        else:
            return _with_preflight_transcript(PublishPreflightResult(
                ok=False,
                state="LOCAL_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            ), transcript)
    if result.status == VerificationStatus.VERIFIED and result.reason_code not in {ReasonCode.PASS, ReasonCode.BASELINE_GENESIS}:
        return _with_preflight_transcript(PublishPreflightResult(
            ok=False,
            state="LOCAL_PASS_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=result.reason_code,
        ), transcript)
    if result.reason_code == ReasonCode.BASELINE_GENESIS or result.chain_status != ChainStatus.CHAINED:
        if not allow_demo_baseline_genesis:
            return _with_preflight_transcript(PublishPreflightResult(
                ok=False,
                state="CHAINED_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            ), transcript)
    checkpoint = _load_checkpoint(ledger_checkpoint_path)
    if checkpoint is None:
        blocked = PublishPreflightResult(
            ok=False,
            state="LEDGER_CHECKPOINT_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=ReasonCode.RECEIPT_MISMATCH,
        )
        transcript.append(
            step_id="load-ledger-checkpoint",
            command="load_checkpoint",
            inputs={"ledger_checkpoint_path": str(ledger_checkpoint_path)},
            output=blocked.model_dump(mode="json"),
            exit_code=1,
        )
        return _with_preflight_transcript(blocked, transcript)
    transcript.append(
        step_id="load-ledger-checkpoint",
        command="load_checkpoint",
        inputs={"ledger_checkpoint_path": str(ledger_checkpoint_path)},
        output=checkpoint.model_dump(mode="json"),
        exit_code=0,
    )
    trust_policy_checked = False
    if trust_policy_path is not None or trust_policy_hash is not None:
        trust_policy_ok = _trust_policy_matches(trust_policy_path=trust_policy_path, trust_policy_hash=trust_policy_hash)
        if not trust_policy_ok:
            blocked = PublishPreflightResult(
                ok=False,
                state="TRUST_POLICY_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                report_hash=_report_hash(report_path),
                ledger_hash=checkpoint.ledger_hash,
                ledger_checkpoint_hash=checkpoint.checkpoint_hash,
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
            )
            transcript.append(
                step_id="trust-policy",
                command="verify_trust_policy",
                inputs={"trust_policy_path": str(trust_policy_path) if trust_policy_path is not None else None, "trust_policy_hash": trust_policy_hash},
                output=blocked.model_dump(mode="json"),
                exit_code=1,
            )
            return _with_preflight_transcript(blocked, transcript)
        transcript.append(
            step_id="trust-policy",
            command="verify_trust_policy",
            inputs={"trust_policy_path": str(trust_policy_path), "trust_policy_hash": trust_policy_hash},
            output={"ok": True},
            exit_code=0,
        )
        trust_policy_checked = True
    if result.chain_status == ChainStatus.CHAINED and trust_policy_path is None:
        blocked = PublishPreflightResult(
            ok=False,
            state="TRUSTED_LEDGER_CHECKPOINT_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            report_hash=_report_hash(report_path),
            ledger_hash=checkpoint.ledger_hash,
            ledger_checkpoint_hash=checkpoint.checkpoint_hash,
            reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
        )
        transcript.append(
            step_id="trust-policy",
            command="verify_trust_policy",
            inputs={"trust_policy_path": None, "trust_policy_hash": trust_policy_hash},
            output=blocked.model_dump(mode="json"),
            exit_code=1,
        )
        return _with_preflight_transcript(blocked, transcript)
    if result.chain_status == ChainStatus.CHAINED and not trust_policy_checked:
        trust_policy_ok = _trust_policy_matches(trust_policy_path=trust_policy_path, trust_policy_hash=trust_policy_hash)
        if not trust_policy_ok:
            blocked = PublishPreflightResult(
                ok=False,
                state="TRUST_POLICY_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                report_hash=_report_hash(report_path),
                ledger_hash=checkpoint.ledger_hash,
                ledger_checkpoint_hash=checkpoint.checkpoint_hash,
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
            )
            transcript.append(
                step_id="trust-policy",
                command="verify_trust_policy",
                inputs={"trust_policy_path": str(trust_policy_path), "trust_policy_hash": trust_policy_hash},
                output=blocked.model_dump(mode="json"),
                exit_code=1,
            )
            return _with_preflight_transcript(blocked, transcript)
        transcript.append(
            step_id="trust-policy",
            command="verify_trust_policy",
            inputs={"trust_policy_path": str(trust_policy_path), "trust_policy_hash": trust_policy_hash},
            output={"ok": True},
            exit_code=0,
        )
    ensure_safe_output_dir(out_dir)
    try:
        package_archive, annotation = make_receipt_bound_package_archive(
            receipt_path=receipt_path,
            package=package,
            annotation_path=out_dir / "redline-annotation.json",
            out_path=out_dir / "annotated-package.tar.gz",
            ledger_checkpoint_path=ledger_checkpoint_path,
            ledger_attestation_path=ledger_attestation_path,
            package_hash=package_hash,
            strength_summary=result.strength_summary,
            verification_level=result.verification_level,
        )
    except (CanonicalizationError, OSError) as exc:
        reason = exc.reason_code if isinstance(exc, CanonicalizationError) else ReasonCode.DATA_MISSING
        blocked = PublishPreflightResult(
            ok=False,
            state="OUTPUT_PATH_INVALID",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=reason,
        )
        transcript.append(
            step_id="annotate-package",
            command="make_receipt_bound_package_archive",
            inputs={
                "receipt_path": str(receipt_path),
                "package": str(package),
                "annotation_path": str(out_dir / "redline-annotation.json"),
                "out_path": str(out_dir / "annotated-package.tar.gz"),
            },
            output=blocked.model_dump(mode="json"),
            exit_code=1,
        )
        return _with_preflight_transcript(blocked, transcript)
    package_archive_hash = sha256_bytes(package_archive.read_bytes())
    transcript.append(
        step_id="annotate-package",
        command="make_receipt_bound_package_archive",
        inputs={
            "receipt_path": str(receipt_path),
            "package": str(package),
            "annotation_path": str(out_dir / "redline-annotation.json"),
            "out_path": str(out_dir / "annotated-package.tar.gz"),
        },
        output={
            "package_archive_hash": package_archive_hash,
            "annotation_hash": annotation.annotation_hash,
            "annotation_kind": annotation.annotation_kind,
        },
        exit_code=0,
    )
    return _with_preflight_transcript(PublishPreflightResult(
        ok=True,
        state="DEMO_ANNOTATION_READY" if annotation.annotation_kind == "demo-preview" else "ANNOTATED_PACKAGE_READY",
        receipt_hash=result.receipt_hash,
        package_hash=package_hash,
        package_archive_hash=package_archive_hash,
        report_hash=annotation.report_hash,
        ledger_hash=checkpoint.ledger_hash,
        ledger_checkpoint_hash=checkpoint.checkpoint_hash,
        ledger_attestation_hash=annotation.ledger_attestation_hash,
        annotation_hash=annotation.annotation_hash,
        reason_code=result.reason_code,
    ), transcript)


def make_receipt_bound_package_archive(
    *,
    receipt_path: Path,
    package: Path,
    annotation_path: Path,
    out_path: Path,
    ledger_checkpoint_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    package_hash: str | None = None,
    strength_summary: str | None = None,
    verification_level: VerificationLevel = VerificationLevel.REPLAYED,
) -> tuple[Path, PackageAnnotation]:
    receipt = load_receipt(receipt_path)
    package_hash = package_hash or hash_tree(package)
    checkpoint_path = ledger_checkpoint_path or receipt_path.parent / "issuance-ledger.checkpoint.json"
    checkpoint = _load_checkpoint(checkpoint_path)
    if checkpoint is None:
        raise FileNotFoundError(checkpoint_path)
    attestation_path = ledger_attestation_path or receipt_path.parent / "issuance-ledger.attestation.json"
    attestation = _load_attestation(attestation_path) if attestation_path.exists() else None
    annotation = PackageAnnotation(
        annotation_kind="demo-preview" if receipt.baseline.chain_status != ChainStatus.CHAINED else "publish-preflight",
        receipt_path=_portable_artifact_label(receipt_path),
        receipt_hash=receipt.receipt_hash,
        report_hash=receipt.report.report_hash,
        package_hash=package_hash,
        ledger_hash=checkpoint.ledger_hash,
        ledger_checkpoint_hash=checkpoint.checkpoint_hash,
        ledger_attestation_hash=attestation.attestation_hash if attestation is not None else None,
        strength_summary=strength_summary or receipt.strength_summary,
        chain_status=receipt.baseline.chain_status,
        verification_level=verification_level,
        trust_policy_id=attestation.trust_policy_id if attestation is not None else None,
        trusted_ledger_key_id=attestation.key_id if attestation is not None else None,
        annotation_hash="",
    )
    annotation = annotation.model_copy(update={"annotation_hash": hash_obj(annotation)})
    ensure_safe_output_dir(annotation_path.parent)
    ensure_safe_output_dir(out_path.parent)
    atomic_write_text(annotation_path, annotation.model_dump_json(indent=2) + "\n")
    return make_annotated_package_archive(package_dir=package, annotation_path=annotation_path, out_path=out_path), annotation


def _portable_artifact_label(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def verify_annotation(
    *,
    annotation_path: Path,
    receipt_path: Path | None = None,
    package: Path | None = None,
    report_path: Path | None = None,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
    ledger_checkpoint_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    trust_policy_path: Path | None = None,
    trust_policy_hash: str | None = None,
    baseline_receipt_path: Path | None = None,
    allow_demo_preview: bool = False,
) -> PublishPreflightResult:
    try:
        annotation = PackageAnnotation.model_validate(json.loads(annotation_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return PublishPreflightResult(ok=False, state="ANNOTATION_INVALID", reason_code=ReasonCode.SCHEMA_INVALID)
    if receipt_path is None or package is None or report_path is None or ledger_checkpoint_path is None:
        return PublishPreflightResult(
            ok=False,
            state="ANNOTATION_BINDINGS_REQUIRED",
            annotation_hash=annotation.annotation_hash,
            reason_code=ReasonCode.DATA_MISSING,
        )
    expected_hash = hash_obj(annotation.model_copy(update={"annotation_hash": ""}))
    if annotation.annotation_hash != expected_hash:
        return PublishPreflightResult(ok=False, state="ANNOTATION_HASH_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if receipt_path is not None:
        try:
            receipt = load_receipt(receipt_path)
        except Exception:
            return PublishPreflightResult(ok=False, state="RECEIPT_INVALID", reason_code=ReasonCode.PARSE_ERROR)
        resolved_suite_path = suite_path or _resolve_receipt_source_path(receipt.suite.source_path, receipt_path=receipt_path, package=package)
        resolved_spec_path = spec_path or _resolve_receipt_source_path(receipt.spec.source_path, receipt_path=receipt_path, package=package)
        verification = verify(
            receipt_path=receipt_path,
            package=package,
            suite_path=resolved_suite_path,
            spec_path=resolved_spec_path,
            report_path=report_path,
            ledger_checkpoint_path=ledger_checkpoint_path,
            ledger_attestation_path=ledger_attestation_path,
            trust_policy_path=trust_policy_path,
            baseline_receipt_path=baseline_receipt_path,
            level=VerificationLevel.REPLAYED,
        )
        if verification.status in {VerificationStatus.BAD_INPUT, VerificationStatus.REJECTED}:
            return PublishPreflightResult(ok=False, state="ANNOTATION_RECEIPT_INVALID", reason_code=verification.reason_code)
        if annotation.annotation_kind == "publish-preflight" and (
            verification.status != VerificationStatus.VERIFIED or verification.reason_code != ReasonCode.PASS
        ):
            return PublishPreflightResult(ok=False, state="ANNOTATION_LOCAL_PASS_REQUIRED", reason_code=verification.reason_code)
        if annotation.receipt_hash != receipt.receipt_hash or annotation.report_hash != receipt.report.report_hash:
            return PublishPreflightResult(ok=False, state="ANNOTATION_BINDING_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
        if (
            annotation.strength_summary != receipt.strength_summary
            or annotation.chain_status != receipt.baseline.chain_status
            or annotation.verification_level != verification.verification_level
        ):
            return PublishPreflightResult(ok=False, state="ANNOTATION_BINDING_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if package is not None and annotation.package_hash != hash_tree(package):
        return PublishPreflightResult(ok=False, state="ANNOTATION_PACKAGE_MISMATCH", reason_code=ReasonCode.RECEIPT_BINDING_FAILED)
    if report_path is not None and annotation.report_hash != _report_hash(report_path):
        return PublishPreflightResult(ok=False, state="ANNOTATION_REPORT_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if ledger_checkpoint_path is not None:
        checkpoint = _load_checkpoint(ledger_checkpoint_path)
        if checkpoint is None or annotation.ledger_checkpoint_hash != checkpoint.checkpoint_hash or annotation.ledger_hash != checkpoint.ledger_hash:
            return PublishPreflightResult(ok=False, state="ANNOTATION_LEDGER_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if annotation.annotation_kind == "publish-preflight" and (
        annotation.ledger_attestation_hash is None or annotation.trust_policy_id is None or annotation.trusted_ledger_key_id is None
    ):
        return PublishPreflightResult(ok=False, state="ANNOTATION_ATTESTATION_REQUIRED", reason_code=ReasonCode.DATA_MISSING)
    publish_receipt_not_pass = (
        receipt.result.status != Status.PASS
        or receipt.decision.reason_code != ReasonCode.PASS
        or receipt.baseline.chain_status != ChainStatus.CHAINED
    )
    if annotation.annotation_kind == "publish-preflight" and publish_receipt_not_pass:
        return PublishPreflightResult(
            ok=False,
            state="ANNOTATION_LOCAL_PASS_REQUIRED",
            receipt_hash=annotation.receipt_hash,
            package_hash=annotation.package_hash,
            report_hash=annotation.report_hash,
            ledger_hash=annotation.ledger_hash,
            ledger_checkpoint_hash=annotation.ledger_checkpoint_hash,
            annotation_hash=annotation.annotation_hash,
            reason_code=receipt.decision.reason_code,
        )
    if annotation.annotation_kind == "demo-preview" and not allow_demo_preview:
        return PublishPreflightResult(
            ok=False,
            state="DEMO_ANNOTATION_REQUIRES_ALLOW_FLAG",
            receipt_hash=annotation.receipt_hash,
            package_hash=annotation.package_hash,
            report_hash=annotation.report_hash,
            ledger_hash=annotation.ledger_hash,
            ledger_checkpoint_hash=annotation.ledger_checkpoint_hash,
            annotation_hash=annotation.annotation_hash,
            reason_code=ReasonCode.BASELINE_GENESIS,
        )
    demo_receipt_mismatch = (
        receipt.result.status != Status.PASS
        or receipt.decision.reason_code != ReasonCode.BASELINE_GENESIS
        or receipt.baseline.chain_status != ChainStatus.GENESIS
    )
    if annotation.annotation_kind == "demo-preview" and demo_receipt_mismatch:
        return PublishPreflightResult(ok=False, state="ANNOTATION_DEMO_PREVIEW_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if annotation.ledger_attestation_hash is not None:
        if ledger_attestation_path is None or trust_policy_path is None:
            return PublishPreflightResult(ok=False, state="ANNOTATION_ATTESTATION_REQUIRED", reason_code=ReasonCode.DATA_MISSING)
        attestation = _load_attestation(ledger_attestation_path)
        if attestation is None or annotation.ledger_attestation_hash != attestation.attestation_hash:
            return PublishPreflightResult(ok=False, state="ANNOTATION_ATTESTATION_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
        if annotation.trust_policy_id != attestation.trust_policy_id or annotation.trusted_ledger_key_id != attestation.key_id:
            return PublishPreflightResult(ok=False, state="ANNOTATION_ATTESTATION_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
        if annotation.annotation_kind == "publish-preflight" and not _trust_policy_matches(
            trust_policy_path=trust_policy_path,
            trust_policy_hash=trust_policy_hash,
        ):
            return PublishPreflightResult(ok=False, state="ANNOTATION_TRUST_POLICY_REQUIRED", reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED)
        checkpoint = _load_checkpoint(ledger_checkpoint_path) if ledger_checkpoint_path is not None else None
        if checkpoint is None or not _verify_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy_path=trust_policy_path):
            return PublishPreflightResult(ok=False, state="ANNOTATION_ATTESTATION_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    return PublishPreflightResult(
        ok=True,
        state="ANNOTATION_VERIFIED",
        receipt_hash=annotation.receipt_hash,
        package_hash=annotation.package_hash,
        report_hash=annotation.report_hash,
        ledger_hash=annotation.ledger_hash,
        ledger_checkpoint_hash=annotation.ledger_checkpoint_hash,
        ledger_attestation_hash=annotation.ledger_attestation_hash,
        annotation_hash=annotation.annotation_hash,
        reason_code=ReasonCode.BASELINE_GENESIS if annotation.annotation_kind == "demo-preview" else ReasonCode.PASS,
    )


def execute_sponsor_readback(
    *,
    receipt_path: Path,
    package: Path,
    out_dir: Path,
    access_key: str,
    secret_key: str,
    passphrase: str,
    final_publish: bool = False,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    trust_policy_path: Path | None = None,
    trust_policy_hash: str | None = None,
    baseline_receipt_path: Path | None = None,
) -> SponsorStepResult:
    receipt = load_receipt(receipt_path)
    envelope = decision_envelope_from_receipt(receipt)
    pass_error = assert_local_pass(envelope, "execute_sponsor_readback")
    if pass_error is not None:
        return pass_error
    if envelope.chain_status != ChainStatus.CHAINED:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.LOCAL_PASS_REQUIRED,
            evidence={"call_site": "execute_sponsor_readback", "chain_status": envelope.chain_status.value},
            reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    annotation_path = out_dir / "redline-annotation.json"
    if not annotation_path.exists():
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, reason_code=ReasonCode.DATA_MISSING)
    trust_policy_path = trust_policy_path or (
        Path(os.environ["REDLINE_TRUST_POLICY"]) if os.environ.get("REDLINE_TRUST_POLICY") else None
    )
    trust_policy_hash = trust_policy_hash or os.environ.get("REDLINE_TRUST_POLICY_HASH")
    annotation_result = verify_annotation(
        annotation_path=annotation_path,
        receipt_path=receipt_path,
        package=package,
        report_path=receipt_path.parent / "report.json",
        suite_path=suite_path,
        spec_path=spec_path,
        ledger_checkpoint_path=receipt_path.parent / "issuance-ledger.checkpoint.json",
        ledger_attestation_path=ledger_attestation_path or receipt_path.parent / "issuance-ledger.attestation.json",
        trust_policy_path=trust_policy_path,
        trust_policy_hash=trust_policy_hash,
        baseline_receipt_path=baseline_receipt_path,
    )
    if not annotation_result.ok:
        return SponsorStepResult(
            ok=False,
            state=SponsorState.LOCAL_PASS_REQUIRED,
            evidence={"annotation_state": annotation_result.state},
            reason_code=annotation_result.reason_code or ReasonCode.SPONSOR_READBACK_MISMATCH,
        )
    archive = make_package_archive(package_dir=package, out_path=out_dir / "package.tar.gz")
    adapter = BitgetSponsorAdapter(access_key=access_key, secret_key=secret_key, passphrase=passphrase, transcript_path=out_dir / "sponsor-transcript.jsonl")
    upload = adapter.upload(envelope=envelope, package_hash=receipt.package.identity_hash, package_archive=archive)
    if not upload.ok:
        return upload
    version_id = upload.evidence.get("draft_id") or upload.evidence.get("version_id")
    if version_id is None:
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
    run = adapter.run(version_id=version_id)
    if not run.ok:
        return run
    run_id = run.evidence.get("run_id")
    if run_id is None:
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
    readback = adapter.readback(
        run_id=run_id,
        expected_version_id=version_id,
        expected_package_hash=receipt.package.identity_hash,
        expected_package_archive_hash=upload.evidence.get("package_archive_hash"),
    )
    _write_sponsor_readback(out_dir / "sponsor-readback.json", readback)
    _write_sponsor_readback_proof(
        out_dir=out_dir,
        result=readback,
        receipt_hash=receipt.receipt_hash,
        package_hash=receipt.package.identity_hash,
        annotation_hash=annotation_result.annotation_hash or "",
        annotation_file_hash=hash_file(annotation_path),
    )
    if not final_publish or not readback.ok:
        return readback
    draft_id = upload.evidence.get("draft_id")
    if draft_id is None:
        return SponsorStepResult(ok=False, state=SponsorState.MISMATCH, evidence=readback.evidence, reason_code=ReasonCode.SPONSOR_READBACK_MISMATCH)
    published = adapter.publish(draft_id=draft_id)
    if not published.ok:
        return published
    return SponsorStepResult(ok=True, state=SponsorState.PUBLISHED, evidence={**readback.evidence, **published.evidence})


def _resolve_receipt_source_path(value: str, *, receipt_path: Path, package: Path | None) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    candidates = [Path.cwd() / path, receipt_path.resolve().parent / path]
    if package is not None:
        resolved_package = package.resolve()
        candidates.extend(parent / path for parent in resolved_package.parents)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return (receipt_path.resolve().parent / path).resolve()


def render_report_html(
    report_path: Path,
    out_path: Path,
    *,
    receipt_path: Path | None = None,
    package: Path | None = None,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
    ledger_attestation_path: Path | None = None,
    trusted_ledger_public_key: str | None = None,
    trust_policy_path: Path | None = None,
    trust_policy_hash: str | None = None,
    baseline_receipt_path: Path | None = None,
    require_verified: bool = False,
) -> None:
    payload = _load_report_payload(report_path)
    verified = False
    verification_reason = "UNVERIFIED_PREVIEW"
    if receipt_path is not None and package is not None and suite_path is not None and spec_path is not None:
        result = verify(
            receipt_path=receipt_path,
            package=package,
            suite_path=suite_path,
            spec_path=spec_path,
            report_path=report_path,
            ledger_attestation_path=ledger_attestation_path,
            trusted_ledger_public_key=trusted_ledger_public_key,
            trust_policy_path=trust_policy_path,
            baseline_receipt_path=baseline_receipt_path,
            level=VerificationLevel.REPLAYED,
        )
        verified = (
            result.status == VerificationStatus.VERIFIED
            and result.receipt_hash == payload.get("receipt_hash")
            and _trust_policy_matches(trust_policy_path=trust_policy_path, trust_policy_hash=trust_policy_hash)
        )
        verification_reason = result.reason_code.value
    if require_verified and not verified:
        raise ValueError(f"report is not replay-verified: {verification_reason}")
    title = "Playbook Redline Report"
    status = payload.get("envelope", {}).get("status", "unknown")
    reason = payload.get("envelope", {}).get("reason_code", "unknown")
    summary = payload.get("strength_summary", "")
    body = json.dumps(payload, indent=2, sort_keys=True)
    stamp = f"VERIFIED / {reason}" if verified else f"UNVERIFIED PREVIEW / {reason}"
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem; background: #101214; color: #f4f1ea; }}
    .stamp {{ display: inline-block; border: 2px solid #ff5a3d; color: #ff5a3d; padding: .35rem .6rem; transform: rotate(-4deg); }}
    pre {{ white-space: pre-wrap; background: #181b1f; padding: 1rem; border: 1px solid #343941; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <p class="stamp">{html.escape(stamp)}</p>
  <p>Status: {html.escape(str(status)).upper()}</p>
  <p>{html.escape(str(summary))}</p>
  <pre>{html.escape(body)}</pre>
</body>
</html>
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_doc, encoding="utf-8")


def _load_checkpoint(path: Path) -> LedgerCheckpoint | None:
    try:
        checkpoint = LedgerCheckpoint.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None
    expected_hash = hash_obj(checkpoint.model_copy(update={"checkpoint_hash": ""}))
    return checkpoint if checkpoint.checkpoint_hash == expected_hash else None


def _load_attestation(path: Path) -> LedgerCheckpointAttestation | None:
    try:
        attestation = LedgerCheckpointAttestation.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None
    expected_hash = hash_obj(attestation.model_copy(update={"attestation_hash": ""}))
    return attestation if attestation.attestation_hash == expected_hash else None


def _verify_attestation(*, checkpoint: LedgerCheckpoint, attestation: LedgerCheckpointAttestation, trust_policy_path: Path) -> bool:
    from redline.models import TrustPolicy
    from redline.trust import verify_checkpoint_attestation

    try:
        policy = TrustPolicy.model_validate(json.loads(trust_policy_path.read_text(encoding="utf-8")))
        return verify_checkpoint_attestation(checkpoint=checkpoint, attestation=attestation, trust_policy=policy)
    except Exception:
        return False


def _trust_policy_matches(*, trust_policy_path: Path | None, trust_policy_hash: str | None) -> bool:
    if trust_policy_path is None or trust_policy_hash is None:
        return False
    try:
        from redline.models import TrustPolicy
        from redline.trust import verify_trust_policy

        policy = TrustPolicy.model_validate(json.loads(trust_policy_path.read_text(encoding="utf-8")))
    except Exception:
        return False
    return policy.policy_hash == trust_policy_hash and verify_trust_policy(policy)


def _load_report_payload(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        report = ReportJson.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("report JSON is invalid") from exc
    report_payload = report.model_dump(mode="json")
    expected_hash = hash_obj({key: value for key, value in {**report_payload, "receipt_hash": None}.items() if key != "report_hash"})
    if report.report_hash != expected_hash:
        raise ValueError("report_hash mismatch")
    return report_payload


def _report_hash(path: Path) -> str | None:
    try:
        return _load_report_payload(path)["report_hash"]
    except ValueError:
        return None


def _write_sponsor_readback(path: Path, result: SponsorStepResult) -> None:
    if "run_id" not in result.evidence or "version_id" not in result.evidence or "metrics_output_hash" not in result.evidence:
        return
    payload = {
        "version": "redline.sponsor.bitget.readback.v1",
        "run_id": result.evidence["run_id"],
        "version_id": result.evidence["version_id"],
        "status": result.evidence.get("status", ""),
        "metrics_output_hash": result.evidence["metrics_output_hash"],
        "expected_version_id": result.evidence.get("expected_version_id", ""),
        "package_hash": result.evidence.get("package_hash", ""),
        "package_archive_hash": result.evidence.get("package_archive_hash", ""),
        "source_kind": result.evidence.get("source_kind", "live"),
        "proof_eligible": result.evidence.get("proof_eligible") == "true",
        "transcript_hash": result.evidence.get("transcript_hash", ""),
    }
    if result.evidence.get("expected_metrics_output_hash"):
        payload["expected_metrics_output_hash"] = result.evidence["expected_metrics_output_hash"]
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_sponsor_readback_proof(
    *,
    out_dir: Path,
    result: SponsorStepResult,
    receipt_hash: str,
    package_hash: str,
    annotation_hash: str,
    annotation_file_hash: str,
) -> None:
    if "run_id" not in result.evidence or "version_id" not in result.evidence or "metrics_output_hash" not in result.evidence:
        return
    artifact = {
        "state": result.state.value,
        "ok": result.ok,
        "reason_code": (result.reason_code or ReasonCode.PASS).value,
        "evidence": result.evidence,
    }
    proof = Proof(
        proof_id=f"proof:sponsor_readback:{hash_obj({'receipt_hash': receipt_hash, 'artifact': artifact})[-24:]}",
        phase="sponsor-readback",
        kind=ProofKind.SPONSOR_READBACK,
        verdict_bearing=False,
        inputs_hash=hash_obj(
            {
                "receipt_hash": receipt_hash,
                "package_hash": package_hash,
                "annotation_hash": annotation_hash,
                "annotation_file_hash": annotation_file_hash,
            }
        ),
        artifact_hash=hash_obj(artifact),
        reproduce="uv run redline verify-sponsor-run sponsor-readback.json --receipt <receipt> --package <package> --json",
        meta={
            "receipt_hash": receipt_hash,
            "package_hash": package_hash,
            "annotation_hash": annotation_hash,
            "annotation_file_hash": annotation_file_hash,
            "proof_eligible": str(result.evidence.get("proof_eligible", "")).lower(),
            "state": result.state.value,
        },
    )
    proofs_dir = out_dir / "proofs"
    ensure_safe_output_dir(proofs_dir)
    atomic_write_text(proofs_dir / f"{proof.proof_id.replace(':', '_')}.json", proof.model_dump_json(indent=2) + "\n")
