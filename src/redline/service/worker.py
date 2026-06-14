from __future__ import annotations

from pathlib import Path

from redline.canonical import CanonicalizationError, hash_tree
from redline.models import ReasonCode, Status
from redline.runner import run_redline
from redline.service.artifacts import build_artifact_manifest
from redline.service.models import RunCreateRequest, RunState
from redline.service.storage import RunMetadataStore


def execute_run(
    *,
    store: RunMetadataStore,
    run_id: str,
    request: RunCreateRequest,
    package_path: Path,
    out_dir: Path,
    expose_error_details: bool = True,
) -> None:
    store.mark_running(run_id)
    try:
        artifacts = run_redline(
            package_dir=package_path,
            baseline=request.baseline,
            candidate=request.candidate,
            suite_path=Path(request.suite_path),
            spec_path=Path(request.spec_path),
            out_dir=out_dir,
            baseline_receipt_path=Path(request.baseline_receipt_path) if request.baseline_receipt_path else None,
            baseline_trust_policy_path=Path(request.baseline_trust_policy_path) if request.baseline_trust_policy_path else None,
            baseline_version_id=request.baseline_version_id,
            candidate_version_id=request.candidate_version_id,
        )
        manifest = build_artifact_manifest(run_id, out_dir)
        envelope = artifacts.envelope
        receipt_hash = artifacts.receipt.receipt_hash if artifacts.receipt is not None else None
        report_hash = artifacts.report_json.get("report_hash")
        store.mark_completed(
            run_id=run_id,
            state=_map_run_state(envelope.status, envelope.reason_code),
            reason_code=envelope.reason_code.value,
            envelope_status=envelope.status.value,
            package_hash=hash_tree(package_path),
            receipt_hash=receipt_hash,
            report_hash=str(report_hash) if report_hash is not None else None,
            artifact_manifest=manifest,
        )
    except CanonicalizationError as exc:
        store.mark_error(run_id=run_id, error_code=exc.reason_code.value, message=str(exc))
    except FileNotFoundError as exc:
        store.mark_error(run_id=run_id, error_code=ReasonCode.FILE_NOT_FOUND.value, message=_error_message(exc, expose_error_details=expose_error_details))
    except Exception as exc:
        store.mark_error(run_id=run_id, error_code=ReasonCode.DATA_MISSING.value, message=_error_message(exc, expose_error_details=expose_error_details))


def _map_run_state(status: Status, reason_code: ReasonCode) -> RunState:
    if status == Status.PASS and reason_code == ReasonCode.PASS:
        return RunState.PASS
    if status == Status.PASS and reason_code == ReasonCode.BASELINE_GENESIS:
        return RunState.AMBER
    if status == Status.WITHHELD:
        return RunState.FAIL
    return RunState.ERROR


def _error_message(exc: Exception, *, expose_error_details: bool) -> str:
    if expose_error_details:
        return str(exc)
    return "run failed; inspect server logs with the request_id and run_id"
