from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redline.attestation import RELEASE_ATTESTATION_NAME, verify_release_attestation
from redline.canonical import CanonicalizationError
from redline.models import ReasonCode
from redline.service.release import BUNDLE_NAME, resolve_release_run_dir, verify_release_evidence_bundle
from redline.sponsor.bitget_execution import ExecutionBlocked, load_execution_evidence, load_execution_ledger


def verify_release_chain(input_path: Path, *, attestation_path: Path | None = None, trusted_public_key: str | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    try:
        release_dir, bundle_path = _resolve_chain_input(input_path)
        record("input", True, str(bundle_path))
    except (CanonicalizationError, FileNotFoundError, NotADirectoryError, ValueError) as exc:
        record("input", False, _verification_detail(exc))
        return _chain_payload(
            input_path=input_path,
            release_dir=None,
            bundle_path=None,
            attestation_path=attestation_path,
            bundle_result=None,
            attestation_result=None,
            checks=checks,
        )

    bundle_result = verify_release_evidence_bundle(bundle_path)
    checks.extend(bundle_result.get("checks", []))
    resolved_attestation_path = attestation_path or (release_dir / RELEASE_ATTESTATION_NAME)
    if resolved_attestation_path.exists():
        attestation_result = verify_release_attestation(attestation_path=resolved_attestation_path, bundle_path=bundle_path, trusted_public_key=trusted_public_key)
    else:
        attestation_result = {
            "schema_version": "redline.release_attestation.verify.v1",
            "ok": False,
            "attestation_path": str(resolved_attestation_path),
            "bundle_path": str(bundle_path),
            "checks": [{"name": "attestation-json", "ok": False, "detail": "missing"}],
        }
    checks.extend(attestation_result.get("checks", []))
    return _chain_payload(
        input_path=input_path,
        release_dir=release_dir,
        bundle_path=bundle_path,
        attestation_path=resolved_attestation_path,
        bundle_result=bundle_result,
        attestation_result=attestation_result,
        checks=checks,
    )


def verify_execution_evidence_file(evidence_path: Path, *, ledger_path: Path | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    try:
        resolved_evidence_path, resolved_ledger_path = _resolve_execution_evidence_input(evidence_path, ledger_path=ledger_path)
    except (CanonicalizationError, FileNotFoundError, NotADirectoryError, ValueError, json.JSONDecodeError) as exc:
        resolved_evidence_path = evidence_path
        resolved_ledger_path = ledger_path or (evidence_path.parent / "execution-ledger.jsonl")
        checks.append({"name": "execution-evidence", "ok": False, "detail": _verification_detail(exc), "reason_code": _reason_code(exc)})
        return _execution_payload(
            input_path=evidence_path,
            evidence_path=resolved_evidence_path,
            ledger_path=resolved_ledger_path,
            evidence=None,
            checks=checks,
        )
    evidence = None
    ledger_entries = None

    try:
        evidence = load_execution_evidence(resolved_evidence_path)
        checks.append({"name": "execution-evidence", "ok": True, "detail": evidence.artifact_hash, "reason_code": ReasonCode.PASS.value})
    except ExecutionBlocked as exc:
        checks.append({"name": "execution-evidence", "ok": False, "detail": exc.message, "reason_code": exc.reason_code})
    except (CanonicalizationError, OSError, ValueError) as exc:
        checks.append({"name": "execution-evidence", "ok": False, "detail": _verification_detail(exc), "reason_code": _reason_code(exc)})

    if evidence is not None:
        try:
            if not resolved_ledger_path.exists():
                raise ExecutionBlocked("EXECUTION_LEDGER_MISSING", "execution ledger is missing")
            ledger_entries = load_execution_ledger(resolved_ledger_path)
            checks.append({"name": "execution-ledger-chain", "ok": True, "detail": str(len(ledger_entries)), "reason_code": ReasonCode.PASS.value})
        except ExecutionBlocked as exc:
            checks.append({"name": "execution-ledger-chain", "ok": False, "detail": exc.message, "reason_code": exc.reason_code})
        except (CanonicalizationError, OSError, ValueError) as exc:
            checks.append({"name": "execution-ledger-chain", "ok": False, "detail": _verification_detail(exc), "reason_code": _reason_code(exc)})

    if evidence is not None and ledger_entries is not None:
        try:
            entry = next((candidate for candidate in ledger_entries if candidate.entry_hash == evidence.execution_ledger_entry_hash), None)
            if entry is None:
                raise ExecutionBlocked("EXECUTION_LEDGER_ENTRY_MISSING", "execution ledger entry for evidence is missing")
            mismatched = _execution_entry_mismatches(evidence, entry)
            if mismatched:
                raise ExecutionBlocked("EXECUTION_LEDGER_LINK_MISMATCH", "execution ledger entry does not match evidence: " + ",".join(mismatched))
            checks.append({"name": "execution-ledger-entry-link", "ok": True, "detail": entry.entry_hash, "reason_code": ReasonCode.PASS.value})
        except ExecutionBlocked as exc:
            checks.append({"name": "execution-ledger-entry-link", "ok": False, "detail": exc.message, "reason_code": exc.reason_code})

    return _execution_payload(
        input_path=evidence_path,
        evidence_path=resolved_evidence_path,
        ledger_path=resolved_ledger_path,
        evidence=evidence,
        checks=checks,
    )


def _resolve_execution_evidence_input(input_path: Path, *, ledger_path: Path | None) -> tuple[Path, Path]:
    if input_path.is_dir() or (input_path.is_file() and input_path.name == BUNDLE_NAME):
        release_dir, bundle_path = _resolve_chain_input(input_path)
        bundle_result = verify_release_evidence_bundle(bundle_path)
        if not bundle_result["ok"]:
            raise CanonicalizationError("release evidence bundle is not valid", ReasonCode.RECEIPT_MISMATCH)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        execution = bundle.get("execution_evidence") if isinstance(bundle, dict) else None
        run_id = execution.get("run_id") if isinstance(execution, dict) else None
        if not run_id:
            raise CanonicalizationError("release bundle is missing execution evidence run_id", ReasonCode.DATA_MISSING)
        run_dir = resolve_release_run_dir(release_dir, run_id)
        return run_dir / "execution-evidence.json", ledger_path or (run_dir / "execution-ledger.jsonl")
    return input_path, ledger_path or (input_path.parent / "execution-ledger.jsonl")


def _execution_payload(
    *,
    input_path: Path,
    evidence_path: Path,
    ledger_path: Path,
    evidence: Any | None,
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    ok = all(bool(item.get("ok")) for item in checks)
    return {
        "schema_version": "redline.execution_evidence.verify.v1",
        "ok": ok,
        "reason_code": ReasonCode.PASS.value if ok else _first_failed_reason(checks),
        "input_path": str(input_path),
        "evidence_path": str(evidence_path),
        "ledger_path": str(ledger_path),
        "artifact_hash": evidence.artifact_hash if evidence is not None else None,
        "execution_ledger_entry_hash": evidence.execution_ledger_entry_hash if evidence is not None else None,
        "checks": checks,
    }


def _execution_entry_mismatches(evidence: Any, entry: Any) -> list[str]:
    fields = [
        "run_id",
        "receipt_hash",
        "issuance_ledger_entry_hash",
        "issuance_checkpoint_hash",
        "approval_hash",
        "verdict",
        "client_oid",
        "bitget_order_id",
        "response_hash",
        "placed_at",
    ]
    return [field for field in fields if getattr(evidence, field) != getattr(entry, field)]


def _resolve_chain_input(input_path: Path) -> tuple[Path, Path]:
    if input_path.is_dir():
        if input_path.is_symlink():
            raise CanonicalizationError("release directory must not be a symlink", ReasonCode.RECEIPT_BINDING_FAILED)
        bundle_path = input_path / BUNDLE_NAME
        if not bundle_path.exists():
            raise FileNotFoundError(bundle_path)
        return input_path, bundle_path
    if input_path.is_file():
        if input_path.name != BUNDLE_NAME:
            raise ValueError(f"release bundle file must be named {BUNDLE_NAME}")
        return input_path.parent, input_path
    raise FileNotFoundError(input_path)


def _chain_payload(
    *,
    input_path: Path,
    release_dir: Path | None,
    bundle_path: Path | None,
    attestation_path: Path | None,
    bundle_result: dict[str, Any] | None,
    attestation_result: dict[str, Any] | None,
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    ok = all(bool(item.get("ok")) for item in checks) and bundle_result is not None and attestation_result is not None
    ok = bool(ok and (bundle_result or {}).get("ok") and (attestation_result or {}).get("ok"))
    return {
        "schema_version": "redline.chain.verify.v1",
        "ok": ok,
        "reason_code": ReasonCode.PASS.value if ok else ReasonCode.RECEIPT_MISMATCH.value,
        "input_path": str(input_path),
        "release_dir": str(release_dir) if release_dir is not None else None,
        "bundle_path": str(bundle_path) if bundle_path is not None else None,
        "attestation_path": str(attestation_path) if attestation_path is not None else None,
        "bundle": bundle_result,
        "attestation": attestation_result,
        "checks": checks,
    }


def _verification_detail(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if reason is not None:
        return f"{getattr(reason, 'value', str(reason))}: {exc}"
    return str(exc) or type(exc).__name__


def _reason_code(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if reason is None:
        return ReasonCode.RECEIPT_MISMATCH.value
    return getattr(reason, "value", str(reason))


def _first_failed_reason(checks: list[dict[str, Any]]) -> str:
    for check in checks:
        if not check.get("ok"):
            return str(check.get("reason_code") or ReasonCode.RECEIPT_MISMATCH.value)
    return ReasonCode.PASS.value
