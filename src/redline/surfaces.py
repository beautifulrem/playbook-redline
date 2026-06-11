from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import hash_file, hash_obj, hash_tree
from redline.models import (
    ChainStatus,
    EditProvenance,
    LedgerCheckpoint,
    PackageAnnotation,
    PackageImportResult,
    ProbeSpec,
    ProbeType,
    PublishPreflightResult,
    ReasonCode,
    RedlineSpec,
    ReportJson,
    VerificationLevel,
    VerificationStatus,
)
from redline.verifier import load_receipt, verify


def import_package(path: Path) -> PackageImportResult:
    root = path.resolve()
    files = [
        file_path.relative_to(root).as_posix()
        for file_path in sorted(p for p in root.rglob("*") if p.is_file())
        if "__pycache__" not in file_path.parts and not file_path.name.endswith((".pyc", ".pyo"))
    ]
    return PackageImportResult(path=str(root), identity_hash=hash_tree(root), files=files)


def compile_spec(source_path: Path) -> RedlineSpec:
    text = source_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return _compile_text_spec(text, source_path=source_path)
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


def publish_preflight(
    *,
    receipt_path: Path,
    package: Path,
    suite_path: Path,
    spec_path: Path,
    out_dir: Path,
    report_path: Path | None = None,
    ledger_checkpoint_path: Path | None = None,
    trusted_ledger_checkpoint_hash: str | None = None,
    allow_demo_baseline_genesis: bool = False,
) -> PublishPreflightResult:
    report_path = report_path or receipt_path.parent / "report.json"
    ledger_checkpoint_path = ledger_checkpoint_path or receipt_path.parent / "issuance-ledger.checkpoint.json"
    result = verify(
        receipt_path=receipt_path,
        package=package,
        suite_path=suite_path,
        spec_path=spec_path,
        report_path=report_path,
        ledger_checkpoint_path=ledger_checkpoint_path,
        trusted_ledger_checkpoint_hash=trusted_ledger_checkpoint_hash,
        level=VerificationLevel.REPLAYED,
    )
    package_hash = hash_tree(package)
    if result.status != VerificationStatus.VERIFIED:
        if result.reason_code == ReasonCode.BASELINE_GENESIS and allow_demo_baseline_genesis:
            pass
        elif result.reason_code == ReasonCode.BASELINE_GENESIS:
            return PublishPreflightResult(
                ok=False,
                state="CHAINED_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            )
        elif result.reason_code == ReasonCode.BASELINE_UNCHAINED:
            return PublishPreflightResult(
                ok=False,
                state="TRUSTED_LEDGER_CHECKPOINT_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            )
        else:
            return PublishPreflightResult(
                ok=False,
                state="LOCAL_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            )
    if result.status == VerificationStatus.VERIFIED and result.reason_code not in {ReasonCode.PASS, ReasonCode.BASELINE_GENESIS}:
        return PublishPreflightResult(
            ok=False,
            state="LOCAL_PASS_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=result.reason_code,
        )
    if result.reason_code == ReasonCode.BASELINE_GENESIS or result.chain_status != ChainStatus.CHAINED:
        if not allow_demo_baseline_genesis:
            return PublishPreflightResult(
                ok=False,
                state="CHAINED_PASS_REQUIRED",
                receipt_hash=result.receipt_hash,
                package_hash=package_hash,
                reason_code=result.reason_code,
            )
    checkpoint = _load_checkpoint(ledger_checkpoint_path)
    if checkpoint is None:
        return PublishPreflightResult(
            ok=False,
            state="LEDGER_CHECKPOINT_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=ReasonCode.RECEIPT_MISMATCH,
        )
    if result.chain_status == ChainStatus.CHAINED and trusted_ledger_checkpoint_hash is None:
        return PublishPreflightResult(
            ok=False,
            state="TRUSTED_LEDGER_CHECKPOINT_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            report_hash=_report_hash(report_path),
            ledger_hash=checkpoint.ledger_hash,
            ledger_checkpoint_hash=checkpoint.checkpoint_hash,
            reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED,
        )
    receipt = load_receipt(receipt_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    annotation = PackageAnnotation(
        annotation_kind="demo-preview" if result.chain_status != ChainStatus.CHAINED else "publish-preflight",
        receipt_path=str(receipt_path),
        receipt_hash=receipt.receipt_hash,
        report_hash=receipt.report.report_hash,
        package_hash=package_hash,
        ledger_hash=checkpoint.ledger_hash,
        ledger_checkpoint_hash=checkpoint.checkpoint_hash,
        strength_summary=result.strength_summary,
        chain_status=result.chain_status,
        verification_level=result.verification_level,
        trusted_ledger_checkpoint_hash=trusted_ledger_checkpoint_hash,
        annotation_hash="",
    )
    annotation_hash = hash_obj(annotation)
    annotation = annotation.model_copy(update={"annotation_hash": annotation_hash})
    annotation_path = out_dir / "redline-annotation.json"
    annotation_path.write_text(annotation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return PublishPreflightResult(
        ok=True,
        state="DEMO_ANNOTATION_READY" if annotation.annotation_kind == "demo-preview" else "ANNOTATED_PACKAGE_READY",
        receipt_hash=result.receipt_hash,
        package_hash=package_hash,
        report_hash=receipt.report.report_hash,
        ledger_hash=checkpoint.ledger_hash,
        ledger_checkpoint_hash=checkpoint.checkpoint_hash,
        annotation_hash=annotation_hash,
        reason_code=result.reason_code,
    )


def verify_annotation(
    *,
    annotation_path: Path,
    receipt_path: Path | None = None,
    package: Path | None = None,
    report_path: Path | None = None,
    ledger_checkpoint_path: Path | None = None,
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
        if annotation.receipt_hash != receipt.receipt_hash or annotation.report_hash != receipt.report.report_hash:
            return PublishPreflightResult(ok=False, state="ANNOTATION_BINDING_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if package is not None and annotation.package_hash != hash_tree(package):
        return PublishPreflightResult(ok=False, state="ANNOTATION_PACKAGE_MISMATCH", reason_code=ReasonCode.RECEIPT_BINDING_FAILED)
    if report_path is not None and annotation.report_hash != _report_hash(report_path):
        return PublishPreflightResult(ok=False, state="ANNOTATION_REPORT_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    if ledger_checkpoint_path is not None:
        checkpoint = _load_checkpoint(ledger_checkpoint_path)
        if checkpoint is None or annotation.ledger_checkpoint_hash != checkpoint.checkpoint_hash or annotation.ledger_hash != checkpoint.ledger_hash:
            return PublishPreflightResult(ok=False, state="ANNOTATION_LEDGER_MISMATCH", reason_code=ReasonCode.RECEIPT_MISMATCH)
    return PublishPreflightResult(
        ok=True,
        state="ANNOTATION_VERIFIED",
        receipt_hash=annotation.receipt_hash,
        package_hash=annotation.package_hash,
        report_hash=annotation.report_hash,
        ledger_hash=annotation.ledger_hash,
        ledger_checkpoint_hash=annotation.ledger_checkpoint_hash,
        annotation_hash=annotation.annotation_hash,
        reason_code=ReasonCode.BASELINE_GENESIS if annotation.annotation_kind == "demo-preview" else ReasonCode.PASS,
    )


def render_report_html(
    report_path: Path,
    out_path: Path,
    *,
    receipt_path: Path | None = None,
    package: Path | None = None,
    suite_path: Path | None = None,
    spec_path: Path | None = None,
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
            level=VerificationLevel.REPLAYED,
        )
        verified = result.status == VerificationStatus.VERIFIED and result.receipt_hash == payload.get("receipt_hash")
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


def _compile_text_spec(text: str, *, source_path: Path) -> RedlineSpec:
    max_drawdown = _decimalish(_find_first(text, r"(?:max(?:imum)?[-_\s]*)?drawdown[^0-9.]*([0-9]+(?:\.[0-9]+)?%?)"), default="0.08")
    max_trades = _decimalish(_find_first(text, r"(?:trade(?:s)?|turnover)[^0-9.]*([0-9]+(?:\.[0-9]+)?)"), default="20")
    before_bar = _find_first(text, r"(?:no[-_\s]*entry|avoid[-_\s]*entry)[^0-9]*(?:bar)?[^0-9]*([0-9]+)") or "3"
    return RedlineSpec(
        spec_id=f"compiled-{source_path.stem}",
        compiler="json-fallback",
        probes=[
            ProbeSpec(id="drawdown_limit", type=ProbeType.MAX_DRAWDOWN, params={"max_drawdown": max_drawdown}),
            ProbeSpec(
                id="no_entry_when_crash",
                type=ProbeType.NO_ENTRY_WHEN,
                params={"scenario_id": "btc-crash-2024-03-05", "before_bar": before_bar, "max_abs_position": "0"},
            ),
            ProbeSpec(id="trade_budget", type=ProbeType.TRADE_BUDGET, params={"max_trades": max_trades}),
        ],
    )


def _find_first(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _decimalish(value: str | None, *, default: str) -> str:
    if value is None:
        return default
    if value.endswith("%"):
        return str(float(value[:-1]) / 100)
    return value


def _load_checkpoint(path: Path) -> LedgerCheckpoint | None:
    try:
        checkpoint = LedgerCheckpoint.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None
    expected_hash = hash_obj(checkpoint.model_copy(update={"checkpoint_hash": ""}))
    return checkpoint if checkpoint.checkpoint_hash == expected_hash else None


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
