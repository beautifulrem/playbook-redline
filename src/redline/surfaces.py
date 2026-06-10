from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from redline.canonical import hash_file, hash_obj, hash_tree
from redline.models import (
    EditProvenance,
    PackageImportResult,
    ProbeSpec,
    ProbeType,
    PublishPreflightResult,
    ReasonCode,
    RedlineSpec,
    VerificationLevel,
    VerificationStatus,
)
from redline.verifier import verify


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
) -> PublishPreflightResult:
    result = verify(
        receipt_path=receipt_path,
        package=package,
        suite_path=suite_path,
        spec_path=spec_path,
        level=VerificationLevel.REPLAYED,
    )
    package_hash = hash_tree(package)
    if result.status != VerificationStatus.VERIFIED or result.reason_code not in {ReasonCode.PASS, ReasonCode.BASELINE_GENESIS}:
        return PublishPreflightResult(
            ok=False,
            state="LOCAL_PASS_REQUIRED",
            receipt_hash=result.receipt_hash,
            package_hash=package_hash,
            reason_code=result.reason_code,
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    annotation = {
        "version": "redline.package.annotation.v1",
        "receipt_path": str(receipt_path),
        "receipt_hash": result.receipt_hash,
        "package_hash": package_hash,
        "strength_summary": result.strength_summary,
        "chain_status": result.chain_status.value,
        "verification_level": result.verification_level.value,
    }
    annotation_hash = hash_obj(annotation)
    annotation_path = out_dir / "redline-annotation.json"
    annotation_path.write_text(json.dumps({**annotation, "annotation_hash": annotation_hash}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return PublishPreflightResult(
        ok=True,
        state="ANNOTATED_PACKAGE_READY",
        receipt_hash=result.receipt_hash,
        package_hash=package_hash,
        annotation_hash=annotation_hash,
    )


def render_report_html(report_path: Path, out_path: Path) -> None:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    title = "Playbook Redline Report"
    status = payload.get("envelope", {}).get("status", "unknown")
    reason = payload.get("envelope", {}).get("reason_code", "unknown")
    summary = payload.get("strength_summary", "")
    body = json.dumps(payload, indent=2, sort_keys=True)
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
  <p class="stamp">{html.escape(str(status)).upper()} / {html.escape(str(reason))}</p>
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
