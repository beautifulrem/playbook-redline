from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from redline.canonical import CanonicalizationError
from redline.io_safety import atomic_write_text, reject_unsafe_output_file
from redline.models import ExecutionEvidence, ReportJson
from redline.receipt import compute_receipt_hash
from redline.service.release import AUDIT_LEDGER_NAME, BUNDLE_NAME, load_release_audit_ledger, resolve_release_run_dir, verify_release_evidence_bundle
from redline.sponsor.bitget_execution import ExecutionBlocked, load_execution_evidence, load_execution_ledger
from redline.verifier import load_receipt


HONEST_STATEMENT = "Redline verdict 授权了这笔 Bitget 模拟盘订单；这不是 Bitget Playbook 正式发布"


@dataclass(frozen=True)
class EvidencePanel:
    title: str
    verdict: str
    reason_code: str
    chain_status: str
    strength_summary: str
    receipt_hash: str | None = None
    evidence: ExecutionEvidence | None = None
    block_reason_code: str | None = None
    invalid_reason_code: str | None = None


def render_execution_evidence_html(
    *,
    evidence: ExecutionEvidence | None,
    verdict: str,
    reason_code: str,
    chain_status: str,
    strength_summary: str,
    receipt_hash: str | None = None,
    block_reason_code: str | None = None,
    invalid_reason_code: str | None = None,
    title: str = "Redline Execution Evidence",
) -> str:
    return _render_document(
        title=title,
        panels=[
            EvidencePanel(
                title=title,
                verdict=verdict,
                reason_code=reason_code,
                chain_status=chain_status,
                strength_summary=strength_summary,
                receipt_hash=receipt_hash,
                evidence=evidence,
                block_reason_code=block_reason_code,
                invalid_reason_code=invalid_reason_code,
            )
        ],
        comparison=False,
    )


def render_evidence_comparison_html(good: EvidencePanel, bad: EvidencePanel) -> str:
    return _render_document(title="Redline Evidence Comparison", panels=[good, bad], comparison=True)


def render_evidence_panel_html(panel: EvidencePanel) -> str:
    return _render_document(title=panel.title, panels=[panel], comparison=False)


def write_evidence_html(out_path: Path, html_doc: str) -> None:
    atomic_write_text(out_path, html_doc)


def render_path_html(path: Path) -> str:
    panel = load_evidence_panel(path)
    return render_evidence_panel_html(panel)


def load_evidence_panel(path: Path, *, title: str | None = None) -> EvidencePanel:
    source = path.resolve()
    if (source / "receipt.json").exists() or (source / "report.json").exists():
        return load_run_evidence_panel(source, title=title)
    if (source / BUNDLE_NAME).exists() or (source / AUDIT_LEDGER_NAME).exists():
        return load_release_evidence_panel(source, title=title)
    return _invalid_panel(title or source.name, "EVIDENCE_MISSING")


def load_run_evidence_panel(run_dir: Path, *, title: str | None = None) -> EvidencePanel:
    try:
        receipt = _load_verified_receipt(run_dir / "receipt.json")
        reason_code, chain_status, strength_summary = _load_report_context(run_dir / "report.json", receipt=receipt)
    except (CanonicalizationError, OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        return _invalid_panel(title or run_dir.name, _reason_from_exception(exc))

    display_verdict = "PASS" if receipt.result.status == "pass" else "WITHHELD"
    if receipt.result.status != "pass":
        return EvidencePanel(
            title=title or f"Run {run_dir.name}",
            verdict=display_verdict,
            reason_code=reason_code,
            chain_status=chain_status,
            strength_summary=strength_summary,
            receipt_hash=receipt.receipt_hash,
            block_reason_code=reason_code,
        )

    evidence_path = run_dir / "execution-evidence.json"
    if not evidence_path.exists():
        return EvidencePanel(
            title=title or f"Run {run_dir.name}",
            verdict="UNVERIFIED",
            reason_code=reason_code,
            chain_status=chain_status,
            strength_summary=strength_summary,
            receipt_hash=receipt.receipt_hash,
            block_reason_code="EXECUTION_EVIDENCE_MISSING",
        )
    try:
        evidence = _load_verified_execution_evidence(run_dir, receipt_hash=receipt.receipt_hash)
    except ExecutionBlocked as exc:
        return EvidencePanel(
            title=title or f"Run {run_dir.name}",
            verdict="INVALID",
            reason_code=reason_code,
            chain_status=chain_status,
            strength_summary=strength_summary,
            receipt_hash=receipt.receipt_hash,
            invalid_reason_code=exc.reason_code,
        )
    return EvidencePanel(
        title=title or f"Run {run_dir.name}",
        verdict="PASS",
        reason_code=reason_code,
        chain_status=chain_status,
        strength_summary=strength_summary,
        receipt_hash=receipt.receipt_hash,
        evidence=evidence,
    )


def load_release_evidence_panel(release_dir: Path, *, title: str | None = None, run_dir: Path | None = None) -> EvidencePanel:
    try:
        load_release_audit_ledger(release_dir / AUDIT_LEDGER_NAME)
        if (release_dir / BUNDLE_NAME).exists():
            verification = verify_release_evidence_bundle(release_dir / BUNDLE_NAME)
            if not verification["ok"]:
                return _invalid_panel(title or release_dir.name, "RELEASE_BUNDLE_MISMATCH")
            bundle = _load_json(release_dir / BUNDLE_NAME)
            execution = bundle.get("execution_evidence") if isinstance(bundle, dict) else None
            run_id = str(execution.get("run_id") if isinstance(execution, dict) else "")
            inferred_run_dir = run_dir or _infer_run_dir(release_dir, run_id)
            if inferred_run_dir is not None:
                return load_run_evidence_panel(inferred_run_dir, title=title or f"Release {release_dir.name}")
        return _blocked_release_panel(release_dir, title=title)
    except (CanonicalizationError, OSError, json.JSONDecodeError, ValidationError) as exc:
        return _invalid_panel(title or release_dir.name, _reason_from_exception(exc))


def _load_verified_receipt(receipt_path: Path):
    reject_unsafe_output_file(receipt_path)
    receipt = load_receipt(receipt_path)
    if compute_receipt_hash(receipt) != receipt.receipt_hash:
        raise CanonicalizationError("receipt hash mismatch")
    return receipt


def _load_report_context(report_path: Path, *, receipt) -> tuple[str, str, str]:
    reason_code = receipt.decision.reason_code.value
    chain_status = receipt.baseline.chain_status.value
    strength_summary = receipt.strength_summary
    if not report_path.exists():
        return reason_code, chain_status, strength_summary
    reject_unsafe_output_file(report_path)
    report = ReportJson.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.report_hash != receipt.report.report_hash:
        raise CanonicalizationError("report hash mismatch")
    if report.receipt_hash is not None and report.receipt_hash != receipt.receipt_hash:
        raise CanonicalizationError("report receipt mismatch")
    return report.envelope.reason_code.value, report.envelope.chain_status.value, report.strength_summary or strength_summary


def _load_verified_execution_evidence(run_dir: Path, *, receipt_hash: str) -> ExecutionEvidence:
    evidence = load_execution_evidence(run_dir / "execution-evidence.json")
    ledger_entries = load_execution_ledger(run_dir / "execution-ledger.jsonl")
    match = next((entry for entry in ledger_entries if entry.entry_hash == evidence.execution_ledger_entry_hash), None)
    if match is None:
        raise ExecutionBlocked("EXECUTION_LEDGER_MISMATCH", "execution ledger entry not found")
    if (
        evidence.receipt_hash != receipt_hash
        or evidence.verdict.value != "pass"
        or evidence.order_mode != "demo"
        or evidence.paptrading != "1"
        or match.receipt_hash != evidence.receipt_hash
        or match.client_oid != evidence.client_oid
        or match.bitget_order_id != evidence.bitget_order_id
        or match.response_hash != evidence.response_hash
    ):
        raise ExecutionBlocked("EXECUTION_EVIDENCE_MISMATCH", "execution evidence does not match receipt or ledger")
    return evidence


def _blocked_release_panel(release_dir: Path, *, title: str | None) -> EvidencePanel:
    entries = load_release_audit_ledger(release_dir / AUDIT_LEDGER_NAME)
    reason_code = "RELEASE_BLOCKED"
    for entry in reversed(entries):
        payload = entry.get("payload") if isinstance(entry, dict) else None
        if isinstance(payload, dict):
            reason = payload.get("reason_code") or payload.get("run_state")
            if reason:
                reason_code = str(reason)
                break
    return EvidencePanel(
        title=title or f"Release {release_dir.name}",
        verdict="WITHHELD",
        reason_code=reason_code,
        chain_status="blocked",
        strength_summary="release audit ledger verified; no Bitget demo execution evidence is present",
        block_reason_code=reason_code,
    )


def _infer_run_dir(release_dir: Path, run_id: str) -> Path | None:
    if not run_id:
        return None
    candidate = resolve_release_run_dir(release_dir, run_id)
    return candidate if candidate.exists() else None


def _render_document(*, title: str, panels: list[EvidencePanel], comparison: bool) -> str:
    grid_class = " comparison" if comparison else ""
    rendered = "\n".join(_render_panel(panel) for panel in panels)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{_esc(title)}</title>
  <style>
    :root {{ --paper: #f6f7f9; --ink: #15171a; --muted: #5f6875; --line: #c9d1dc; --pass: #147a4d; --blocked: #9a5b00; --bad: #b3261e; --blue: #1f5f99; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--paper); color: var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1 {{ font-size: 28px; line-height: 1.2; margin: 0 0 18px; letter-spacing: 0; }}
    h2 {{ font-size: 18px; line-height: 1.25; margin: 16px 0 10px; letter-spacing: 0; }}
    .grid {{ display: grid; grid-template-columns: 1fr; gap: 18px; }}
    .grid.comparison {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .panel {{ background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 18px; min-width: 0; }}
    .panel.pass {{ border-top: 6px solid var(--pass); }}
    .panel.blocked {{ border-top: 6px solid var(--blocked); }}
    .panel.invalid {{ border-top: 6px solid var(--bad); }}
    .stamp {{ display: inline-block; border: 2px solid currentColor; padding: 6px 9px; transform: rotate(-2deg); font-weight: 800; font-size: 13px; line-height: 1.25; color: var(--blue); }}
    .pass .stamp {{ color: var(--pass); }}
    .blocked .stamp {{ color: var(--blocked); }}
    .invalid .stamp {{ color: var(--bad); }}
    dl {{ display: grid; grid-template-columns: minmax(148px, 220px) minmax(0, 1fr); gap: 8px 14px; margin: 10px 0 18px; }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    .callout {{ margin: 12px 0; padding: 10px 12px; border: 1px solid var(--line); border-left: 5px solid var(--blocked); background: #fffaf0; }}
    .invalid .callout {{ border-left-color: var(--bad); background: #fff5f3; }}
    .note {{ border-top: 1px solid var(--line); margin-top: 18px; padding-top: 12px; color: var(--muted); font-size: 13px; line-height: 1.45; }}
    @media (max-width: 860px) {{ main {{ padding: 18px; }} .grid.comparison {{ grid-template-columns: 1fr; }} dl {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <h1>{_esc(title)}</h1>
    <div class="grid{grid_class}">
{rendered}
    </div>
    <p class="note">{_esc(HONEST_STATEMENT)}</p>
  </main>
</body>
</html>
"""


def _render_panel(panel: EvidencePanel) -> str:
    state_class = "invalid" if panel.invalid_reason_code else "pass" if panel.evidence else "blocked"
    return f"""      <section class="panel {state_class}">
        <p class="stamp">{_esc(_stamp(panel))}</p>
        <h2>{_esc(panel.title)}</h2>
        {_render_redline(panel)}
        {_render_execution(panel)}
        {_render_block(panel)}
      </section>"""


def _render_redline(panel: EvidencePanel) -> str:
    return f"""<h2>Redline 侧</h2>
        <dl>
          <dt>verdict</dt><dd>{_esc(panel.verdict)}</dd>
          <dt>reason_code</dt><dd>{_esc(panel.reason_code)}</dd>
          <dt>chain_status</dt><dd>{_esc(panel.chain_status)}</dd>
          <dt>receipt_hash</dt><dd>{_esc(panel.receipt_hash or "missing")}</dd>
          <dt>strength_summary</dt><dd>{_esc(panel.strength_summary or "not provided")}</dd>
        </dl>"""


def _render_execution(panel: EvidencePanel) -> str:
    if panel.evidence is None or panel.invalid_reason_code is not None:
        return ""
    evidence = panel.evidence
    return f"""<h2>执行侧</h2>
        <dl>
          <dt>bitget_order_id</dt><dd>{_esc(evidence.bitget_order_id)}</dd>
          <dt>client_oid</dt><dd>{_esc(evidence.client_oid)}</dd>
          <dt>placed_at</dt><dd>{_esc(evidence.placed_at)}</dd>
          <dt>symbol</dt><dd>{_esc(evidence.symbol)}</dd>
          <dt>product_type</dt><dd>{_esc(evidence.product_type)}</dd>
          <dt>order_mode</dt><dd>{_esc(evidence.order_mode)}</dd>
          <dt>paptrading</dt><dd>{_esc(evidence.paptrading or "0")}</dd>
          <dt>receipt_hash</dt><dd>{_esc(evidence.receipt_hash)}</dd>
          <dt>response_hash</dt><dd>{_esc(evidence.response_hash)}</dd>
        </dl>"""


def _render_block(panel: EvidencePanel) -> str:
    if panel.evidence is not None and panel.invalid_reason_code is None:
        return ""
    if panel.invalid_reason_code:
        return f"""<div class="callout"><strong>EVIDENCE INVALID</strong><br>{_esc(_invalid_message(panel.invalid_reason_code))}</div>"""
    reason = panel.block_reason_code or panel.reason_code
    return f"""<h2>拦截侧</h2>
        <dl>
          <dt>block reason_code</dt><dd>{_esc(reason)}</dd>
          <dt>exchange call</dt><dd>Bitget 未被调用</dd>
        </dl>"""


def _stamp(panel: EvidencePanel) -> str:
    suffix = "DEMO · paptrading:1 · 非 mainnet"
    if panel.invalid_reason_code:
        return f"EVIDENCE INVALID · {_invalid_message(panel.invalid_reason_code)} · {suffix}"
    if panel.evidence is not None and panel.verdict == "PASS":
        return f"PASS · REPLAYED + chained + signed · {suffix}"
    if panel.verdict == "WITHHELD":
        return f"WITHHELD · BLOCKED · {suffix}"
    return f"UNVERIFIED · BLOCKED · {suffix}"


def _invalid_panel(title: str, reason_code: str) -> EvidencePanel:
    return EvidencePanel(
        title=title,
        verdict="INVALID",
        reason_code=reason_code,
        chain_status="unverified",
        strength_summary="evidence failed integrity validation",
        invalid_reason_code=reason_code,
    )


def _invalid_message(reason_code: str) -> str:
    if "MISMATCH" in reason_code:
        return "hash mismatch"
    if "MISSING" in reason_code:
        return "required evidence missing"
    return "integrity check failed"


def _reason_from_exception(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if reason is not None:
        return getattr(reason, "value", str(reason))
    if isinstance(exc, json.JSONDecodeError):
        return "EVIDENCE_PARSE_ERROR"
    return "EVIDENCE_INVALID"


def _load_json(path: Path) -> Any:
    reject_unsafe_output_file(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)
