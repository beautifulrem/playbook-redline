from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from functools import lru_cache
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


@lru_cache(maxsize=1)
def _inline_css() -> str:
    """The shared design system, inlined so evidence pages stay self-contained and offline.
    Comments are stripped (smaller payload + keeps words like 'secret' out of the evidence HTML)."""
    css = (Path(__file__).resolve().parent / "static" / "redline.css").read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S).strip()


def _render_document(*, title: str, panels: list[EvidencePanel], comparison: bool) -> str:
    rendered = "\n".join(_render_panel(panel, with_title=comparison) for panel in panels)
    inner = f'    <div class="rl-cols-2">\n{rendered}\n    </div>' if comparison else rendered
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(title)}</title>
  <style>{_inline_css()}</style>
</head>
<body>
  <main class="rl-main">
    <h1 class="rl-macro">{_esc(title)}</h1>
{inner}
    <hr>
    <p class="rl-muted">{_esc(HONEST_STATEMENT)}</p>
  </main>
</body>
</html>
"""


def _render_panel(panel: EvidencePanel, *, with_title: bool = False) -> str:
    band_mod = "rl-band--pass" if (panel.evidence is not None and panel.invalid_reason_code is None) else ""
    title_html = f'        <p class="rl-label">{_esc(panel.title)}</p>\n' if with_title else ""
    return f"""      <section>
{title_html}        <div class="rl-band {band_mod}">
          <span class="rl-band__verdict">{_esc(panel.verdict)}</span>
          <span class="rl-band__meta">{_esc(_band_meta(panel))}</span>
        </div>
{_render_seal(panel)}
{_render_redline(panel)}
{_render_execution(panel)}
{_render_block(panel)}
      </section>"""


def _render_redline(panel: EvidencePanel) -> str:
    return f"""        <p class="rl-sec">redline 侧</p>
        <div class="rl-box"><dl class="rl-dl">
          <dt>verdict</dt><dd>{_esc(panel.verdict)}</dd>
          <dt>reason_code</dt><dd>{_esc(panel.reason_code)}</dd>
          <dt>chain_status</dt><dd>{_esc(panel.chain_status)}</dd>
          <dt>receipt_hash</dt><dd class="rl-mono">{_esc(panel.receipt_hash or "missing")}</dd>
          <dt>strength_summary</dt><dd>{_render_summary(panel.strength_summary)}</dd>
        </dl></div>"""


def _render_execution(panel: EvidencePanel) -> str:
    if panel.evidence is None or panel.invalid_reason_code is not None:
        return ""
    evidence = panel.evidence
    return f"""        <p class="rl-sec">执行侧</p>
        <div class="rl-box"><dl class="rl-dl">
          <dt>bitget_order_id</dt><dd class="rl-mono">{_esc(evidence.bitget_order_id)}</dd>
          <dt>client_oid</dt><dd class="rl-mono">{_esc(evidence.client_oid)}</dd>
          <dt>placed_at</dt><dd>{_esc(evidence.placed_at)}</dd>
          <dt>symbol</dt><dd>{_esc(evidence.symbol)}</dd>
          <dt>product_type</dt><dd>{_esc(evidence.product_type)}</dd>
          <dt>order_mode</dt><dd>{_esc(evidence.order_mode)}</dd>
          <dt>paptrading</dt><dd>{_esc(evidence.paptrading or "0")}</dd>
          <dt>receipt_hash</dt><dd class="rl-mono">{_esc(evidence.receipt_hash)}</dd>
          <dt>response_hash</dt><dd class="rl-mono">{_esc(evidence.response_hash)}</dd>
        </dl></div>"""


def _render_block(panel: EvidencePanel) -> str:
    if panel.evidence is not None and panel.invalid_reason_code is None:
        return ""
    if panel.invalid_reason_code:
        return f"""        <div class="rl-stripe"><span class="rl-stripe__msg">⚠ EVIDENCE INVALID · {_esc(_invalid_message(panel.invalid_reason_code))}</span></div>"""
    reason = panel.block_reason_code or panel.reason_code
    return f"""        <p class="rl-sec">拦截侧</p>
        <div class="rl-box"><dl class="rl-dl">
          <dt>block reason_code</dt><dd class="rl-mono">{_esc(reason)}</dd>
          <dt>exchange call</dt><dd>Bitget 未被调用</dd>
        </dl></div>"""


def _render_summary(summary: str | None) -> str:
    """Render the strength summary as scannable one-invariant-per-line rows (split on ';')."""
    if not summary:
        return _esc("not provided")
    parts = [part.strip() for part in summary.split(";") if part.strip()]
    return "<br>".join(_esc(part) for part in parts) if parts else _esc(summary)


def randomart_svg(seed: str, cell: int = 9) -> str:
    """SSH 'Drunken Bishop' randomart (OpenSSH VisualHostKey) as inline SVG — a named
    cryptographic fingerprint so near-identical hashes look obviously different to a human.
    Deterministic, fill=currentColor, no external refs (safe for the offline evidence page)."""
    hx = "".join(c for c in seed if c in "0123456789abcdefABCDEF")
    if len(hx) % 2:
        hx = hx[:-1]
    data = bytes.fromhex(hx) if hx else hashlib.sha256(seed.encode("utf-8")).digest()
    cols, rows = 17, 9
    grid = [[0] * cols for _ in range(rows)]
    x, y = cols // 2, rows // 2
    for byte in data:
        b = byte
        for _ in range(4):
            x = min(cols - 1, max(0, x + (1 if b & 1 else -1)))
            y = min(rows - 1, max(0, y + (1 if b & 2 else -1)))
            grid[y][x] += 1
            b >>= 2
    peak = max((max(row) for row in grid), default=1) or 1
    fills = "".join(
        f'<rect x="{i*cell}" y="{j*cell}" width="{cell}" height="{cell}" fill-opacity="{0.16 + 0.84 * (grid[j][i] / peak):.2f}"/>'
        for j in range(rows)
        for i in range(cols)
        if grid[j][i]
    )
    sx, sy = cols // 2, rows // 2
    marks = (
        f'<rect x="{sx*cell}" y="{sy*cell}" width="{cell}" height="{cell}" fill="none" stroke="currentColor" stroke-opacity=".85"/>'
        f'<rect x="{x*cell}" y="{y*cell}" width="{cell}" height="{cell}" fill="none" stroke="currentColor" stroke-opacity=".85"/>'
    )
    return (
        f'<svg viewBox="0 0 {cols*cell} {rows*cell}" fill="currentColor" role="img" aria-label="randomart hash fingerprint of the receipt">'
        + fills + marks + "</svg>"
    )


def _render_seal(panel: EvidencePanel) -> str:
    seed = panel.receipt_hash or (panel.evidence.response_hash if panel.evidence else None)
    if not seed:
        return ""
    passed = panel.evidence is not None and panel.invalid_reason_code is None
    mod = "rl-seal--pass" if passed else "rl-seal--void"
    stamp = "VERIFIED" if passed else "VOID"
    short = seed if len(seed) <= 26 else seed[:26] + "…"
    return (
        f'        <div class="rl-seal {mod}"><span class="rl-seal__art">{randomart_svg(seed)}</span>'
        f'<span class="rl-seal__body"><span class="rl-seal__stamp">{_esc(stamp)}</span>'
        f'<span class="rl-seal__algo">SSH randomart · receipt fingerprint</span>'
        f'<span class="rl-seal__hash">{_esc(short)}</span></span></div>'
    )


def _band_meta(panel: EvidencePanel) -> str:
    suffix = "DEMO · paptrading:1 · 非 MAINNET"
    if panel.invalid_reason_code:
        return f"INTEGRITY FAIL · {suffix}"
    if panel.evidence is not None and panel.verdict == "PASS":
        return f"REPLAYED · CHAINED · SIGNED · {suffix}"
    if panel.verdict == "WITHHELD":
        return f"BLOCKED · BITGET 未被调用 · {suffix}"
    return f"BLOCKED · {suffix}"


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
