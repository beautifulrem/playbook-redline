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


HONEST_STATEMENT_EN = "The Redline verdict authorized this Bitget demo (paptrading) order. This is not an official Bitget Playbook release."
HONEST_STATEMENT_ZH = "Redline 裁决授权了这笔 Bitget 模拟盘（demo）订单；这不是 Bitget Playbook 正式发布。"
HONEST_STATEMENT = HONEST_STATEMENT_EN  # back-compat alias

# Self-contained verify/tamper engine: pure-JS sha256 (no crypto.subtle / secure-context
# dependency, works offline on file://) + a JS port of the Drunken Bishop randomart that
# matches render.randomart_svg, so editing the evidence morphs the seal and flips the verdict.
def t(en: str, zh: str) -> str:
    """Bilingual inline text: both languages are emitted; CSS reveals the active one (.i18n)."""
    return f'<span class="i18n"><span lang="en">{_esc(en)}</span><span lang="zh">{_esc(zh)}</span></span>'


REPO_URL = "https://github.com/beautifulrem/playbook-redline"


def _lang_toggle() -> str:
    return (
        '<div class="rl-topbar">'
        f'<a class="rl-ghbtn" href="{REPO_URL}" target="_blank" rel="noopener">'
        '<span class="i18n"><span lang="en">View on GitHub</span><span lang="zh">GitHub 仓库</span></span> &nearr;</a>'
        '<div class="rl-lang" role="group" aria-label="language / 语言">'
        '<button type="button" class="rl-lang__btn" data-lang-set="en">EN</button>'
        '<button type="button" class="rl-lang__btn" data-lang-set="zh">中</button>'
        "</div></div>"
    )


# one-click EN/中 switch: dual-text spans toggled via <html data-lang>, persisted, broadcast for live re-render
_I18N_SCRIPT = """
<script>
(function () {
  var KEY = "rl-lang", h = document.documentElement;
  function apply(l) {
    if (l === "zh") { h.setAttribute("data-lang", "zh"); h.setAttribute("lang", "zh-Hans"); }
    else { h.removeAttribute("data-lang"); h.setAttribute("lang", "en"); }
    try { window.dispatchEvent(new CustomEvent("rl-lang", { detail: l })); } catch (e) {}
  }
  var s = "en"; try { if (localStorage.getItem(KEY) === "zh") s = "zh"; } catch (e) {}
  apply(s);
  document.addEventListener("click", function (e) {
    var b = e.target && e.target.closest ? e.target.closest("[data-lang-set]") : null;
    if (!b) return;
    var l = b.getAttribute("data-lang-set"); apply(l);
    try { localStorage.setItem(KEY, l); } catch (e) {}
  });
})();
</script>
"""


_VERIFY_SCRIPT = """
<script>
(function () {
  function sha256hex(msg) {
    function R(n, x) { return (x >>> n) | (x << (32 - n)); }
    var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var bytes = [], i;
    for (i = 0; i < msg.length; i++) {
      var c = msg.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) bytes.push(192 | (c >> 6), 128 | (c & 63));
      else if (c < 55296 || c >= 57344) bytes.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
      else { i++; var u = 0x10000 + (((c & 1023) << 10) | (msg.charCodeAt(i) & 1023)); bytes.push(240 | (u >> 18), 128 | ((u >> 12) & 63), 128 | ((u >> 6) & 63), 128 | (u & 63)); }
    }
    var bl = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (i = 7; i >= 0; i--) bytes.push(Math.floor(bl / Math.pow(2, 8 * i)) & 0xff);
    for (var off = 0; off < bytes.length; off += 64) {
      var w = new Array(64);
      for (i = 0; i < 16; i++) w[i] = (bytes[off + i*4] << 24) | (bytes[off + i*4+1] << 16) | (bytes[off + i*4+2] << 8) | bytes[off + i*4+3];
      for (i = 16; i < 64; i++) { var s0 = R(7,w[i-15])^R(18,w[i-15])^(w[i-15]>>>3); var s1 = R(17,w[i-2])^R(19,w[i-2])^(w[i-2]>>>10); w[i] = (s1 + w[i-7] + s0 + w[i-16]) | 0; }
      var a=H[0],b=H[1],c2=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (i = 0; i < 64; i++) {
        var S1 = R(6,e)^R(11,e)^R(25,e), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        var S0 = R(2,a)^R(13,a)^R(22,a), mj = (a & b) ^ (a & c2) ^ (b & c2), t2 = (S0 + mj) | 0;
        h=g; g=f; f=e; e=(d + t1) | 0; d=c2; c2=b; b=a; a=(t1 + t2) | 0;
      }
      H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c2)|0; H[3]=(H[3]+d)|0; H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
    }
    var hex = "";
    for (i = 0; i < 8; i++) hex += ("00000000" + (H[i] >>> 0).toString(16)).slice(-8);
    return hex;
  }
  function randomart(hex) {
    var hx = (hex.match(/[0-9a-fA-F]/g) || []).join(""), data = [], i;
    for (i = 0; i + 1 < hx.length; i += 2) data.push(parseInt(hx.substr(i, 2), 16));
    var cols = 17, rows = 9, cell = 9, grid = [];
    for (i = 0; i < rows; i++) grid.push(new Array(cols).fill(0));
    var x = cols >> 1, y = rows >> 1;
    for (var bi = 0; bi < data.length; bi++) { var bb = data[bi]; for (var k = 0; k < 4; k++) { x = Math.min(cols-1, Math.max(0, x + ((bb & 1) ? 1 : -1))); y = Math.min(rows-1, Math.max(0, y + ((bb & 2) ? 1 : -1))); grid[y][x]++; bb >>= 2; } }
    var peak = 1, j; for (j = 0; j < rows; j++) for (i = 0; i < cols; i++) if (grid[j][i] > peak) peak = grid[j][i];
    var fills = ""; for (j = 0; j < rows; j++) for (i = 0; i < cols; i++) { var v = grid[j][i]; if (v) fills += '<rect x="' + (i*cell) + '" y="' + (j*cell) + '" width="' + cell + '" height="' + cell + '" fill-opacity="' + (0.16 + 0.84 * (v / peak)).toFixed(2) + '"/>'; }
    var sx = cols >> 1, sy = rows >> 1;
    var frame = '<rect x="0.5" y="0.5" width="' + (cols*cell-1) + '" height="' + (rows*cell-1) + '" fill="none" stroke="currentColor" stroke-opacity=".3"/>';
    var marks = '<rect x="' + (sx*cell) + '" y="' + (sy*cell) + '" width="' + cell + '" height="' + cell + '" fill="none" stroke="currentColor" stroke-opacity=".85"/><rect x="' + (x*cell) + '" y="' + (y*cell) + '" width="' + cell + '" height="' + cell + '" fill="none" stroke="currentColor" stroke-opacity=".85"/>';
    return '<svg viewBox="0 0 ' + (cols*cell) + ' ' + (rows*cell) + '" fill="currentColor" shape-rendering="crispEdges" role="img" aria-label="randomart fingerprint">' + frame + fills + marks + '</svg>';
  }
  var root = document.getElementById("vf-root");
  var expected = root.getAttribute("data-expected");
  var input = document.getElementById("vf-input");
  var original = input.value;
  function setText(id, t) { var el = document.getElementById(id); if (el) el.textContent = t; }
  function L() { return document.documentElement.getAttribute("data-lang") === "zh" ? "zh" : "en"; }
  var STR = {
    intact: { en: "INTACT", zh: "完好" },
    fail: { en: "INTEGRITY FAIL", zh: "完整性失效" },
    okmeta: { en: "sha256 matches \\u00b7 fingerprint verified", zh: "sha256 一致 \\u00b7 指纹已验证" },
    badmeta: { en: "sha256 MISMATCH \\u00b7 evidence tampered \\u00b7 Bitget never called", zh: "sha256 不一致 \\u00b7 证据被篡改 \\u00b7 Bitget 从未被调用" },
    verified: { en: "VERIFIED", zh: "已验证" },
    voided: { en: "VOID", zh: "作废" },
    okstatus: { en: "sha256 match", zh: "sha256 一致" },
    badstatus: { en: "sha256 MISMATCH", zh: "sha256 不一致" }
  };
  function S(k) { return STR[k][L()]; }
  function update() {
    var digest = sha256hex(input.value), ok = digest === expected;
    document.getElementById("vf-art").innerHTML = randomart(digest);
    setText("vf-hash", digest.slice(0, 24) + "\\u2026");
    setText("vf-verdict", ok ? S("intact") : S("fail"));
    setText("vf-meta", ok ? S("okmeta") : S("badmeta"));
    setText("vf-stamp", ok ? S("verified") : S("voided"));
    setText("vf-status", ok ? S("okstatus") : S("badstatus"));
    document.getElementById("vf-band").classList.toggle("rl-band--pass", ok);
    var seal = document.getElementById("vf-seal");
    seal.classList.toggle("rl-seal--pass", ok);
    seal.classList.toggle("rl-seal--void", !ok);
  }
  input.addEventListener("input", update);
  window.addEventListener("rl-lang", update);
  update();
  document.getElementById("vf-flip").addEventListener("click", function () {
    var v = input.value; if (!v) return; var i = Math.floor(v.length / 2);
    input.value = v.slice(0, i) + String.fromCharCode(v.charCodeAt(i) ^ 1) + v.slice(i + 1);
    update();
  });
  document.getElementById("vf-reset").addEventListener("click", function () { input.value = original; update(); });
  update();
})();
</script>
"""


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


def _verify_record(panel: EvidencePanel | None) -> dict[str, object]:
    if panel is not None and panel.evidence is not None:
        evidence = panel.evidence
        return {
            "verdict": panel.verdict,
            "reason_code": panel.reason_code,
            "bitget_order_id": evidence.bitget_order_id,
            "client_oid": evidence.client_oid,
            "symbol": evidence.symbol,
            "order_mode": evidence.order_mode,
            "paptrading": evidence.paptrading or "1",
            "receipt_hash": evidence.receipt_hash,
            "response_hash": evidence.response_hash,
        }
    return {
        "verdict": "PASS",
        "reason_code": "PASS",
        "bitget_order_id": "1453610833413308417",
        "client_oid": "rl-98eb356e754b8eab27b6442f92c29",
        "symbol": "BTCUSDT",
        "order_mode": "demo",
        "paptrading": "1",
        "receipt_hash": "sha256:426312eeddd82c552a747df781bf12e2573280fcb7b9ab442f277a2fb76645d6",
        "response_hash": "sha256:9d7da0b24514ee1724d80ba8383514781265f59678bcfacea63e1030e46e8d5c",
    }


def render_verify_html(panel: EvidencePanel | None = None) -> str:
    """Self-contained offline verify/tamper page: edit the evidence, and a pure-JS sha256
    re-derives the fingerprint so the randomart seal visibly morphs and the verdict flips."""
    payload = json.dumps(_verify_record(panel), indent=2, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    short = _esc(digest[:24] + "…")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Redline · Verify</title>
  <style>{_inline_css()}</style>
</head>
<body>
  <main class="rl-main" id="vf-root" data-expected="{digest}">
    {_lang_toggle()}
    <h1 class="rl-macro rl-caret">{t("Verify", "校验")}</h1>
    <p class="rl-label">{t("offline self-verification · no network · edit the evidence to break the seal", "离线自校验 · 无需联网 · 编辑证据即可破坏印章")}</p>
    <hr>
    <div class="rl-band rl-band--pass rl-scanin" id="vf-band">
      <span class="rl-band__verdict" id="vf-verdict">INTACT</span>
      <span class="rl-band__meta" id="vf-meta">sha256 matches &middot; fingerprint verified</span>
    </div>
    <div class="rl-seal rl-seal--pass" id="vf-seal">
      <span class="rl-seal__art" id="vf-art">{randomart_svg(digest)}</span>
      <span class="rl-seal__body"><span class="rl-seal__stamp" id="vf-stamp">VERIFIED</span><span class="rl-seal__algo">{t("SSH randomart · live fingerprint", "SSH randomart · 实时指纹")}</span><span class="rl-seal__hash" id="vf-hash">{short}</span><span class="rl-seal__edge">ED25519 &middot; PLAYBOOK REDLINE</span></span>
    </div>
    <p class="rl-sec">{t("Tamper control · change one byte, watch the fingerprint morph", "篡改控制台 · 改动一个字节，观察指纹形变")}</p>
    <div class="rl-box">
      <p class="rl-label">{t("expected sha256", "期望 sha256")} &nbsp; <span class="rl-mono">{digest}</span></p>
      <textarea id="vf-input" class="rl-ta" spellcheck="false" aria-label="evidence payload">{_esc(payload)}</textarea>
      <p class="rl-row"><button type="button" class="rl-btn rl-btn--hazard" id="vf-flip">{t("flip one byte", "翻转一个字节")}</button><button type="button" class="rl-btn" id="vf-reset">{t("reset", "重置")}</button><span class="rl-mono" id="vf-status">sha256 match</span></p>
    </div>
    <p class="rl-sec">{t("Zero-secret reproduce on a clean machine", "在干净机器上零密钥复现")}</p>
    <div class="rl-cmd"><div class="rl-cmd__body">
      <samp class="rl-cmd__cmt">{t("same check in your terminal, exits non-zero on tamper", "在你的终端里做同样的校验，被篡改时以非零码退出")}</samp>
      <samp>uv run redline verify-chain &lt;release_dir&gt; --json</samp>
      <samp>scripts/tamper-demo.sh</samp>
    </div></div>
    <hr>
    <p class="rl-muted">{t(HONEST_STATEMENT_EN, HONEST_STATEMENT_ZH)}</p>
  </main>
  {_I18N_SCRIPT}
  {_VERIFY_SCRIPT}
</body>
</html>
"""


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


_EVIDENCE_SCRIPT = """
<script>
(function () {
  var nodes = document.querySelectorAll(".rl-mono");
  for (var i = 0; i < nodes.length; i++) {
    (function (el) {
      if (el.children.length) return;
      var text = (el.textContent || "").trim();
      if (text.length < 8) return;
      el.classList.add("rl-copyable");
      el.setAttribute("title", "click to copy");
      el.addEventListener("click", function () {
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          el.classList.add("rl-copied");
          setTimeout(function () { el.classList.remove("rl-copied"); }, 800);
        });
      });
    })(nodes[i]);
  }
})();
</script>
"""


def _render_document(*, title: str, panels: list[EvidencePanel], comparison: bool) -> str:
    rendered = "\n".join(_render_panel(panel, with_title=comparison) for panel in panels)
    inner = f'    <div class="rl-cols-2">\n{rendered}\n    </div>' if comparison else rendered
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(title)}</title>
  <style>{_inline_css()}</style>
</head>
<body>
  <main class="rl-main">
    {_lang_toggle()}
    <h1 class="rl-macro rl-caret">{_esc(title)}</h1>
{inner}
    <hr>
    <p class="rl-muted">{t(HONEST_STATEMENT_EN, HONEST_STATEMENT_ZH)}</p>
  </main>
  {_I18N_SCRIPT}
  {_EVIDENCE_SCRIPT}
</body>
</html>
"""


def _render_panel(panel: EvidencePanel, *, with_title: bool = False) -> str:
    band_mod = "rl-band--pass" if (panel.evidence is not None and panel.invalid_reason_code is None) else ""
    title_html = f'        <p class="rl-label">{_esc(panel.title)}</p>\n' if with_title else ""
    return f"""      <section>
{title_html}        <div class="rl-band {band_mod}">
          <span class="rl-band__verdict">{_esc(panel.verdict)}</span>
          <span class="rl-band__meta">{_band_meta(panel)}</span>
        </div>
{_render_seal(panel)}
{_render_redline(panel)}
{_render_execution(panel)}
{_render_block(panel)}
      </section>"""


def _render_redline(panel: EvidencePanel) -> str:
    return f"""        <p class="rl-sec">{t("redline side", "redline 侧")}</p>
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
    return f"""        <p class="rl-sec">{t("execution side", "执行侧")}</p>
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
    return f"""        <p class="rl-sec">{t("block side", "拦截侧")}</p>
        <div class="rl-box"><dl class="rl-dl">
          <dt>block reason_code</dt><dd class="rl-mono">{_esc(reason)}</dd>
          <dt>exchange call</dt><dd>{t("Bitget was not called", "Bitget 未被调用")}</dd>
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
    frame = f'<rect x="0.5" y="0.5" width="{cols * cell - 1}" height="{rows * cell - 1}" fill="none" stroke="currentColor" stroke-opacity=".3"/>'
    marks = (
        f'<rect x="{sx*cell}" y="{sy*cell}" width="{cell}" height="{cell}" fill="none" stroke="currentColor" stroke-opacity=".85"/>'
        f'<rect x="{x*cell}" y="{y*cell}" width="{cell}" height="{cell}" fill="none" stroke="currentColor" stroke-opacity=".85"/>'
    )
    return (
        f'<svg viewBox="0 0 {cols*cell} {rows*cell}" fill="currentColor" shape-rendering="crispEdges" role="img" aria-label="randomart hash fingerprint of the receipt">'
        + frame + fills + marks + "</svg>"
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
        f'<span class="rl-seal__hash">{_esc(short)}</span>'
        f'<span class="rl-seal__edge">ED25519 · PLAYBOOK REDLINE</span></span></div>'
    )


def _band_meta(panel: EvidencePanel) -> str:
    suffix = t("DEMO paptrading:1 non-mainnet", "演示 paptrading:1 非主网")
    if panel.invalid_reason_code:
        return f'{t("INTEGRITY FAIL", "完整性失效")} · {suffix}'
    if panel.evidence is not None and panel.verdict == "PASS":
        return f'{t("REPLAYED CHAINED SIGNED", "已重放 已链接 已签名")} · {suffix}'
    if panel.verdict == "WITHHELD":
        return f'{t("BLOCKED", "已拦截")} · {t("BITGET NOT CALLED", "BITGET 未被调用")} · {suffix}'
    return f'{t("BLOCKED", "已拦截")} · {suffix}'


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
