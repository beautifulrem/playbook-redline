from __future__ import annotations

import html
import json
from typing import Any

from redline.render import _inline_css, randomart_svg

REPO_URL = "https://github.com/beautifulrem/playbook-redline"
BITGET_DOCS_URL = "https://www.bitget.com/api-doc/contract/intro"
DEMO_STAMP = "DEMO / paptrading:1 / non-mainnet"

_OK = {"ok", "pass", "passed", "succeeded", "job_succeeded", "release_ready", "attested", "verified"}
_BAD = {"failed", "invalid", "missing", "blocked", "blocked_withheld", "withheld", "void", "cancelled", "true"}


def render_judge_console_html(*, principal: str, safety: dict[str, Any], releases: list[dict[str, Any]]) -> str:
    rows = "\n".join(
        "<tr>"
        f'<td><a href="/v1/judge/releases/{_e(item["release_id"])}">{_e(item["release_id"])}</a></td>'
        f"<td>{_badge(item['state'])}</td>"
        f"<td>{_id(item.get('canonical_order_id'))}</td>"
        f"<td>{_e(item.get('showcase_count', 0))}</td>"
        f"<td>{_badge(item.get('attestation_status') or 'missing')}</td>"
        f"<td>{_badge(item.get('latest_job_status') or 'none')}</td>"
        "</tr>"
        for item in releases
    )
    if not rows:
        rows = '<tr><td colspan="6">No release candidates</td></tr>'
    body = f"""
    <h1 class="rl-macro">Judge Console</h1>
    <p class="rl-label">{_e(DEMO_STAMP)} &nbsp;&middot;&nbsp; principal {_e(principal)}</p>
    <hr>
    <h2 class="rl-sec">Safety</h2>
    <div class="rl-grid rl-grid--3">
      {_metric("release freeze", _flag(safety.get("release_freeze")))}
      {_metric("execution freeze", _flag(safety.get("execution_freeze")))}
      {_metric("mainnet enabled", _flag(safety.get("mainnet_orders_enabled")))}
    </div>
    <h2 class="rl-sec">Release candidates</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">release</th><th scope="col">state</th><th scope="col">canonical order</th><th scope="col">showcase</th><th scope="col">attestation</th><th scope="col">latest job</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    {_chrome()}
    {_script()}
"""
    return _document(title="Redline Judge Console", body=body)


def render_judge_release_html(
    *,
    principal: str,
    safety: dict[str, Any],
    release: dict[str, Any],
    showcase_orders: list[dict[str, Any]],
    jobs: list[dict[str, Any]],
    latest_events: list[dict[str, Any]],
    audit_entries: list[dict[str, Any]],
    bundle_status: dict[str, Any],
    attestation_status: dict[str, Any],
) -> str:
    release_id = str(release["release_id"])
    execution = release.get("execution_evidence") or {}
    state = str(release.get("state") or "")
    band_mod = "rl-band--pass" if _is_ok(state) else ""
    showcase_rows = "\n".join(
        "<tr>"
        f"<td>{_e(item.get('attempt_id'))}</td>"
        f"<td>{_badge('ok' if item.get('ok') else item.get('reason_code') or 'invalid')}</td>"
        f"<td>{_id(item.get('bitget_order_id'))}</td>"
        f"<td>{_id(item.get('client_oid'))}</td>"
        f'<td><a href="{_e(item.get("evidence_html_url") or "#")}">evidence</a></td>'
        "</tr>"
        for item in showcase_orders
    )
    if not showcase_rows:
        showcase_rows = '<tr><td colspan="5">No showcase orders</td></tr>'
    job_rows = "\n".join(
        "<tr>"
        f"<td>{_e(item.get('job_id'))}</td>"
        f"<td>{_badge(item.get('status') or 'unknown')}</td>"
        f"<td>{_e(item.get('job_type'))}</td>"
        f"<td>{_e(item.get('requested_by'))}</td>"
        f'<td><a href="/v1/release-candidates/{_e(release_id)}/jobs/{_e(item.get("job_id"))}/events.ndjson">events</a></td>'
        "</tr>"
        for item in jobs
    )
    if not job_rows:
        job_rows = '<tr><td colspan="5">No jobs</td></tr>'
    event_lines = "\n".join(_e(_event_line(item)) for item in latest_events) or "No job events"
    audit_lines = "\n".join(_e(_audit_line(item)) for item in audit_entries[-12:]) or "No audit entries"
    body = f"""
    <p class="rl-label"><a href="/v1/judge/console">&larr; Judge Console</a></p>
    <h1 class="rl-macro">Release</h1>
    <p class="rl-label">{_e(DEMO_STAMP)} &nbsp;&middot;&nbsp; <span class="rl-mono">{_e(release_id)}</span> &nbsp;&middot;&nbsp; principal {_e(principal)}</p>
    <div class="rl-band {band_mod}">
      <span class="rl-band__verdict">{_e((state or "unknown").upper().replace("_", " "))}</span>
      <span class="rl-band__meta">verdict {_e(release.get("redline_reason_code") or "missing")}</span>
    </div>
    {_release_seal(release, state)}
    <h2 class="rl-sec">Verifiable chain</h2>
    {_proofbar(release, showcase_orders)}
    {_chain_walk(release, bundle_status, attestation_status)}
    <h2 class="rl-sec">Assurance tier</h2>
    {_tier_meter(release)}
    <h2 class="rl-sec">Release</h2>
    <div class="rl-grid rl-grid--3">
      {_metric("state", _badge(release.get("state")))}
      {_metric("verdict", _e(release.get("redline_reason_code") or "missing"))}
      {_metric("canonical order", _id(execution.get("bitget_order_id")))}
    </div>
    <div class="rl-grid rl-grid--3">
      {_metric("symbol", _symbol_link(execution.get("symbol")))}
      {_metric("simulation hash", _id(release.get("simulation_evidence_hash")))}
      {_metric("approval", _e((release.get("approval") or {}).get("reviewer_id") or "missing"))}
    </div>
    <div class="rl-grid rl-grid--3">
      {_metric("release freeze", _flag(safety.get("release_freeze")))}
      {_metric("execution freeze", _flag(safety.get("execution_freeze")))}
      {_metric("mainnet enabled", _flag(safety.get("mainnet_orders_enabled")))}
    </div>
    <h2 class="rl-sec">Actions</h2>
    <div class="rl-box">
      <div class="rl-tamper__row">
        <input id="redline-token" class="rl-input" type="password" autocomplete="off" aria-label="Redline token" placeholder="Redline token" />
        <button type="button" class="rl-btn" data-action="save-token">Save token</button>
        <button type="button" class="rl-btn" data-action="run-showcase" data-release-id="{_e(release_id)}">Run live Bitget demo showcase order</button>
        <button type="button" class="rl-btn" data-action="attest" data-release-id="{_e(release_id)}">Attest bundle</button>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/evidence">Download bundle</a>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/evidence.html">Open evidence.html</a>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/attestation.html">Open attestation.html</a>
      </div>
    </div>
    <h2 class="rl-sec">Verification</h2>
    <div class="rl-cols-2">
      {_metric("bundle verify", _status_block(bundle_status))}
      {_metric("attestation", _status_block(attestation_status))}
    </div>
    <h2 class="rl-sec">Showcase orders</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">attempt</th><th scope="col">status</th><th scope="col">order id</th><th scope="col">client oid</th><th scope="col">evidence</th></tr></thead>
      <tbody>{showcase_rows}</tbody>
    </table></div>
    <h2 class="rl-sec">Jobs</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">job</th><th scope="col">status</th><th scope="col">type</th><th scope="col">requested by</th><th scope="col">events</th></tr></thead>
      <tbody>{job_rows}</tbody>
    </table></div>
    <h2 class="rl-sec">Latest job events</h2>
    <pre class="rl-pre" id="job-events">{event_lines}</pre>
    <h2 class="rl-sec">Audit ledger</h2>
    <pre class="rl-pre">{audit_lines}</pre>
    {_chrome()}
    {_script()}
"""
    return _document(title=f"Release {release_id}", body=body)


def _document(*, title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_e(title)}</title>
  <style>{_inline_css()}</style>
</head>
<body>
  <main class="rl-main">
{body}
  </main>
</body>
</html>
"""


def _chrome() -> str:
    return (
        f'    <hr>\n    <p class="rl-muted">Playbook Redline &nbsp;&middot;&nbsp; '
        f'<a href="{REPO_URL}" target="_blank" rel="noopener">source &nearr;</a> &nbsp;&middot;&nbsp; '
        f'<a href="{BITGET_DOCS_URL}" target="_blank" rel="noopener">Bitget API &nearr;</a></p>'
    )


def _release_seal(release: dict[str, Any], state: str) -> str:
    seed = (
        release.get("simulation_evidence_hash")
        or release.get("risk_policy_hash")
        or (release.get("execution_evidence") or {}).get("response_hash")
    )
    if not seed:
        return ""
    seed = str(seed)
    passed = _is_ok(state)
    mod = "rl-seal--pass" if passed else "rl-seal--void"
    stamp = "VERIFIED" if passed else "REVIEW"
    short = seed if len(seed) <= 26 else seed[:26] + "…"
    return (
        f'    <div class="rl-seal {mod}"><span class="rl-seal__art">{randomart_svg(seed)}</span>'
        f'<span class="rl-seal__body"><span class="rl-seal__stamp">{_e(stamp)}</span>'
        f'<span class="rl-seal__algo">SSH randomart &middot; release fingerprint</span>'
        f'<span class="rl-seal__hash">{_e(short)}</span></span></div>'
    )


def _chain_walk(release: dict[str, Any], bundle_status: dict[str, Any], attestation_status: dict[str, Any]) -> str:
    execution = release.get("execution_evidence") or {}
    approval = release.get("approval") or {}
    steps = [
        ("receipt", str(release.get("redline_reason_code") or "verdict"), bool(release.get("redline_reason_code"))),
        ("approval", str(approval.get("reviewer_id") or "-"), bool(approval.get("reviewer_id"))),
        ("execution", _short_id(execution.get("bitget_order_id")), bool(execution.get("bitget_order_id"))),
        ("attestation", "ed25519" if attestation_status.get("ok") else "-", bool(attestation_status.get("ok"))),
        ("merkle", "root" if bundle_status.get("ok") else "-", bool(bundle_status.get("ok"))),
    ]
    nodes = []
    failed = False
    for label, detail, ok in steps:
        if failed:
            status = '<span class="rl-chain__st--skip">not reached</span>'
            node_cls = ""
            detail = "-"
        elif ok:
            status = '<span class="rl-chain__st--ok">&#10004; verified</span>'
            node_cls = ""
        else:
            status = '<span class="rl-chain__st--bad">&#10008; failed</span><span class="rl-chain__flag">first failed</span>'
            node_cls = " rl-chain__node--fail"
            failed = True
        nodes.append(
            f'<div class="rl-chain__node{node_cls}"><span class="rl-chain__label">{_e(label)}</span>'
            f'<span class="rl-chain__hash">{_e(detail)}</span>{status}</div>'
        )
    return f'    <div class="rl-chain">{"".join(nodes)}</div>'


def _proofbar(release: dict[str, Any], showcase_orders: list[dict[str, Any]]) -> str:
    execution = release.get("execution_evidence") or {}
    verified = sum(1 for order in showcase_orders if order.get("ok"))
    tier = "L1" if execution.get("bitget_order_id") else "L0"
    items = [
        (str(verified).zfill(2), "verified orders", False),
        ("00", "live funds at risk", True),
        (tier, "assurance tier", False),
        ("256", "bit hash-chained", False),
    ]
    cells = "".join(
        f'<div><span class="rl-proof__num{" rl-proof__num--ok" if ok else ""}">{_e(num)}</span>'
        f'<span class="rl-proof__label">{_e(label)}</span></div>'
        for num, label, ok in items
    )
    return f'    <div class="rl-proofbar">{cells}</div>'


def _tier_meter(release: dict[str, Any]) -> str:
    executed = bool((release.get("execution_evidence") or {}).get("bitget_order_id"))
    segments = [
        ("L0", "sim-only", "rl-tier__seg--reached"),
        ("L1", "demo-executed", "rl-tier__seg--on" if executed else ""),
        ("L2", "live-gated", ""),
    ]
    segs = "".join(
        f'<div class="rl-tier__seg {cls}"><b>{_e(code)}</b>{_e(label)}</div>' for code, label, cls in segments
    )
    return f'    <div class="rl-tier">{segs}</div>'


def _short_id(value: object) -> str:
    raw = str(value or "")
    return raw if len(raw) <= 14 else raw[:6] + "…" + raw[-4:]


def _symbol_link(symbol: object) -> str:
    raw = str(symbol or "").strip()
    if not raw:
        return _e("missing")
    return f'<a href="https://www.bitget.com/futures/usdt/{_e(raw)}" target="_blank" rel="noopener">{_e(raw)} &nearr;</a>'


def _script() -> str:
    return """
<script>
(() => {
  const tokenInput = document.getElementById("redline-token");
  if (tokenInput && localStorage.getItem("redlineJudgeToken")) tokenInput.value = localStorage.getItem("redlineJudgeToken");
  function token() {
    const value = tokenInput ? tokenInput.value.trim() : "";
    if (!value) window.alert("Enter a Redline token first.");
    return value;
  }
  async function api(path, options = {}) {
    const value = token();
    if (!value) throw new Error("missing token");
    const headers = Object.assign({"X-Redline-Token": value}, options.headers || {});
    return fetch(path, Object.assign({}, options, {headers}));
  }
  async function refreshEvents(releaseId, jobId) {
    const target = document.getElementById("job-events");
    const events = await api(`/v1/release-candidates/${releaseId}/jobs/${jobId}/events.ndjson`);
    const text = await events.text();
    if (target) target.textContent = text || "No job events";
  }
  async function pollJob(releaseId, jobId) {
    for (let i = 0; i < 30; i += 1) {
      await refreshEvents(releaseId, jobId);
      const response = await api(`/v1/release-candidates/${releaseId}/jobs/${jobId}`);
      const job = await response.json();
      if (job.status === "succeeded" || job.status === "failed" || job.status === "cancelled") return job;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return null;
  }
  document.addEventListener("click", async (event) => {
    const copyBtn = event.target.closest("[data-copy]");
    if (copyBtn) {
      try {
        await navigator.clipboard.writeText(copyBtn.dataset.copy);
        const prev = copyBtn.textContent;
        copyBtn.textContent = "copied";
        setTimeout(() => { copyBtn.textContent = prev; }, 1200);
      } catch (err) { /* clipboard unavailable */ }
      return;
    }
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "save-token") {
      if (tokenInput) localStorage.setItem("redlineJudgeToken", tokenInput.value.trim());
      return;
    }
    const releaseId = button.dataset.releaseId;
    button.disabled = true;
    try {
      if (action === "run-showcase") {
        const response = await api(`/v1/release-candidates/${releaseId}/jobs/showcase-order`, {
          method: "POST",
          headers: {"Content-Type": "application/json", "Idempotency-Key": `judge-console-${Date.now()}`},
          body: JSON.stringify({side: "buy", size: "0.0001"})
        });
        const job = await response.json();
        await pollJob(releaseId, job.job_id);
      }
      if (action === "attest") {
        await api(`/v1/release-candidates/${releaseId}/attest`, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"});
        window.location.reload();
      }
    } finally {
      button.disabled = false;
    }
  });
})();
</script>
"""


def _metric(label: str, value: object) -> str:
    return f'<div class="rl-box"><span class="rl-box__label">{_e(label)}</span><strong>{value}</strong></div>'


def _badge(value: object) -> str:
    raw = str(value or "missing")
    key = raw.lower().replace(" ", "_").replace("/", "_").replace("-", "_")
    mod = " rl-badge--ok" if key in _OK else " rl-badge--fail" if key in _BAD else ""
    return f'<span class="rl-badge{mod}">{_e(raw)}</span>'


def _id(value: object) -> str:
    raw = str(value or "")
    if not raw or raw in {"none", "missing"}:
        return _e(raw or "none")
    return (
        f'<span class="rl-idcopy"><span class="rl-mono">{_e(raw)}</span>'
        f'<button type="button" class="rl-copy" data-copy="{_e(raw)}" aria-label="copy {_e(raw)}">copy</button></span>'
    )


def _status_block(status: dict[str, Any]) -> str:
    label = status.get("status") or ("ok" if status.get("ok") else "missing")
    detail = status.get("detail") or status.get("hash") or ""
    return f'{_badge(label)}<br><small class="rl-mono rl-faint">{_e(detail)}</small>'


def _event_line(item: dict[str, Any]) -> str:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return f"{item.get('sequence', '')} {item.get('event_type', '')} {json.dumps(payload, sort_keys=True)}"


def _audit_line(item: dict[str, Any]) -> str:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return f"{item.get('created_at', '')} {item.get('event_type', '')} {json.dumps(payload, sort_keys=True)}"


def _is_ok(state: object) -> bool:
    return str(state or "").lower().replace("-", "_") in _OK


def _flag(value: object) -> str:
    return _badge("true" if bool(value) else "false")


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)
