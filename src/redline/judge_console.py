from __future__ import annotations

import html
import json
from typing import Any


def render_judge_console_html(*, principal: str, safety: dict[str, Any], releases: list[dict[str, Any]]) -> str:
    rows = "\n".join(
        "<tr>"
        f"<td><a href=\"/v1/judge/releases/{_e(item['release_id'])}\">{_e(item['release_id'])}</a></td>"
        f"<td>{_badge(item['state'])}</td>"
        f"<td>{_e(item.get('canonical_order_id') or 'none')}</td>"
        f"<td>{_e(item.get('showcase_count', 0))}</td>"
        f"<td>{_badge(item.get('attestation_status') or 'missing')}</td>"
        f"<td>{_badge(item.get('latest_job_status') or 'none')}</td>"
        "</tr>"
        for item in releases
    )
    if not rows:
        rows = "<tr><td colspan=\"6\">No release candidates</td></tr>"
    return _document(
        title="Redline Judge Console",
        body=f"""
<header>
  <div>
    <p class="stamp">DEMO / paptrading:1 / non-mainnet</p>
    <h1>Redline Judge Console</h1>
  </div>
  <div class="principal">{_e(principal)}</div>
</header>
<section class="grid three">
  {_metric("release freeze", _flag(safety.get("release_freeze")))}
  {_metric("execution freeze", _flag(safety.get("execution_freeze")))}
  {_metric("mainnet enabled", _flag(safety.get("mainnet_orders_enabled")))}
</section>
<section>
  <h2>Release Candidates</h2>
  <table>
    <thead><tr><th>release</th><th>state</th><th>canonical order</th><th>showcase</th><th>attestation</th><th>latest job</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
""",
    )


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
    showcase_rows = "\n".join(
        "<tr>"
        f"<td>{_e(item.get('attempt_id'))}</td>"
        f"<td>{_badge('ok' if item.get('ok') else item.get('reason_code') or 'invalid')}</td>"
        f"<td>{_e(item.get('bitget_order_id') or '')}</td>"
        f"<td>{_e(item.get('client_oid') or '')}</td>"
        f"<td><a href=\"{_e(item.get('evidence_html_url') or '#')}\">evidence</a></td>"
        "</tr>"
        for item in showcase_orders
    )
    if not showcase_rows:
        showcase_rows = "<tr><td colspan=\"5\">No showcase orders</td></tr>"
    job_rows = "\n".join(
        "<tr>"
        f"<td>{_e(item.get('job_id'))}</td>"
        f"<td>{_badge(item.get('status') or 'unknown')}</td>"
        f"<td>{_e(item.get('job_type'))}</td>"
        f"<td>{_e(item.get('requested_by'))}</td>"
        f"<td><a href=\"/v1/release-candidates/{_e(release_id)}/jobs/{_e(item.get('job_id'))}/events.ndjson\">events</a></td>"
        "</tr>"
        for item in jobs
    )
    if not job_rows:
        job_rows = "<tr><td colspan=\"5\">No jobs</td></tr>"
    event_lines = "\n".join(_e(_event_line(item)) for item in latest_events) or "No job events"
    audit_lines = "\n".join(_e(_audit_line(item)) for item in audit_entries[-12:]) or "No audit entries"
    return _document(
        title=f"Release {release_id}",
        body=f"""
<header>
  <div>
    <p class="stamp">DEMO / paptrading:1 / non-mainnet</p>
    <h1>Release {_e(release_id)}</h1>
  </div>
  <div class="principal">{_e(principal)}</div>
</header>
<nav><a href="/v1/judge/console">Judge Console</a></nav>
<section class="grid three">
  {_metric("state", _badge(release.get("state")))}
  {_metric("verdict", _e(release.get("redline_reason_code") or "missing"))}
  {_metric("canonical order", _e((release.get("execution_evidence") or {}).get("bitget_order_id") or "missing"))}
</section>
<section class="grid three">
  {_metric("simulation hash", _short(release.get("simulation_evidence_hash")))}
  {_metric("risk hash", _short(release.get("risk_policy_hash")))}
  {_metric("approval", _e((release.get("approval") or {}).get("reviewer_id") or "missing"))}
</section>
<section class="grid three">
  {_metric("release freeze", _flag(safety.get("release_freeze")))}
  {_metric("execution freeze", _flag(safety.get("execution_freeze")))}
  {_metric("mainnet enabled", _flag(safety.get("mainnet_orders_enabled")))}
</section>
<section class="actions">
  <input id="redline-token" type="password" autocomplete="off" placeholder="Redline token" />
  <button type="button" data-action="save-token">Save token</button>
  <button type="button" data-action="run-showcase" data-release-id="{_e(release_id)}">Run live Bitget demo showcase order</button>
  <button type="button" data-action="attest" data-release-id="{_e(release_id)}">Attest bundle</button>
  <a class="button" href="/v1/release-candidates/{_e(release_id)}/evidence">Download bundle</a>
  <a class="button" href="/v1/release-candidates/{_e(release_id)}/evidence.html">Open evidence.html</a>
  <a class="button" href="/v1/release-candidates/{_e(release_id)}/attestation.html">Open attestation.html</a>
</section>
<section class="grid two">
  {_metric("bundle verify", _status_block(bundle_status))}
  {_metric("attestation", _status_block(attestation_status))}
</section>
<section>
  <h2>Showcase Orders</h2>
  <table>
    <thead><tr><th>attempt</th><th>status</th><th>order id</th><th>client oid</th><th>evidence</th></tr></thead>
    <tbody>{showcase_rows}</tbody>
  </table>
</section>
<section>
  <h2>Jobs</h2>
  <table>
    <thead><tr><th>job</th><th>status</th><th>type</th><th>requested by</th><th>events</th></tr></thead>
    <tbody>{job_rows}</tbody>
  </table>
</section>
<section>
  <h2>Latest Job Events</h2>
  <pre id="job-events">{event_lines}</pre>
</section>
<section>
  <h2>Audit Ledger</h2>
  <pre>{audit_lines}</pre>
</section>
{_script()}
""",
    )


def _document(*, title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_e(title)}</title>
  <style>
    :root {{ color-scheme: light; --fg: #1f2328; --muted: #57606a; --line: #d8dee4; --ok: #1a7f37; --bad: #cf222e; --warn: #9a6700; --bg: #f6f8fa; }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--fg); background: white; }}
    header {{ display: flex; align-items: end; justify-content: space-between; gap: 16px; padding: 24px 28px 12px; border-bottom: 1px solid var(--line); }}
    h1 {{ margin: 4px 0 0; font-size: 24px; }}
    h2 {{ margin: 0 0 12px; font-size: 16px; }}
    nav, section {{ margin: 18px 28px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ padding: 9px 8px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; word-break: break-word; }}
    th {{ color: var(--muted); font-weight: 600; }}
    pre {{ margin: 0; padding: 12px; overflow: auto; border: 1px solid var(--line); background: var(--bg); border-radius: 6px; font-size: 12px; line-height: 1.5; }}
    input {{ min-width: 220px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; }}
    button, .button {{ display: inline-block; margin: 4px 8px 4px 0; padding: 8px 10px; border: 1px solid #1f6feb; border-radius: 6px; background: #0969da; color: white; font: inherit; text-decoration: none; cursor: pointer; }}
    a {{ color: #0969da; }}
    .grid {{ display: grid; gap: 12px; }}
    .grid.two {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .grid.three {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .metric {{ padding: 12px; border: 1px solid var(--line); border-radius: 8px; }}
    .metric .label {{ display: block; color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
    .badge {{ display: inline-block; padding: 2px 7px; border-radius: 999px; background: var(--bg); border: 1px solid var(--line); }}
    .badge.ok, .badge.pass, .badge.succeeded, .badge.release_ready, .badge.ATTESTED {{ color: var(--ok); border-color: var(--ok); }}
    .badge.failed, .badge.invalid, .badge.missing, .badge.true {{ color: var(--bad); border-color: var(--bad); }}
    .badge.running, .badge.queued {{ color: var(--warn); border-color: var(--warn); }}
    .stamp, .principal {{ color: var(--muted); font-size: 13px; margin: 0; }}
    .actions {{ padding: 12px; border: 1px solid var(--line); border-radius: 8px; }}
    @media (max-width: 760px) {{ .grid.two, .grid.three {{ grid-template-columns: 1fr; }} header {{ align-items: start; flex-direction: column; }} }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


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
    return f"<div class=\"metric\"><span class=\"label\">{_e(label)}</span><strong>{value}</strong></div>"


def _badge(value: object) -> str:
    raw = str(value or "missing")
    cls = raw.replace(" ", "_").replace("/", "_")
    return f"<span class=\"badge {_e(cls)}\">{_e(raw)}</span>"


def _status_block(status: dict[str, Any]) -> str:
    label = status.get("status") or ("ok" if status.get("ok") else "missing")
    detail = status.get("detail") or status.get("hash") or ""
    return f"{_badge(label)}<br><small>{_e(detail)}</small>"


def _event_line(item: dict[str, Any]) -> str:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return f"{item.get('sequence', '')} {item.get('event_type', '')} {json.dumps(payload, sort_keys=True)}"


def _audit_line(item: dict[str, Any]) -> str:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return f"{item.get('created_at', '')} {item.get('event_type', '')} {json.dumps(payload, sort_keys=True)}"


def _short(value: object) -> str:
    raw = str(value or "missing")
    if len(raw) <= 24:
        return _e(raw)
    return _e(raw[:18] + "..." + raw[-8:])


def _flag(value: object) -> str:
    return _badge("true" if bool(value) else "false")


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)
