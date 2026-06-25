from __future__ import annotations

import html
import json
from typing import Any

from redline.render import _I18N_SCRIPT, REPO_URL, _inline_css, _lang_toggle, randomart_svg, t

BITGET_DOCS_URL = "https://www.bitget.com/api-doc/contract/intro"
DEMO_STAMP = "DEMO / paptrading:1 / non-mainnet"

_OK = {"ok", "pass", "passed", "succeeded", "job_succeeded", "release_ready", "attested", "verified"}
_BAD = {"failed", "invalid", "missing", "blocked", "blocked_withheld", "withheld", "void", "cancelled", "true"}


def render_judge_console_html(*, principal: str, safety: dict[str, Any], releases: list[dict[str, Any]]) -> str:
    rows = "\n".join(
        "<tr>"
        f'<td>{_row_seal(item.get("canonical_order_id") or item["release_id"], _is_ok(item["state"]))}</td>'
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
        rows = f'<tr><td colspan="7">{t("No release candidates", "暂无候选发布")}</td></tr>'
    body = f"""
    <h1 class="rl-macro rl-caret">{t("Judge Console", "判官控制台")}</h1>
    <p class="rl-label">{_e(DEMO_STAMP)} &nbsp;&middot;&nbsp; {t("principal", "主体")} {_e(principal)}</p>
    <hr>
{_session_bar()}
    <h2 class="rl-sec">{t("Safety", "安全")}</h2>
    <div class="rl-grid rl-grid--3">
      {_metric(t("release freeze", "发布冻结"), _flag(safety.get("release_freeze")))}
      {_metric(t("execution freeze", "执行冻结"), _flag(safety.get("execution_freeze")))}
      {_metric(t("mainnet enabled", "主网已启用"), _flag(safety.get("mainnet_orders_enabled")))}
    </div>
    <h2 class="rl-sec">{t("Release candidates", "候选发布")}</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">{t("seal", "印章")}</th><th scope="col">{t("release", "发布")}</th><th scope="col">{t("state", "状态")}</th><th scope="col">{t("canonical order", "规范订单")}</th><th scope="col">{t("showcase", "展示")}</th><th scope="col">{t("attestation", "认证")}</th><th scope="col">{t("latest job", "最新任务")}</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    {_chrome()}
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
        f'<td><a href="{_e(item.get("evidence_html_url") or "#")}">{t("evidence", "证据")}</a></td>'
        "</tr>"
        for item in showcase_orders
    )
    if not showcase_rows:
        showcase_rows = f'<tr><td colspan="5">{t("No showcase orders", "暂无展示订单")}</td></tr>'
    job_rows = "\n".join(
        "<tr>"
        f"<td>{_e(item.get('job_id'))}</td>"
        f"<td>{_badge(item.get('status') or 'unknown')}</td>"
        f"<td>{_e(item.get('job_type'))}</td>"
        f"<td>{_e(item.get('requested_by'))}</td>"
        f'<td><a href="/v1/release-candidates/{_e(release_id)}/jobs/{_e(item.get("job_id"))}/events.ndjson">{t("events", "事件")}</a></td>'
        "</tr>"
        for item in jobs
    )
    if not job_rows:
        job_rows = f'<tr><td colspan="5">{t("No jobs", "暂无任务")}</td></tr>'
    event_lines = "\n".join(_e(_event_line(item)) for item in latest_events) or t("No job events", "暂无任务事件")
    audit_lines = "\n".join(_e(_audit_line(item)) for item in audit_entries[-12:]) or t("No audit entries", "暂无审计条目")
    body = f"""
    <p class="rl-label"><a href="/v1/judge/console">&larr; {t("Judge Console", "判官控制台")}</a></p>
    <h1 class="rl-macro rl-caret">{t("Release", "发布")}</h1>
    <p class="rl-label">{_e(DEMO_STAMP)} &nbsp;&middot;&nbsp; <span class="rl-mono">{_e(release_id)}</span> &nbsp;&middot;&nbsp; {t("principal", "主体")} {_e(principal)}</p>
    <div class="rl-band {band_mod} rl-scanin">
      <span class="rl-band__verdict">{_e((state or "unknown").upper().replace("_", " "))}</span>
      <span class="rl-band__meta">{t("verdict", "裁决")} {_e(release.get("redline_reason_code") or "missing")}</span>
    </div>
    {_release_seal(release, state)}
    <h2 class="rl-sec">{t("Verifiable chain", "可验证链")}</h2>
    {_proofbar(release, showcase_orders)}
    {_chain_walk(release, bundle_status, attestation_status)}
    <h2 class="rl-sec">{t("Assurance tier", "保障层级")}</h2>
    {_tier_meter(release)}
    <h2 class="rl-sec">{t("Verdict reason", "裁决理由")}</h2>
    {_violation_telemetry(release.get("redline_reason_code"))}
    <h2 class="rl-sec">{t("Release", "发布")}</h2>
    <div class="rl-grid rl-grid--3">
      {_metric(t("state", "状态"), _badge(release.get("state")))}
      {_metric(t("verdict", "裁决"), _e(release.get("redline_reason_code") or "missing"))}
      {_metric(t("canonical order", "规范订单"), _id(execution.get("bitget_order_id")))}
    </div>
    <div class="rl-grid rl-grid--3">
      {_metric(t("symbol", "交易对"), _symbol_link(execution.get("symbol")))}
      {_metric(t("simulation hash", "模拟哈希"), _hash_field(release.get("simulation_evidence_hash")))}
      {_metric(t("approval", "审批"), _e((release.get("approval") or {}).get("reviewer_id") or "missing"))}
    </div>
    <div class="rl-grid rl-grid--3">
      {_metric(t("release freeze", "发布冻结"), _flag(safety.get("release_freeze")))}
      {_metric(t("execution freeze", "执行冻结"), _flag(safety.get("execution_freeze")))}
      {_metric(t("mainnet enabled", "主网已启用"), _flag(safety.get("mainnet_orders_enabled")))}
    </div>
    <h2 class="rl-sec">{t("Session", "会话")}</h2>
{_session_bar()}
    <h2 class="rl-sec">{t("Actions", "操作")}</h2>
    <div class="rl-box">
      <div class="rl-row">
        <button type="button" class="rl-btn" data-action="run-showcase" data-release-id="{_e(release_id)}">{t("Run live Bitget demo showcase order", "运行实时 Bitget 模拟展示订单")}</button>
        <button type="button" class="rl-btn" data-action="attest" data-release-id="{_e(release_id)}">{t("Attest bundle", "认证打包")}</button>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/evidence">{t("Download bundle", "下载打包")}</a>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/evidence.html">{t("Open evidence.html", "打开 evidence.html")}</a>
        <a class="rl-btn" href="/v1/release-candidates/{_e(release_id)}/attestation.html">{t("Open attestation.html", "打开 attestation.html")}</a>
      </div>
      <p class="rl-live" id="rl-job-status" aria-live="polite"></p>
    </div>
    <h2 class="rl-sec">{t("Verification", "校验")}</h2>
    <div class="rl-cols-2">
      {_metric(t("bundle verify", "打包校验"), _status_block(bundle_status))}
      {_metric(t("attestation", "认证"), _status_block(attestation_status))}
    </div>
    <h2 class="rl-sec">{t("Showcase orders", "展示订单")}</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">{t("attempt", "尝试")}</th><th scope="col">{t("status", "状态")}</th><th scope="col">{t("order id", "订单号")}</th><th scope="col">{t("client oid", "客户端 oid")}</th><th scope="col">{t("evidence", "证据")}</th></tr></thead>
      <tbody>{showcase_rows}</tbody>
    </table></div>
    <h2 class="rl-sec">{t("Jobs", "任务")}</h2>
    <div class="rl-scroll-x"><table class="rl-table">
      <thead><tr><th scope="col">{t("job", "任务")}</th><th scope="col">{t("status", "状态")}</th><th scope="col">{t("type", "类型")}</th><th scope="col">{t("requested by", "请求者")}</th><th scope="col">{t("events", "事件")}</th></tr></thead>
      <tbody>{job_rows}</tbody>
    </table></div>
    <h2 class="rl-sec">{t("Latest job events", "最新任务事件")}</h2>
    <pre class="rl-pre" id="job-events">{event_lines}</pre>
    <h2 class="rl-sec">{t("Audit ledger", "审计账本")}</h2>
    <pre class="rl-pre">{audit_lines}</pre>
    {_chrome()}
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
{_lang_toggle()}
{body}
  </main>
  <div class="rl-toast" id="rl-toast" role="status" aria-live="polite"></div>
{_I18N_SCRIPT}
{_script()}
</body>
</html>
"""


def _session_bar() -> str:
    return f"""    <div class="rl-box">
      <div class="rl-row rl-row--between">
        <span class="rl-live" id="rl-session">{t("checking session", "正在检查会话")}&hellip;</span>
        <span class="rl-row">
          <button type="button" class="rl-btn" data-action="dev-login">{t("Dev login", "开发登录")}</button>
          <button type="button" class="rl-btn" data-action="logout">{t("Log out", "登出")}</button>
          <details class="rl-adv"><summary class="rl-label">{t("token", "令牌")}</summary>
            <div class="rl-row"><input id="redline-token" class="rl-input" type="password" autocomplete="off" aria-label="Redline token" placeholder="X-Redline-Token (optional)" /><button type="button" class="rl-btn" data-action="save-token">{t("Save token", "保存令牌")}</button></div>
          </details>
        </span>
      </div>
    </div>"""


def _chrome() -> str:
    return (
        f'    <hr>\n    <p class="rl-muted">Playbook Redline &nbsp;&middot;&nbsp; '
        f'<a href="{REPO_URL}" target="_blank" rel="noopener">{t("source", "源码")} &nearr;</a> &nbsp;&middot;&nbsp; '
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
    stamp = t("VERIFIED", "已验证") if passed else t("REVIEW", "待复核")
    short = seed if len(seed) <= 26 else seed[:26] + "…"
    return (
        f'    <div class="rl-seal {mod}"><span class="rl-seal__art">{randomart_svg(seed)}</span>'
        f'<span class="rl-seal__body"><span class="rl-seal__stamp">{stamp}</span>'
        f'<span class="rl-seal__algo">{t("SSH randomart · release fingerprint", "SSH randomart · 发布指纹")}</span>'
        f'<span class="rl-seal__hash">{_e(short)}</span>'
        f'<span class="rl-seal__edge">ED25519 &middot; PLAYBOOK REDLINE</span></span></div>'
    )


def _row_seal(seed: object, passed: bool) -> str:
    s = str(seed or "")
    if not s:
        return ""
    mod = " rl-seal-mini--pass" if passed else ""
    return f'<span class="rl-seal-mini{mod}" title="release fingerprint">{randomart_svg(s)}</span>'


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
    total = len(steps)
    for idx, (label, detail, ok) in enumerate(steps, 1):
        if failed:
            status = f'<span class="rl-chain__st--skip">{t("not reached", "未触及")}</span>'
            node_cls = ""
            detail = "-"
        elif ok:
            status = f'<span class="rl-chain__st--ok">&#10004; {t("verified", "已验证")}</span>'
            node_cls = ""
        else:
            status = f'<span class="rl-chain__st--bad">&#10008; {t("failed", "失败")}</span><span class="rl-chain__flag">{t("first failed", "首个失败")}</span>'
            node_cls = " rl-chain__node--fail"
            failed = True
        nodes.append(
            f'<div class="rl-chain__node{node_cls}"><span class="rl-chain__idx">LINK {idx:02d}/{total:02d}</span>'
            f'<span class="rl-chain__label">{_e(label)}</span>'
            f'<span class="rl-chain__hash">{_e(detail)}</span>{status}</div>'
        )
    return f'    <div class="rl-chain rl-chain--live">{"".join(nodes)}</div>'


def _proofbar(release: dict[str, Any], showcase_orders: list[dict[str, Any]]) -> str:
    execution = release.get("execution_evidence") or {}
    verified = sum(1 for order in showcase_orders if order.get("ok"))
    tier = "L1" if execution.get("bitget_order_id") else "L0"
    items = [
        (str(verified).zfill(2), t("verified orders", "已验证订单"), False),
        ("00", t("live funds at risk", "在险真实资金"), True),
        (tier, t("assurance tier", "保障层级"), False),
        ("256", t("bit hash-chained", "位哈希链"), False),
    ]
    cells = "".join(
        f'<div><span class="rl-proof__num{" rl-proof__num--ok" if ok else ""}">{_e(num)}</span>'
        f'<span class="rl-proof__label">{label}</span></div>'
        for num, label, ok in items
    )
    return f'    <div class="rl-proofbar">{cells}</div>'


def _tier_meter(release: dict[str, Any]) -> str:
    executed = bool((release.get("execution_evidence") or {}).get("bitget_order_id"))
    segments = [
        ("L0", t("sim-only", "仅模拟"), "rl-tier__seg--reached"),
        ("L1", t("demo-executed", "已执行模拟"), "rl-tier__seg--on" if executed else ""),
        ("L2", t("live-gated", "实盘受闸"), ""),
    ]
    segs = "".join(
        f'<div class="rl-tier__seg {cls}"><b>{_e(code)}</b>{label}</div>' for code, label, cls in segments
    )
    return f'    <div class="rl-tier">{segs}</div>'


def _short_id(value: object) -> str:
    raw = str(value or "")
    return raw if len(raw) <= 14 else raw[:6] + "…" + raw[-4:]


def _violation_telemetry(reason_code: object) -> str:
    raw = str(reason_code or "").strip()
    if not raw:
        return ""
    meta = None
    try:
        from redline.models import ReasonCode
        from redline.violations import REASON_META

        meta = REASON_META.get(ReasonCode(raw))
    except (ValueError, KeyError, ImportError):
        meta = None
    code_cls = " rl-badge--ok" if raw == "PASS" else (" rl-badge--fail" if (meta and meta.severity == "blocking") else "")
    code_badge = f'<span class="rl-badge{code_cls}">{_e(raw)}</span>'
    if meta is None:
        return f'<div class="rl-box"><dl class="rl-dl"><dt>reason_code</dt><dd>{code_badge}</dd></dl></div>'
    sev_cls = " rl-badge--fail" if meta.severity == "blocking" else ""
    return (
        '<div class="rl-box"><dl class="rl-dl">'
        f'<dt>reason_code</dt><dd>{code_badge}</dd>'
        f'<dt>severity</dt><dd><span class="rl-badge{sev_cls}">{_e(meta.severity)}</span></dd>'
        f'<dt>recoverable</dt><dd>{t("yes", "是") if meta.recoverable else t("no", "否")}</dd>'
        f'<dt>summary</dt><dd>{_e(meta.summary)}</dd>'
        "</dl></div>"
    )


def _symbol_link(symbol: object) -> str:
    raw = str(symbol or "").strip()
    if not raw:
        return _e("missing")
    return f'<a href="https://www.bitget.com/futures/usdt/{_e(raw)}" target="_blank" rel="noopener">{_e(raw)} &nearr;</a>'


def _script() -> str:
    return """
<script>
(() => {
  function L() { return document.documentElement.getAttribute("data-lang") === "zh" ? "zh" : "en"; }
  var STR = {
    offline: { en: "offline view \\u00b7 live actions need the served console", zh: "离线视图 \\u00b7 实时操作需在已部署的控制台进行" },
    session: { en: "session", zh: "会话" },
    notauth: { en: "not authenticated", zh: "未认证" },
    devlogin: { en: "Dev login", zh: "开发登录" },
    orpaste: { en: "or paste a token", zh: "或粘贴令牌" },
    copied: { en: "copied", zh: "已复制" },
    tokensaved: { en: "token saved", zh: "已保存令牌" },
    loginprompt: { en: "dev login as (blank = default):", zh: "开发登录身份（留空=默认）：" },
    loggedinas: { en: "logged in as ", zh: "已登录为 " },
    loggedout: { en: "logged out", zh: "已登出" },
    placing: { en: "placing demo order\\u2026", zh: "正在下模拟单\\u2026" },
    placed: { en: "demo order placed and reconciled", zh: "模拟单已下并完成对账" },
    reloadev: { en: "reload for evidence", zh: "刷新以查看证据" },
    jobword: { en: "job ", zh: "任务 " },
    timeout: { en: "timed out", zh: "超时" },
    attested: { en: "bundle attested", zh: "打包已认证" },
    actionfailed: { en: "action failed", zh: "操作失败" },
    nojobevents: { en: "No job events", zh: "暂无任务事件" },
    authenticated: { en: "authenticated", zh: "已认证" },
    devloginfailed: { en: "dev login failed", zh: "开发登录失败" },
    showcasefailed: { en: "showcase request failed", zh: "展示请求失败" },
    attestfailed: { en: "attest failed", zh: "认证失败" }
  };
  function S(k) { return STR[k][L()]; }
  function el(id) { return document.getElementById(id); }
  function spin() { var s = document.createElement("span"); s.className = "rl-spin"; return s; }
  function bold(txt) { var b = document.createElement("b"); b.textContent = txt; return b; }
  const tokenInput = el("redline-token");
  if (tokenInput && localStorage.getItem("redlineJudgeToken")) tokenInput.value = localStorage.getItem("redlineJudgeToken");
  const toastEl = el("rl-toast");
  let toastTimer = null;
  function toast(msg, kind) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.className = "rl-toast is-on" + (kind ? " rl-toast--" + kind : "");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastEl.className = "rl-toast"; }, 3500);
  }
  function token() { return tokenInput ? tokenInput.value.trim() : ""; }
  async function api(path, options = {}) {
    const t = token();
    const headers = Object.assign({}, options.headers || {}, t ? { "X-Redline-Token": t } : {});
    return fetch(path, Object.assign({ credentials: "same-origin" }, options, { headers }));
  }
  // all dynamic values below go in via textContent / built nodes (never innerHTML) — XSS-safe.
  async function refreshSession() {
    const e = el("rl-session");
    if (!e) return;
    if (location.protocol === "file:") {
      e.className = "rl-live rl-live--err"; e.textContent = S("offline"); return;
    }
    try {
      const r = await api("/v1/auth/me");
      if (!r.ok) throw new Error(String(r.status));
      const data = await r.json();
      const p = data.principal || {};
      e.className = "rl-live";
      e.replaceChildren(document.createTextNode(S("session") + ": "), bold(p.principal_id || S("authenticated")));
      if (Array.isArray(p.scopes) && p.scopes.length) e.append(" \\u00b7 " + p.scopes.join(" "));
    } catch (err) {
      e.className = "rl-live rl-live--err";
      e.replaceChildren(document.createTextNode(S("notauth") + " \\u00b7 "), bold(S("devlogin")), document.createTextNode(" " + S("orpaste")));
    }
  }
  function busy(button, on) { if (!button) return; button.setAttribute("aria-busy", on ? "true" : "false"); button.disabled = on; }
  async function refreshEvents(releaseId, jobId) {
    const target = el("job-events");
    const r = await api("/v1/release-candidates/" + releaseId + "/jobs/" + jobId + "/events.ndjson");
    const text = await r.text();
    if (target) target.textContent = text || S("nojobevents");
    const status = el("rl-job-status");
    const last = (text || "").trim().split("\\n").pop() || "";
    if (status && last) status.replaceChildren(spin(), document.createTextNode(" " + last.slice(0, 90)));
  }
  async function pollJob(releaseId, jobId) {
    for (let i = 0; i < 30; i += 1) {
      await refreshEvents(releaseId, jobId);
      const r = await api("/v1/release-candidates/" + releaseId + "/jobs/" + jobId);
      const job = await r.json();
      if (["succeeded", "failed", "cancelled"].includes(job.status)) return job;
      await new Promise((res) => setTimeout(res, 1000));
    }
    return null;
  }
  document.addEventListener("click", async (event) => {
    const copyBtn = event.target.closest("[data-copy]");
    if (copyBtn) {
      try { await navigator.clipboard.writeText(copyBtn.dataset.copy); const prev = copyBtn.textContent; copyBtn.textContent = S("copied"); setTimeout(() => { copyBtn.textContent = prev; }, 1200); } catch (e) {}
      return;
    }
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "save-token") {
      if (tokenInput) localStorage.setItem("redlineJudgeToken", tokenInput.value.trim());
      toast(S("tokensaved"), "ok"); refreshSession(); return;
    }
    const releaseId = button.dataset.releaseId;
    busy(button, true);
    try {
      if (action === "dev-login") {
        const login = window.prompt(S("loginprompt"), "") || undefined;
        const r = await api("/v1/auth/dev-login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(login ? { login } : {}) });
        if (!r.ok) throw new Error(S("devloginfailed") + " (" + r.status + ")");
        const data = await r.json();
        toast(S("loggedinas") + ((data.principal || {}).principal_id || "ok"), "ok");
        await refreshSession();
      } else if (action === "logout") {
        await api("/v1/auth/logout", { method: "POST" });
        toast(S("loggedout"), "ok"); await refreshSession();
      } else if (action === "run-showcase") {
        const status = el("rl-job-status");
        if (status) { status.className = "rl-live"; status.replaceChildren(spin(), document.createTextNode(" " + S("placing"))); }
        const r = await api("/v1/release-candidates/" + releaseId + "/jobs/showcase-order", { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": "judge-console-" + Date.now() }, body: JSON.stringify({ side: "buy", size: "0.0001" }) });
        if (!r.ok) throw new Error(S("showcasefailed") + " (" + r.status + ")");
        const job = await r.json();
        const final = await pollJob(releaseId, job.job_id);
        if (final && final.status === "succeeded") {
          toast(S("placed"), "ok");
          if (status) status.replaceChildren(bold(final.status), document.createTextNode(" \\u00b7 " + S("reloadev")));
        } else {
          toast(S("jobword") + (final ? final.status : S("timeout")), "err");
          if (status) { status.className = "rl-live rl-live--err"; status.replaceChildren(bold(final ? final.status : S("timeout"))); }
        }
      } else if (action === "attest") {
        const r = await api("/v1/release-candidates/" + releaseId + "/attest", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
        if (!r.ok) throw new Error(S("attestfailed") + " (" + r.status + ")");
        toast(S("attested"), "ok"); setTimeout(() => window.location.reload(), 700);
      }
    } catch (err) {
      toast(err.message || S("actionfailed"), "err");
    } finally {
      busy(button, false);
    }
  });
  window.addEventListener("rl-lang", refreshSession);
  refreshSession();
  // telemetry readouts boot up on load (reduced-motion: skip, leave final value)
  if (!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches)) {
    var nums = document.querySelectorAll(".rl-proof__num");
    for (var ni = 0; ni < nums.length; ni++) (function (e2) {
      var raw = (e2.textContent || "").trim();
      if (!/^[0-9]+$/.test(raw)) return;
      var target = parseInt(raw, 10), pad = raw.length, t0 = null;
      function step(ts) { if (!t0) t0 = ts; var p = Math.min(1, (ts - t0) / 700); e2.textContent = String(Math.round(target * p)).padStart(pad, "0"); if (p < 1) requestAnimationFrame(step); else e2.textContent = raw; }
      e2.textContent = "".padStart(pad, "0"); requestAnimationFrame(step);
    })(nums[ni]);
  }
})();
</script>
"""


def _metric(label: str, value: object) -> str:
    return f'<div class="rl-box"><span class="rl-box__label">{label}</span><strong>{value}</strong></div>'


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
        f'<button type="button" class="rl-copy" data-copy="{_e(raw)}" aria-label="copy {_e(raw)}">{t("copy", "复制")}</button></span>'
    )


def _hash_field(value: object) -> str:
    raw = str(value or "")
    if not raw or raw in {"none", "missing"}:
        return _e(raw or "none")
    short = raw if len(raw) <= 22 else raw[:12] + "…" + raw[-6:]
    return (
        f'<span class="rl-idcopy"><span class="rl-mono" title="{_e(raw)}">{_e(short)}</span>'
        f'<button type="button" class="rl-copy" data-copy="{_e(raw)}" aria-label="copy full hash">{t("copy", "复制")}</button></span>'
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
