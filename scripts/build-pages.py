#!/usr/bin/env python3
"""Build the static GitHub Pages site: offline, zero-secret, self-contained.

Mirrors the judge-facing offline pages (verify/tamper-check + the evidence
comparison) and adds a small bilingual landing page. No network, no secrets,
no server: the same files a judge can open from a fresh clone, served as a URL.
"""
from __future__ import annotations

import re
from pathlib import Path

from redline.render import (
    REPO_URL,
    _I18N_SCRIPT,
    _inline_css,
    _lang_toggle,
    render_verify_html,
    t,
)

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SITE.mkdir(exist_ok=True)

# small cross-page nav injected into the leaf pages (relative links, bilingual)
NAV = (
    '<nav class="rl-row" aria-label="site">'
    f'<a class="rl-ghbtn" href="index.html">{t("Home", "首页")}</a>'
    f'<a class="rl-ghbtn" href="verify.html">{t("Verify", "校验")}</a>'
    f'<a class="rl-ghbtn" href="evidence.html">{t("Evidence", "证据")}</a>'
    "</nav>"
)


def _with_nav(html: str) -> str:
    return re.sub(r'(<main class="rl-main"[^>]*>)', lambda m: m.group(1) + NAV, html, count=1)


# verify / tamper-check page, rendered fresh (offline, pure-JS)
(SITE / "verify.html").write_text(_with_nav(render_verify_html()), encoding="utf-8")

# evidence comparison page: reuse the checked-in golden (already rendered, zero-secret)
_evidence = (ROOT / "artifacts/release-demo/current/evidence.html").read_text(encoding="utf-8")
(SITE / "evidence.html").write_text(_with_nav(_evidence), encoding="utf-8")

# landing page, same inline CSS + bilingual toggle as the rest of the surface
index = (
    '<!doctype html><html lang="zh-Hans" data-lang="zh"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    f"<title>Playbook Redline</title><style>{_inline_css()}</style></head>"
    f'<body><main class="rl-main">{_lang_toggle()}'
    '<h1 class="rl-macro rl-caret">Playbook Redline</h1>'
    f'<p class="rl-label">{t("pre-release control gate for AI-edited trading strategies", "AI 改写交易策略的发布前校验闸")}</p>'
    f'<p class="rl-muted">{t("Offline, zero-secret, paptrading demo. No login, no server.", "离线、零密钥、paptrading 演示。免登录，无需服务器。")}</p>'
    "<hr>"
    '<div class="rl-row">'
    f'<a class="rl-btn rl-btn--hazard" href="verify.html">{t("Verify a receipt (offline)", "离线验一张回执")}</a>'
    f'<a class="rl-btn" href="evidence.html">{t("Judge evidence", "评委证据页")}</a>'
    f'<a class="rl-ghbtn" href="{REPO_URL}">{t("View on GitHub", "在 GitHub 查看")}</a>'
    "</div>"
    f"</main>{_I18N_SCRIPT}</body></html>"
)
(SITE / "index.html").write_text(index, encoding="utf-8")

print("site built:", ", ".join(sorted(p.name for p in SITE.iterdir())))
