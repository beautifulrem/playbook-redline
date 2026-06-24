#!/usr/bin/env python3
"""Render a self-contained gallery of the Redline design-system components.

The single CSS source (src/redline/static/redline.css) is INLINED so the page is
offline self-contained — the same path evidence pages use. This lets chrome-devtools
render it via file:// and verify the inline path + zero-secret invariant.

Usage: gen-gallery.py [out.html]   (default: /tmp/redline-gallery.html)
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from redline.render import randomart_svg  # single source for the SSH-randomart seal

CSS = Path("src/redline/static/redline.css").read_text(encoding="utf-8")

BODY = """
<main class="rl-main">
  <h1 class="rl-macro">REDLINE</h1>
  <p class="rl-label">Tactical Telemetry — design system gallery · DEMO · paptrading:1 · non-mainnet</p>
  <hr>

  <h2 class="rl-sec">Status band</h2>
  <div class="rl-band rl-band--pass">
    <span class="rl-band__verdict">PASS</span>
    <span class="rl-band__meta">REPLAYED · CHAINED · SIGNED · TIER L1</span>
  </div>
  <div class="rl-band">
    <span class="rl-band__verdict">WITHHELD</span>
    <span class="rl-band__meta">NEW_BLOCK_BREACH · BITGET NOT CALLED</span>
  </div>

  <h2 class="rl-sec">Telemetry</h2>
  <div class="rl-box">
    <dl class="rl-dl">
      <dt>receipt_hash</dt><dd class="rl-mono">sha256:426312eeddd82c552a747df781bf12e2573280fcb7b9ab442f277a2fb76645d6</dd>
      <dt>verdict_tier</dt><dd>ALLOW</dd>
      <dt>bitget_order_id</dt><dd class="rl-mono">1453***8417</dd>
      <dt>response_hash</dt><dd class="rl-mono">sha256:9d7da0b24514ee1724d80ba8383514781265f59678bcfacea63e1030e46e8d5c</dd>
    </dl>
  </div>

  <h2 class="rl-sec">Badges</h2>
  <p>
    <span class="rl-badge rl-badge--ok">ATTESTED</span>
    <span class="rl-badge">RELEASE_READY</span>
    <span class="rl-badge rl-badge--fail">BLOCKED</span>
    <span class="rl-badge">QUEUED</span>
  </p>

  <h2 class="rl-sec">Safety grid</h2>
  <div class="rl-grid rl-grid--3">
    <div class="rl-box"><span class="rl-box__label">release freeze</span><strong>FALSE</strong></div>
    <div class="rl-box"><span class="rl-box__label">execution freeze</span><strong>FALSE</strong></div>
    <div class="rl-box"><span class="rl-box__label">mainnet enabled</span><strong class="rl-c-hazard">FALSE</strong></div>
  </div>

  <h2 class="rl-sec">Release table</h2>
  <div class="rl-scroll-x">
  <table class="rl-table">
    <thead><tr><th scope="col">release</th><th scope="col">state</th><th scope="col">canonical order</th><th scope="col">tier</th><th scope="col">attestation</th></tr></thead>
    <tbody>
      <tr><td>release-demo-good</td><td><span class="rl-badge rl-badge--ok">release_ready</span></td><td class="rl-mono">1453***8417</td><td>L1</td><td><span class="rl-badge rl-badge--ok">ATTESTED</span></td></tr>
      <tr><td>release-demo-bad</td><td><span class="rl-badge rl-badge--fail">blocked_withheld</span></td><td>none</td><td>L0</td><td><span class="rl-badge">missing</span></td></tr>
    </tbody>
  </table>
  </div>

  <h2 class="rl-sec">Chain walk — verifiable chain</h2>
  <div class="rl-chain">
    <div class="rl-chain__node"><span class="rl-chain__label">edit</span><span class="rl-chain__hash">sha256:0a91…7e2c</span><span class="rl-chain__st--ok">✔ provenance</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">verdict</span><span class="rl-chain__hash">sha256:4263…645d6</span><span class="rl-chain__st--ok">✔ replayed</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">approval</span><span class="rl-chain__hash">sha256:b8e1…09af</span><span class="rl-chain__st--ok">✔ digest burn</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">execution</span><span class="rl-chain__hash">1453***8417</span><span class="rl-chain__st--ok">✔ bitget</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">attestation</span><span class="rl-chain__hash">merkle 9d7d…8d5c</span><span class="rl-chain__st--ok">✔ ed25519</span></div>
  </div>
  <p class="rl-label">任一节点 ✗ → 该隔间翻红 + 定位 first failed link：</p>
  <div class="rl-chain">
    <div class="rl-chain__node"><span class="rl-chain__label">edit</span><span class="rl-chain__hash">sha256:0a91…7e2c</span><span class="rl-chain__st--ok">✔ provenance</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">verdict</span><span class="rl-chain__hash">sha256:4263…645d6</span><span class="rl-chain__st--ok">✔ replayed</span></div>
    <div class="rl-chain__node rl-chain__node--fail"><span class="rl-chain__label">approval</span><span class="rl-chain__hash">sha256:dead…beef</span><span class="rl-chain__st--bad">✗ digest mismatch</span><span class="rl-chain__flag">first failed</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">execution</span><span class="rl-chain__hash">— halted —</span><span class="rl-chain__st--skip">not reached</span></div>
    <div class="rl-chain__node"><span class="rl-chain__label">attestation</span><span class="rl-chain__hash">— none —</span><span class="rl-chain__st--skip">not reached</span></div>
  </div>

  <h2 class="rl-sec">Proofbar</h2>
  <div class="rl-proofbar">
    <div><span class="rl-proof__num">06</span><span class="rl-proof__label">crash tapes replayed</span></div>
    <div><span class="rl-proof__num rl-proof__num--ok">00</span><span class="rl-proof__label">live funds at risk</span></div>
    <div><span class="rl-proof__num">L1</span><span class="rl-proof__label">assurance tier</span></div>
    <div><span class="rl-proof__num">256</span><span class="rl-proof__label">bit hash-chained</span></div>
  </div>

  <h2 class="rl-sec">Tier meter</h2>
  <div class="rl-tier">
    <div class="rl-tier__seg rl-tier__seg--reached"><b>L0</b>sim-only</div>
    <div class="rl-tier__seg rl-tier__seg--on"><b>L1</b>demo-executed</div>
    <div class="rl-tier__seg"><b>L2</b>live-gated</div>
  </div>

  <h2 class="rl-sec">Command block — zero-secret verify</h2>
  <div class="rl-cmd">
    <div class="rl-cmd__head"><span>verify on a clean machine</span><span>no secrets · offline</span></div>
    <div class="rl-cmd__body">
      <samp class="rl-cmd__cmt">改一字节 → 非零退出 + 精确 violation code</samp>
      <samp>uv run redline verify-chain &lt;release_dir&gt; --json</samp>
      <samp>uv run redline verify-release-attestation &lt;attestation&gt; --bundle &lt;bundle&gt; --trusted-public-key &lt;ed25519-public:…&gt;</samp>
      <samp>scripts/tamper-demo.sh</samp>
    </div>
  </div>

  <h2 class="rl-sec">Tamper control</h2>
  <div class="rl-tamper">
    <div class="rl-tamper__row">
      <span class="rl-tamper__k">receipt_hash</span>
      <samp class="rl-tamper__val">sha256:426312eeddd82c552a747df781bf12e2573280fcb7b9ab442f277a2fb76645d6</samp>
      <button class="rl-btn rl-btn--hazard" type="button">flip byte</button>
    </div>
  </div>

  <h2 class="rl-sec">Warning stripe</h2>
  <div class="rl-stripe"><span class="rl-stripe__msg">⚠ execution freeze active · demo execution disabled</span></div>

  <!--MOTION-->

  <hr>
  <p class="rl-muted">Redline verdict 授权了这笔 Bitget 模拟盘订单；这不是 Bitget Playbook 正式发布。 <span class="rl-faint">REV 2.6 · UNIT RL-01</span></p>
</main>
"""

DOC = (
    '<!doctype html>\n<html lang="en">\n<head>\n'
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    "<title>Redline — Design System</title>\n"
    "<style>{css}</style>\n</head>\n<body>{body}</body>\n</html>\n"
)


def fingerprint_svg(seed: str, size: int = 42, cells: int = 5) -> str:
    """A deterministic identicon-style glyph rendered from a hash — a unique 'image' per hash.
    Inline SVG (no xmlns → valid HTML5), fill=currentColor so it inherits the wrapper's brand color."""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    pad = 3.0
    cell = (size - 2 * pad) / cells
    half = (cells + 1) // 2
    rects = []
    for row in range(cells):
        for col in range(half):
            if digest[(row * half + col) % len(digest)] & 1:
                for mirrored in {col, cells - 1 - col}:  # horizontal mirror → glyph-like
                    x = pad + mirrored * cell
                    y = pad + row * cell
                    rects.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{cell:.1f}" height="{cell:.1f}"/>')
    return (
        f'<svg viewBox="0 0 {size} {size}" fill="currentColor" role="img" aria-label="hash fingerprint">'
        + "".join(rects)
        + "</svg>"
    )


def _motion_section() -> str:
    h_pass = "sha256:426312eeddd82c552a747df781bf12e2573280fcb7b9ab442f277a2fb76645d6"
    h_resp = "sha256:9d7da0b24514ee1724d80ba8383514781265f59678bcfacea63e1030e46e8d5c"
    h_bad = "sha256:deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234"
    nodes = "".join(
        f'<div class="rl-chain__node"><span class="rl-chain__label">{lbl}</span>'
        f'<span class="rl-chain__hash">{hsh}</span><span class="rl-chain__st--ok">✔ {st}</span></div>'
        for lbl, hsh, st in [
            ("edit", "sha256:0a91…7e2c", "provenance"),
            ("verdict", "sha256:4263…645d6", "replayed"),
            ("approval", "sha256:b8e1…09af", "digest burn"),
            ("execution", "1453***8417", "bitget"),
            ("attestation", "merkle 9d7d…8d5c", "ed25519"),
        ]
    )
    return f"""
  <h2 class="rl-sec">Motion &amp; imagery</h2>

  <p class="rl-label">动效 · 在浏览器里看（prefers-reduced-motion 下自动静止）</p>
  <div class="rl-crt rl-box">
    <div class="rl-band rl-band--pass">
      <span class="rl-band__verdict rl-scanin">PASS</span>
      <span class="rl-band__meta rl-scanin rl-scanin--2 rl-caret">VERIFYING · REPLAYED · CHAINED · SIGNED</span>
    </div>
  </div>

  <h2 class="rl-sec">Chain light-up · 链路逐节点点亮</h2>
  <div class="rl-chain rl-chain--live">{nodes}</div>

  <h2 class="rl-sec">Redline seal · SSH randomart 印章（hash→可视指纹，篡改即变形）</h2>
  <div class="rl-seals">
    <div class="rl-seal rl-seal--pass"><span class="rl-seal__art">{randomart_svg(h_pass)}</span><span class="rl-seal__body"><span class="rl-seal__stamp">VERIFIED</span><span class="rl-seal__algo">SSH randomart · receipt</span><span class="rl-seal__hash">{h_pass[:24]}…</span></span></div>
    <div class="rl-seal"><span class="rl-seal__art">{randomart_svg(h_resp)}</span><span class="rl-seal__body"><span class="rl-seal__stamp">RESPONSE</span><span class="rl-seal__algo">SSH randomart · response</span><span class="rl-seal__hash">{h_resp[:24]}…</span></span></div>
    <div class="rl-seal rl-seal--void"><span class="rl-seal__art">{randomart_svg(h_bad)}</span><span class="rl-seal__body"><span class="rl-seal__stamp">VOID</span><span class="rl-seal__algo">SSH randomart · tampered</span><span class="rl-seal__hash">{h_bad[:24]}…</span></span></div>
  </div>

  <h2 class="rl-sec">Verification checklist · 替代单调 summary</h2>
  <div class="rl-box"><ul class="rl-check">
    <li>max_drawdown ≤ 0.08000000 · observed 0.00498134</li>
    <li>no_entry_when ≤ 0 · observed 0</li>
    <li>replay_wellformed == 24 · observed 24</li>
    <li>trade_budget ≤ 20.00000000 · observed 1.00000000</li>
    <li class="rl-check--no">new_block_breach · observed TRUE → WITHHELD</li>
  </ul></div>

  <h2 class="rl-sec">Metric bars · observed vs threshold（载入充能）</h2>
  <div class="rl-box">
    <div class="rl-meter"><span class="rl-meter__k">max_drawdown</span><span class="rl-bar"><i style="width:6%"></i></span><span class="rl-meter__v">.005 / .08</span></div>
    <div class="rl-meter"><span class="rl-meter__k">trade_budget</span><span class="rl-bar"><i style="width:5%"></i></span><span class="rl-meter__v">1.0 / 20</span></div>
    <div class="rl-meter"><span class="rl-meter__k">replay_wellformed</span><span class="rl-bar"><i style="width:100%"></i></span><span class="rl-meter__v">24 / 24</span></div>
    <div class="rl-meter"><span class="rl-meter__k">new_block_breach</span><span class="rl-bar rl-bar--over"><i style="width:100%"></i></span><span class="rl-meter__v">BREACH</span></div>
  </div>
"""


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/redline-gallery.html")
    body = BODY.replace("<!--MOTION-->", _motion_section())
    out.write_text(DOC.format(css=CSS, body=body), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
