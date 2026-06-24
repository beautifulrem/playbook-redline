#!/usr/bin/env bash
# Deterministic frontend render gate (the "no weird wraps / overflow" quality bar, systematized).
# Generates the design-system gallery + the evidence comparison + the verify/tamper page, then:
#   - design tokens are on-brand (check-design-tokens.sh)
#   - evidence + verify pages are offline self-contained / zero-secret (check-frontend-zero-secret.sh)
#   - every page renders with 0 console-errors, no horizontal page overflow, and no element
#     overflowing its own box, at desktop (1280) and mobile (390).
# Requires a local Chromium-family browser (Helium) + puppeteer-core; SKIPs cleanly if absent.
set -euo pipefail
cd "$(dirname "$0")/.."

HELIUM="/Applications/Helium.app/Contents/MacOS/Helium"
PC="$(ls -d "$HOME"/.npm/_npx/*/node_modules/puppeteer-core 2>/dev/null | head -1 || true)"
if [ ! -x "$HELIUM" ] || [ -z "$PC" ]; then
  echo "SKIP frontend render gate: need Helium + puppeteer-core (local/browser-only check)"; exit 0
fi
NM="$(dirname "$PC")"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

bash scripts/check-design-tokens.sh src/redline/static/redline.css

uv run python scripts/gen-gallery.py "$OUT/gallery.html" >/dev/null
uv run python -c "from pathlib import Path; from redline.render import render_verify_html; Path('$OUT/verify.html').write_text(render_verify_html(), encoding='utf-8')"
uv run python - "$OUT" <<'PY'
import sys
from pathlib import Path
from redline.render import render_evidence_comparison_html, load_evidence_panel
from redline.verifier import load_receipt
out = Path(sys.argv[1])
current = Path("artifacts/release-demo/current"); runs = current / "service" / "runs"
dirs = sorted(p for p in runs.iterdir() if p.is_dir() and (p / "receipt.json").exists())
good = next(p for p in dirs if (p / "execution-evidence.json").exists())
bad = next(p for p in dirs if (lambda s: getattr(s, "value", s) == "withheld" or str(s).upper().endswith("WITHHELD"))(load_receipt(p / "receipt.json").result.status))
html = render_evidence_comparison_html(load_evidence_panel(good, title="good"), load_evidence_panel(bad, title="bad"))
(out / "evidence.html").write_text(html, encoding="utf-8")
PY

bash scripts/check-frontend-zero-secret.sh "$OUT/evidence.html"
bash scripts/check-frontend-zero-secret.sh "$OUT/verify.html"

NODE_PATH="$NM" node scripts/_frontend-render-check.cjs "$OUT/gallery.html" "$OUT/evidence.html" "$OUT/verify.html"
echo "frontend render gate OK"
