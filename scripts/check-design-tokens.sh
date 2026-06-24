#!/usr/bin/env bash
# Deterministic "on-brand" lint for the Tactical Telemetry design system.
# Hardened per cross-model review (Codex): pins exact brand tokens, catches all
# radius / shadow / gradient / non-token-color forms, no fake-pass. Exit 0 = clean.
set -euo pipefail

CSS="${1:-src/redline/static/redline.css}"
if [ ! -f "$CSS" ]; then echo "FAIL: css not found: $CSS" >&2; exit 2; fi

fail=0
note() { echo "DESIGN-TOKEN VIOLATION ($CSS): $1" >&2; fail=1; }

ROOT="$(perl -0777 -ne 'print $1 if /(:root\s*\{.*?\})/s' "$CSS")"
BODY="$(perl -0777 -pe 's/:root\s*\{.*?\}//s' "$CSS")"
[ -n "$ROOT" ] || note "no :root token block found"

# A) canonical brand tokens must be present with EXACT values (true on-brand pin)
req() { printf '%s' "$ROOT" | grep -qiE -- "$1:[[:space:]]*$2([^0-9A-Fa-f]|$)" || note "token $1 missing or != $2"; }
req '--rl-bg'      '#0C0D0F'
req '--rl-surface' '#15161A'
req '--rl-fg'      '#EAEAEA'
req '--rl-muted'   '#8A8A92'
req '--rl-hazard'  '#EC5054'
req '--rl-pass'    '#4FC97A'
printf '%s' "$ROOT" | grep -qiE -- '--rl-radius:[[:space:]]*0([^0-9]|;|$)' || note "--rl-radius must be 0"

# B) no non-zero radius anywhere (any *radius property whose value contains a non-zero digit)
if grep -nE '[a-zA-Z-]*radius:[^;{}]*[1-9]' "$CSS" >/dev/null 2>&1; then note "non-zero border-radius (90 degrees only)"; fi

# C) gradients: allow ONLY hard-stop repeating-linear-gradient (hazard stripes / CRT scanlines, design §5.4/§5.5.9);
#    ban all smooth shading gradients (linear/radial/conic, repeating-radial/conic).
if grep -oEi '(repeating-)?(linear|radial|conic)-gradient' "$CSS" | grep -viE '^repeating-linear-gradient$' | grep -q .; then note "smooth/forbidden gradient (only hard-stop repeating-linear-gradient allowed)"; fi
# C2) a repeating-linear-gradient must carry explicit length stops (px/%/em); a stop-less one is a smooth gradient in disguise.
if grep -iE 'repeating-linear-gradient' "$CSS" | grep -viE 'repeating-linear-gradient\([^;{}]*[0-9]+(px|%|rem|em)' | grep -q .; then note "repeating-linear-gradient without hard length stops (smooth-gradient abuse)"; fi

# D) no shadows at all (soft or hard) and no drop-shadow filter
if grep -nE 'box-shadow:[[:space:]]*[^;}]+' "$CSS" | grep -viE 'box-shadow:[[:space:]]*none[[:space:]]*(;|\}|!important|$)' >/dev/null 2>&1; then note "box-shadow (no shadows; use 1px solid lines)"; fi
if grep -nEi 'drop-shadow\(' "$CSS" >/dev/null 2>&1; then note "drop-shadow filter"; fi

# E) component CSS (outside :root) must use var(--rl-*) tokens, not raw colors
if printf '%s' "$BODY" | grep -nE '#[0-9a-fA-F]{3,8}' >/dev/null 2>&1; then note "raw hex outside :root (use var(--rl-*))"; fi
if printf '%s' "$BODY" | grep -nEi 'hsl\(|oklch\(|oklab\(|lab\(|lch\(|hwb\(|color\(' >/dev/null 2>&1; then note "non-token color function outside :root"; fi
# rgb()/rgba() allowed only as neutral white/black texture overlays (scanline/noise)
if printf '%s' "$BODY" | grep -nEi 'rgba?\(' | grep -viE 'rgba?\([[:space:]]*(255[[:space:]]*,[[:space:]]*255[[:space:]]*,[[:space:]]*255|0[[:space:]]*,[[:space:]]*0[[:space:]]*,[[:space:]]*0)' >/dev/null 2>&1; then note "non-neutral rgb()/rgba() outside :root (only white/black overlays allowed)"; fi
# named CSS colors used as values (transparent/currentColor/inherit/initial/unset/none are fine)
# named color used as any value token (property-agnostic: catches border/outline shorthand too)
if printf '%s' "$BODY" | grep -nEi '[[:space:]:](black|white|red|green|blue|yellow|orange|purple|pink|gray|grey|cyan|magenta|silver|gold|navy|teal|olive|maroon|lime|aqua|fuchsia|brown|coral|crimson|indigo|violet|salmon|khaki|turquoise)([^a-zA-Z0-9_-]|$)' >/dev/null 2>&1; then note "named color outside :root (use var(--rl-*))"; fi

if [ "$fail" -eq 0 ]; then echo "design tokens OK: $CSS"; exit 0; fi
exit 1
