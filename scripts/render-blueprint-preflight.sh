#!/usr/bin/env bash
set -euo pipefail

BLUEPRINT="${1:-render.yaml}"

if [[ ! -f "$BLUEPRINT" ]]; then
  echo "blueprint file not found: $BLUEPRINT" >&2
  exit 66
fi

if command -v render >/dev/null 2>&1; then
  render blueprints validate "$BLUEPRINT"
  exit 0
fi

if [[ -z "${RENDER_API_KEY:-}" || -z "${RENDER_OWNER_ID:-}" ]]; then
  cat >&2 <<'EOF'
Render CLI is not installed and RENDER_API_KEY / RENDER_OWNER_ID are not set.

Install the Render CLI and run:
  render blueprints validate render.yaml

Or set:
  RENDER_API_KEY=<render api key>
  RENDER_OWNER_ID=<render workspace owner id>
  make render-preflight
EOF
  exit 64
fi

curl -fsS \
  --request POST \
  --url "https://api.render.com/v1/blueprints/validate" \
  --header "accept: application/json" \
  --header "authorization: Bearer ${RENDER_API_KEY}" \
  --form "ownerId=${RENDER_OWNER_ID}" \
  --form "file=@${BLUEPRINT};type=application/x-yaml" \
  | python -m json.tool
