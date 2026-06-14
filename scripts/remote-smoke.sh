#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${REDLINE_REMOTE_BASE_URL:-${REDLINE_SERVICE_BASE_URL:-}}"
TOKEN="${REDLINE_REMOTE_TOKEN:-${REDLINE_SERVICE_TOKEN:-}}"

if [[ -z "$BASE_URL" ]]; then
  echo "REDLINE_REMOTE_BASE_URL or REDLINE_SERVICE_BASE_URL is required" >&2
  exit 64
fi
if [[ -z "$TOKEN" ]]; then
  echo "REDLINE_REMOTE_TOKEN or REDLINE_SERVICE_TOKEN is required" >&2
  exit 64
fi

uv run python scripts/frontend-demo-flow.py \
  --base-url "$BASE_URL" \
  --token "$TOKEN" \
  --package-path "${REDLINE_REMOTE_PACKAGE_PATH:-fixtures/demo_pack}" \
  --replay-package "${REDLINE_REMOTE_REPLAY_PACKAGE:-fixtures/demo_pack}" \
  --allow-demo-baseline-genesis
