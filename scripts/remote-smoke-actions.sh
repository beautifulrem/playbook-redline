#!/usr/bin/env bash
set -euo pipefail

REPO="${REDLINE_REMOTE_GITHUB_REPO:-beautifulrem/playbook-redline}"
WORKFLOW="${REDLINE_REMOTE_WORKFLOW:-redline-ci.yml}"
REF="${REDLINE_REMOTE_REF:-main}"
BASE_URL="${REDLINE_REMOTE_BASE_URL:-}"
TOKEN="${REDLINE_REMOTE_TOKEN:-}"
FRONTEND_ORIGIN="${REDLINE_REMOTE_FRONTEND_ORIGIN:-}"
RATE_LIMIT_PROBES="${REDLINE_REMOTE_RATE_LIMIT_PROBES:-0}"

if [[ -z "$BASE_URL" ]]; then
  echo "REDLINE_REMOTE_BASE_URL is required" >&2
  exit 64
fi
if [[ -z "$TOKEN" ]]; then
  echo "REDLINE_REMOTE_TOKEN is required" >&2
  exit 64
fi
if [[ -z "$FRONTEND_ORIGIN" ]]; then
  echo "REDLINE_REMOTE_FRONTEND_ORIGIN is required" >&2
  exit 64
fi
if ! [[ "$RATE_LIMIT_PROBES" =~ ^[0-9]+$ ]]; then
  echo "REDLINE_REMOTE_RATE_LIMIT_PROBES must be a non-negative integer" >&2
  exit 64
fi

echo "Configuring remote smoke secrets for ${REPO}"
printf "%s" "$BASE_URL" | gh secret set REDLINE_REMOTE_BASE_URL --repo "$REPO"
printf "%s" "$TOKEN" | gh secret set REDLINE_REMOTE_TOKEN --repo "$REPO"
printf "%s" "$FRONTEND_ORIGIN" | gh secret set REDLINE_REMOTE_FRONTEND_ORIGIN --repo "$REPO"

echo "Triggering ${WORKFLOW} on ${REF} with remote_smoke=true"
gh workflow run "$WORKFLOW" \
  --repo "$REPO" \
  --ref "$REF" \
  -f remote_smoke=true \
  -f "remote_rate_limit_probes=${RATE_LIMIT_PROBES}"

sleep 5
run_json="$(
  gh run list \
    --repo "$REPO" \
    --workflow "$WORKFLOW" \
    --event workflow_dispatch \
    --branch "$REF" \
    --limit 1 \
    --json databaseId,url
)"
run_id="$(python -c 'import json,sys; runs=json.load(sys.stdin); print(runs[0]["databaseId"] if runs else "")' <<<"$run_json")"
run_url="$(python -c 'import json,sys; runs=json.load(sys.stdin); print(runs[0]["url"] if runs else "")' <<<"$run_json")"
if [[ -z "$run_id" ]]; then
  echo "Could not locate the triggered workflow_dispatch run" >&2
  exit 70
fi

echo "Remote smoke workflow: ${run_url}"
gh run watch "$run_id" --repo "$REPO" --exit-status
