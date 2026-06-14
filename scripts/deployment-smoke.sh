#!/usr/bin/env bash
set -euo pipefail

MODE="${REDLINE_DEPLOYMENT_SMOKE_MODE:-docker}"
PORT="${REDLINE_DEPLOYMENT_SMOKE_PORT:-8093}"
TOKEN="${REDLINE_SERVICE_TOKEN:-}"
if [[ -z "$TOKEN" || "$TOKEN" == "redline-demo" || "$TOKEN" == "redline-smoke" || "$TOKEN" == "test-token" || "${#TOKEN}" -lt 32 ]]; then
  TOKEN="$(python - <<'PY'
import secrets

print(secrets.token_urlsafe(32))
PY
)"
fi
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/redline-deploy-smoke.XXXXXX")"
IMAGE="playbook-redline-service:smoke"
CONTAINER="redline-service-smoke-${PORT}"

cleanup() {
  status=$?
  if [[ "$MODE" == "docker" ]] && command -v docker >/dev/null 2>&1; then
    if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
      if [[ "$status" -ne 0 ]]; then
        docker logs "$CONTAINER" >&2 || true
      fi
      docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT

wait_for_health() {
  python - "$PORT" <<'PY'
from __future__ import annotations

import json
import sys
import time
import urllib.request

port = sys.argv[1]
url = f"http://127.0.0.1:{port}/health"
deadline = time.monotonic() + 60
last_error: Exception | None = None
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if payload.get("ok") is True:
            raise SystemExit(0)
    except Exception as exc:  # pragma: no cover - shell smoke helper
        last_error = exc
        time.sleep(0.5)
raise RuntimeError(f"service did not become healthy: {last_error}")
PY
}

case "$MODE" in
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "docker is required for REDLINE_DEPLOYMENT_SMOKE_MODE=docker" >&2
      exit 127
    fi
    docker build -t "$IMAGE" .
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d \
      --name "$CONTAINER" \
      -e REDLINE_SERVICE_ENV=production \
      -e REDLINE_SERVICE_TOKEN="$TOKEN" \
      -e REDLINE_SERVICE_CORS_ORIGINS=http://localhost:3000 \
      -p "127.0.0.1:${PORT}:8080" \
      "$IMAGE" >/dev/null
    ;;
  local)
    REDLINE_SERVICE_ENV=production \
    REDLINE_SERVICE_ROOT="$ROOT/state" \
    REDLINE_SERVICE_TOKEN="$TOKEN" \
    REDLINE_SERVICE_CORS_ORIGINS=http://localhost:3000 \
    REDLINE_SERVICE_HOST=127.0.0.1 \
    REDLINE_SERVICE_PORT="$PORT" \
      uv run uvicorn 'redline.service.app:create_app' --factory --host 127.0.0.1 --port "$PORT" >"$ROOT/server.log" 2>&1 &
    SERVER_PID=$!
    ;;
  *)
    echo "unknown REDLINE_DEPLOYMENT_SMOKE_MODE: $MODE" >&2
    exit 64
    ;;
esac

wait_for_health

REDLINE_SERVICE_TOKEN="$TOKEN" uv run python scripts/frontend-demo-flow.py \
  --base-url "http://127.0.0.1:${PORT}" \
  --token "$TOKEN" \
  --allow-demo-baseline-genesis
