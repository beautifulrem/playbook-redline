#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/redline-service-smoke.XXXXXX")"
PORT="${REDLINE_SERVICE_SMOKE_PORT:-8092}"
TOKEN="${REDLINE_SERVICE_TOKEN:-redline-smoke}"
LOG="$ROOT/server.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$ROOT"
}
trap cleanup EXIT

REDLINE_SERVICE_ROOT="$ROOT/state" \
REDLINE_SERVICE_TOKEN="$TOKEN" \
uv run uvicorn 'redline.service.app:create_app' --factory --host 127.0.0.1 --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!

python - "$PORT" "$TOKEN" "$LOG" <<'PY'
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

port, token, log_path = sys.argv[1], sys.argv[2], Path(sys.argv[3])
base = f"http://127.0.0.1:{port}"


def request(method: str, path: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"x-redline-token": token}
    if body is not None:
        headers["content-type"] = "application/json"
    req = urllib.request.Request(f"{base}{path}", data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


deadline = time.monotonic() + 30
while True:
    try:
        health = request("GET", "/health")
        if health.get("ok") is True:
            break
    except Exception:
        if time.monotonic() > deadline:
            print(log_path.read_text(encoding="utf-8"), file=sys.stderr)
            raise
        time.sleep(0.2)

package = request("POST", "/v1/packages/import", {"package_path": "fixtures/demo_pack"})
run = request(
    "POST",
    "/v1/runs",
    {
        "package_id": package["package_id"],
        "candidate": "candidate_good",
        "suite_path": "fixtures/suites/demo_suite.json",
        "spec_path": "fixtures/specs/redline_spec.json",
    },
)
run_id = run["run_id"]
deadline = time.monotonic() + 30
while True:
    run = request("GET", f"/v1/runs/{run_id}")
    if run["state"] in {"pass", "amber", "fail", "error"}:
        break
    if time.monotonic() > deadline:
        raise RuntimeError(f"run did not finish: {run_id}")
    time.sleep(0.2)

if run["state"] != "amber" or run["reason_code"] != "BASELINE_GENESIS":
    raise RuntimeError(f"unexpected run state: {run}")
manifest = request("GET", f"/v1/runs/{run_id}/artifacts")
artifact_ids = {item["artifact_id"] for item in manifest["artifacts"]}
if "receipt" not in artifact_ids or "report" not in artifact_ids:
    raise RuntimeError(f"missing artifacts: {artifact_ids}")
receipt = request("GET", f"/v1/runs/{run_id}/artifacts/receipt")
if receipt["receipt_hash"] != run["receipt_hash"]:
    raise RuntimeError("receipt download does not match run summary")
print(json.dumps({"ok": True, "run_id": run_id, "state": run["state"], "receipt_hash": run["receipt_hash"]}, sort_keys=True))
PY
