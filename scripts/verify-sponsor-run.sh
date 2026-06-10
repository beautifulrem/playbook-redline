#!/usr/bin/env bash
set -euo pipefail

receipt_path="${1:-artifacts/demo/pass/receipt.json}"
package_path="${2:-fixtures/demo_pack}"
evidence_path="${3:-artifacts/sponsor/demo-readback.json}"

set +e
uv run redline verify-sponsor-evidence "$evidence_path" --json
evidence_code=$?
set -e
set +e
uv run redline check "$receipt_path" --package "$package_path" --rerun --json
receipt_code=$?
set -e
if [ "$receipt_code" -ne 0 ]; then
  exit "$receipt_code"
fi
if [ "$evidence_code" -ne 0 ]; then
  exit "$evidence_code"
fi
