#!/usr/bin/env bash
set -euo pipefail

evidence_path="${1:-artifacts/sponsor/demo-readback.json}"
receipt_path="${2:-artifacts/demo/pass/receipt.json}"
package_path="${3:-fixtures/demo_pack}"

set +e
uv run redline check "$receipt_path" --package "$package_path" --rerun --json
receipt_code=$?
set -e
if [ "$receipt_code" -ne 0 ] && [ "$receipt_code" -ne 10 ]; then
  exit "$receipt_code"
fi
uv run redline verify-sponsor-run "$evidence_path" --receipt "$receipt_path" --package "$package_path" --json
