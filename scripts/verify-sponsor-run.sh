#!/usr/bin/env bash
set -euo pipefail

receipt_path="${1:-artifacts/demo/pass/receipt.json}"
package_path="${2:-fixtures/demo_pack}"

uv run redline check "$receipt_path" --package "$package_path" --rerun --json
