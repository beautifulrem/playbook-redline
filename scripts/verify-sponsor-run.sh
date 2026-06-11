#!/usr/bin/env bash
set -euo pipefail

evidence_path="${1:-artifacts/sponsor/demo-readback.json}"
receipt_path="${2:-artifacts/demo/pass/receipt.json}"
package_path="${3:-fixtures/demo_pack}"

receipt_json="$(mktemp)"
sponsor_json="$(mktemp)"
trap 'rm -f "$receipt_json" "$sponsor_json"' EXIT

emit_bundle() {
  local sponsor_code="${1:-}"
  python - "$receipt_code" "$receipt_json" "$sponsor_code" "$sponsor_json" <<'PY'
import json
import sys

receipt_code = int(sys.argv[1])
receipt_path = sys.argv[2]
sponsor_code = None if sys.argv[3] == "" else int(sys.argv[3])
sponsor_path = sys.argv[4]


def load_payload(path: str) -> object:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        return {"schema_version": "redline.command.raw.v1", "parse_error": str(exc), "raw": text}


payload = {
    "schema_version": "redline.sponsor.verify_script.v1",
    "receipt_exit_code": receipt_code,
    "receipt_check": load_payload(receipt_path),
    "sponsor_exit_code": sponsor_code,
    "sponsor_readback": load_payload(sponsor_path) if sponsor_code is not None else None,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

set +e
uv run redline check "$receipt_path" --package "$package_path" --rerun --json >"$receipt_json"
receipt_code=$?
set -e
if [ "$receipt_code" -ne 0 ] && [ "$receipt_code" -ne 10 ]; then
  emit_bundle
  exit "$receipt_code"
fi
set +e
uv run redline verify-sponsor-run "$evidence_path" --receipt "$receipt_path" --package "$package_path" --json >"$sponsor_json"
sponsor_code=$?
set -e
emit_bundle "$sponsor_code"
if [ "$sponsor_code" -ne 0 ]; then
  exit "$sponsor_code"
fi
if [ "$receipt_code" -ne 0 ]; then
  exit "$receipt_code"
fi
exit 0
