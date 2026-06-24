#!/usr/bin/env bash
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
BUNDLE_NAME="release-evidence-bundle.json"
MANIFEST_NAME="release-evidence-manifest.json"
SOURCE_TARGET="${1:-artifacts/release-demo/current/service/releases/release-demo-good}"

if [[ -f "$SOURCE_TARGET" ]]; then
  if [[ "$(basename "$SOURCE_TARGET")" != "$BUNDLE_NAME" ]]; then
    echo "SOURCE_EVIDENCE_INVALID"
    echo "expected release directory or $BUNDLE_NAME file: $SOURCE_TARGET"
    exit 2
  fi
  SOURCE_RELEASE_DIR="$(cd "$(dirname "$SOURCE_TARGET")" && pwd -P)"
elif [[ -d "$SOURCE_TARGET" ]]; then
  SOURCE_RELEASE_DIR="$(cd "$SOURCE_TARGET" && pwd -P)"
else
  echo "SOURCE_EVIDENCE_INVALID"
  echo "release evidence target does not exist: $SOURCE_TARGET"
  exit 2
fi

if [[ -L "$SOURCE_RELEASE_DIR" ]]; then
  echo "SOURCE_EVIDENCE_INVALID"
  echo "release directory must not be a symlink: $SOURCE_RELEASE_DIR"
  exit 2
fi

if [[ ! -f "$SOURCE_RELEASE_DIR/$BUNDLE_NAME" ]]; then
  echo "SOURCE_EVIDENCE_INVALID"
  echo "release bundle is missing: $SOURCE_RELEASE_DIR/$BUNDLE_NAME"
  exit 2
fi

SERVICE_ROOT="$(cd "$SOURCE_RELEASE_DIR/../.." && pwd -P)"
RELEASE_REL_PATH="${SOURCE_RELEASE_DIR#$SERVICE_ROOT/}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/redline-tamper-demo.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

cp -R "$SERVICE_ROOT" "$TMP_ROOT/service"
TAMPER_RELEASE_DIR="$TMP_ROOT/service/$RELEASE_REL_PATH"
BASELINE_JSON="$TMP_ROOT/source-verify.json"
TAMPER_JSON="$TMP_ROOT/tamper-verify.json"

echo "SOURCE_RELEASE_DIR=$SOURCE_RELEASE_DIR"
echo "TAMPER_COPY_DIR=$TAMPER_RELEASE_DIR"

if ! (cd "$REPO_ROOT" && uv run redline verify-chain "$TAMPER_RELEASE_DIR" --json > "$BASELINE_JSON" 2>&1); then
  echo "SOURCE_EVIDENCE_INVALID"
  cat "$BASELINE_JSON"
  exit 2
fi

python3 - "$TAMPER_RELEASE_DIR" "$BUNDLE_NAME" "$MANIFEST_NAME" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

release_dir = Path(sys.argv[1])
bundle_name = sys.argv[2]
manifest_name = sys.argv[3]
bundle_path = release_dir / bundle_name
manifest_path = release_dir / manifest_name


def atomic_json_write(path: Path, payload: object) -> None:
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
approval = bundle["release_candidate"]["approval"]
reviewer = str(approval.get("reviewer_id") or "reviewer")
approval["reviewer_id"] = ("x" if not reviewer.startswith("x") else "y") + reviewer[1:]
atomic_json_write(bundle_path, bundle)

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
bundle_bytes = bundle_path.read_bytes()
bundle_hash = "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()
for item in manifest.get("files", []):
    if item.get("path") == bundle_name:
        item["sha256"] = bundle_hash
        item["bytes"] = len(bundle_bytes)
        break
else:
    raise SystemExit(f"manifest does not list {bundle_name}")
atomic_json_write(manifest_path, manifest)

print(f"TAMPERED_FILE={bundle_path}")
print("TAMPERED_FIELD=release_candidate.approval.reviewer_id")
PY

(cd "$REPO_ROOT" && uv run redline verify-chain "$TAMPER_RELEASE_DIR" --json > "$TAMPER_JSON" 2>&1)
VERIFY_STATUS=$?
if [[ "$VERIFY_STATUS" -eq 0 ]]; then
  echo "TAMPER_NOT_DETECTED"
  cat "$TAMPER_JSON"
  exit 1
fi

echo "TAMPER_DETECTED"
python3 - "$TAMPER_JSON" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

verify_path = Path(sys.argv[1])
raw = verify_path.read_text(encoding="utf-8")
try:
    payload = json.loads(raw)
except json.JSONDecodeError:
    print("first_failed_check=verify-chain-output")
    print("reason_code=UNPARSEABLE_VERIFY_OUTPUT")
    print("detail=verify-chain did not emit JSON")
    raise SystemExit(0)

failed = next((item for item in payload.get("checks", []) if not item.get("ok")), {})
print(f"first_failed_check={failed.get('name') or 'unknown'}")
print(f"reason_code={failed.get('reason_code') or payload.get('reason_code') or 'UNKNOWN'}")
print(f"detail={failed.get('detail') or ''}")
PY
cat "$TAMPER_JSON"
exit "$VERIFY_STATUS"
