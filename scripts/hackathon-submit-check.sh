#!/usr/bin/env bash
set -euo pipefail

export UV_CACHE_DIR="${UV_CACHE_DIR:-.uv-cache}"

latest_bundle="${1:-}"
if [ -z "$latest_bundle" ]; then
  latest_bundle="$(find artifacts/release-demo -path '*/release-evidence-bundle.json' -print | sort | tail -1)"
fi
if [ -z "$latest_bundle" ] || [ ! -f "$latest_bundle" ]; then
  echo "missing release evidence bundle; run scripts/release-demo.sh first" >&2
  exit 2
fi

release_dir="$(dirname "$latest_bundle")"
attestation="${REDLINE_RELEASE_ATTESTATION:-$release_dir/release-attestation.json}"
manifest="artifacts/hackathon-submit-manifest.json"
pack_dir="${REDLINE_HACKATHON_PACK_DIR:-artifacts/hackathon-submission-pack}"

uv run redline doctor --json
uv run python scripts/check-verdict-path-imports.py
uv run --extra dev pytest -q tests/test_service_api.py -q
uv run redline verify-release-bundle "$latest_bundle" --json

if [ ! -f "$attestation" ]; then
  uv run redline attest-release-bundle "$latest_bundle" --out "$attestation" --attester-principal "hackathon-submit-check" --json
fi
uv run redline verify-release-attestation "$attestation" --bundle "$latest_bundle" --json

uv run redline hackathon-pack "$latest_bundle" --attestation "$attestation" --out "$pack_dir" --manifest "$manifest" --attester-principal "hackathon-submit-check" --json

if rg -uuu -n "bg_[[:xdigit:]]{32}|REDLINE_BITGET_DEMO_(ACCESS_KEY|SECRET_KEY|PASSPHRASE)=.+" \
  -g '!**/.git/**' \
  -g '!.env.local' \
  src scripts README.md SERVICE_API.md BACKEND_COMPLETENESS.md PRODUCTION_RELEASE_BACKEND.md HACKATHON_SUBMISSION.md "$manifest" "$pack_dir" "$release_dir"; then
  echo "credential pattern scan failed" >&2
  exit 4
fi

echo "hackathon submit check passed"
