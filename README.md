# Playbook Redline

Crash-test receipts for AI-edited Bitget Playbooks.

Playbook Redline is a backend proof kernel and verifier for checking whether an edited trading playbook still passes a fixed crash-test suite before it is trusted or published. The core rule is simple: no proof, no verdict.

## What Is Included

- Deterministic replay engine for fixture playbooks
- Blocking probes for drawdown, no-entry, and trade budget checks
- Decision kernel with closed reason codes
- Receipt issuer and verifier
- Ed25519-signed ledger checkpoint attestation for production publish verification
- Proof-level verification command
- JSON schemas for receipts, reports, specs, suites, decisions, proof verification, ledger checkpoints, ledger attestations, package annotations, sponsor evidence, and verification results
- Demo fixtures and generated demo artifacts for pass and withheld cases
- Fail-closed tests for sandbox and verdict-path violations

## Security Boundary

Candidate strategies run in a subprocess. On macOS, the worker is additionally
wrapped with `sandbox-exec` to deny network access, process forking, and file
writes. Inside the worker, Python audit hooks deny socket/subprocess/fork/exec,
filesystem mutation, reads outside the package/runtime allowlist, and
`ctypes`/`cffi`. Scenario bars are preloaded by trusted code and are not exposed
as readable files to candidate strategies. The verdict path uses only built-in
probes and a separate tripwire rejects network/LLM SDK imports. This is a local
proof-kernel sandbox for demo and CI use; production exchange execution should
still use the exchange's own runtime sandbox.

## Quick Start

```bash
uv run --extra dev pytest
uv run redline export-schemas
uv run redline make-demo
uv run redline check artifacts/demo/pass/receipt.json --package fixtures/demo_pack --rerun --json
uv run redline check artifacts/demo/withheld/receipt.json --package fixtures/demo_pack --rerun --json
```

Expected demo outcomes:

- `candidate_good`: `pass` with `BASELINE_GENESIS`
- `candidate_bad`: `withheld` with `NEW_BLOCK_BREACH`

The bundled suite contains two 24-bar BTCUSDT windows and three blocking probes:
max drawdown, crash-window no-entry, and trade budget.

`BASELINE_GENESIS` intentionally exits with code `10` as an amber state because the fixture baseline is not chained to a previous receipt.
Hash-only checks are integrity-only and return `unverified_no_verdict`; trusted verification uses `--rerun` with the package, suite, and spec inputs.
Replay verification also checks the local `issuance-ledger.checkpoint.json` beside the receipt. A final publish path must use a chained `PASS` receipt plus an Ed25519-signed ledger attestation verified against a protected trust policy.

## CLI

```bash
uv run redline run fixtures/demo_pack \
  --baseline baseline \
  --candidate candidate_bad \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json \
  --out artifacts/demo/withheld \
  --json

uv run redline verify-proof artifacts/demo/pass/receipt.json \
  --proof-id proof:package_canonical:d626e536e38620bff850851f \
  --package fixtures/demo_pack \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json \
  --json

uv run redline import fixtures/demo_pack --json
uv run redline compile fixtures/specs/redline_spec.json --json
uv run redline report artifacts/demo/pass/report.json \
  --receipt artifacts/demo/pass/receipt.json \
  --package fixtures/demo_pack

uv run redline publish fixtures/demo_pack artifacts/demo/pass/receipt.json --json
```

`redline report` without `--verified` renders only an `UNVERIFIED PREVIEW`.
`--verified` is reserved for receipts that are replayed, chained, and backed by
an externally signed ledger checkpoint under a pinned trusted policy; the
bundled genesis fixture is not one. Like production publish, verified report
stamping reads `REDLINE_TRUST_POLICY` and `REDLINE_TRUST_POLICY_HASH` from the
protected environment.
`redline publish` is fail-closed: the fixture pass receipt is still blocked as
`BASELINE_GENESIS` unless `--allow-demo-baseline-genesis` is supplied for a demo
annotation. That demo annotation is not final publish evidence. For a production
publish preflight, sign the checkpoint with `redline sign-ledger-checkpoint` and
pass `--ledger-attestation`. `redline publish` reads the trusted policy only
from `REDLINE_TRUST_POLICY` and requires its protected hash in
`REDLINE_TRUST_POLICY_HASH`. Store both outside the local artifact folder, for
example through CI secret management, repository environment protection, or
sponsor-side key custody. `redline check` and `verify-ledger-attestation` can
still accept a raw public key for low-level debugging, but `redline publish`
requires the protected trust policy pair.

```bash
uv run redline trust-keygen --out-private /tmp/redline-trust.private --out-public /tmp/redline-trust.public
uv run redline trust-policy \
  --public-key "$(cat /tmp/redline-trust.public)" \
  --key-id redline-demo \
  --issuer redline-ci \
  --out /tmp/redline-trust-policy.json
uv run redline sign-ledger-checkpoint artifacts/demo/pass/issuance-ledger.checkpoint.json \
  --private-key-file /tmp/redline-trust.private \
  --key-id redline-demo \
  --issuer redline-ci \
  --out /tmp/redline-ledger.attestation.json
uv run redline verify-ledger-attestation /tmp/redline-ledger.attestation.json \
  artifacts/demo/pass/issuance-ledger.checkpoint.json \
  --trust-policy /tmp/redline-trust-policy.json
export REDLINE_TRUST_POLICY=/tmp/redline-trust-policy.json
export REDLINE_TRUST_POLICY_HASH="$(python -c 'import json;print(json.load(open("/tmp/redline-trust-policy.json"))["policy_hash"])')"
```

The Python wheel installs the CLI and library only. The bundled fixture package,
schemas, GitHub Action, and checked-in demo artifacts are repository assets; use
a repository checkout for the complete demo.

## Verification Script

```bash
scripts/verify-sponsor-run.sh artifacts/sponsor/demo-readback.json artifacts/demo/pass/receipt.json fixtures/demo_pack
```

The script runs receipt verification in replayed mode with package binding.
It then calls `redline verify-sponsor-run`, which requires Bitget credentials and
rechecks the recorded `run_id` through the sponsor read-back endpoint. The live
read-back must match `status=completed`, `version_id`, and
`metrics_output_hash`; otherwise it exits fail-closed. The bundled recorded
file is not treated as live Bitget proof by itself, so
`BITGET_CREDENTIALS_REQUIRED` / `SPONSOR_EVIDENCE_UNVERIFIED` is expected until
real credentials are configured.

`redline publish --execute` is a wrapper around the live sponsor adapter. It
requires `REDLINE_BITGET_ACCESS_KEY`, `REDLINE_BITGET_SECRET_KEY`, and
`REDLINE_BITGET_PASSPHRASE` (or the same names without the `REDLINE_` prefix),
writes a redacted `sponsor-transcript.jsonl`, persists `sponsor_evidence`, and
still refuses final publish unless the local preflight is already chained and
signed. `--final-publish` additionally requires `--execute`,
`--yes-final-publish`, and `REDLINE_ALLOW_FINAL_PUBLISH=1`; only a live,
credentialed readback can reach `READBACK_VERIFIED`. The current adapter uses
injectable mock transport for tests and a conservative HMAC-signed HTTP wrapper
for live Bitget endpoints.

## Repository Layout

```text
src/redline/      backend package
tests/            backend P0 tests
fixtures/         demo packages, suites, specs
schemas/          exported JSON schemas
artifacts/demo/   checked-in demo receipts and proof artifacts
artifacts/sponsor recorded sponsor-attestation shape fixture
scripts/          helper verification scripts
```
