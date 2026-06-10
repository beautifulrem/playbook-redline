# Playbook Redline

Crash-test receipts for AI-edited Bitget Playbooks.

Playbook Redline is a backend proof kernel and verifier for checking whether an edited trading playbook still passes a fixed crash-test suite before it is trusted or published. The core rule is simple: no proof, no verdict.

## What Is Included

- Deterministic replay engine for fixture playbooks
- Blocking probes for drawdown, no-entry, and trade budget checks
- Decision kernel with closed reason codes
- Receipt issuer and verifier
- Proof-level verification command
- JSON schemas for receipts, reports, specs, suites, decisions, proof verification, sponsor evidence, and verification results
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
uv run redline publish fixtures/demo_pack artifacts/demo/pass/receipt.json --json
```

## Verification Script

```bash
scripts/verify-sponsor-run.sh
```

The script runs receipt verification in replayed mode with package binding.
It also validates the bundled recorded sponsor-attestation JSON shape. That
recorded file is not treated as live Bitget read-back proof. A nonzero
`SPONSOR_EVIDENCE_UNVERIFIED` exit is expected until a live credentialed
Bitget adapter is configured.

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
