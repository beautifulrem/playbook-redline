# Playbook Redline

Crash-test receipts for AI-edited Bitget Playbooks.

Playbook Redline is a backend proof kernel and verifier for checking whether an edited trading playbook still passes a fixed crash-test suite before it is trusted or published. The core rule is simple: no proof, no verdict.

## What Is Included

- Deterministic replay engine for fixture playbooks
- Blocking probes for drawdown and trade budget checks
- Decision kernel with closed reason codes
- Receipt issuer and verifier
- Proof-level verification command
- JSON schemas for receipts, specs, suites, decisions, and verification results
- Demo fixtures and generated demo artifacts for pass and withheld cases
- Fail-closed tests for sandbox and verdict-path violations

## Quick Start

```bash
uv run --extra dev pytest
uv run redline export-schemas
uv run redline make-demo
uv run redline check artifacts/demo/pass/receipt.json --json
uv run redline check artifacts/demo/withheld/receipt.json --json
```

Expected demo outcomes:

- `candidate_good`: `pass` with `BASELINE_GENESIS`
- `candidate_bad`: `withheld` with `NEW_BLOCK_BREACH`

`BASELINE_GENESIS` intentionally exits with code `10` as an amber state because the fixture baseline is not chained to a previous receipt.

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
  --proof-id proof:package_canonical:9d8796de0b746e376ff758a8 \
  --json
```

## Verification Script

```bash
scripts/verify-sponsor-run.sh
```

The script runs receipt verification in replayed mode with package binding.

## Repository Layout

```text
src/redline/      backend package
tests/            backend P0 tests
fixtures/         demo packages, suites, specs
schemas/          exported JSON schemas
artifacts/demo/   checked-in demo receipts and proof artifacts
scripts/          helper verification scripts
```
