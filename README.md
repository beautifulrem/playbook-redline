# Playbook Redline

> No AI-edited strategy reaches Bitget until it survives a fixed crash-test suite.
> Every verdict is a signed, tamper-evident receipt you can verify offline, with no server. *No proof, no verdict.*

[English](README.md) · [中文](README_CN.md)

![tests](https://img.shields.io/badge/tests-373%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12-3776AB)
![mode](https://img.shields.io/badge/Bitget-demo%20%2F%20paptrading%20only-F7931A)
![MCP](https://img.shields.io/badge/MCP-receipt--check%20tool-7E3FF2)
![license](https://img.shields.io/badge/license-MIT-blue)

**Live demo** (no install, no login): <https://beautifulrem.github.io/playbook-redline/>

Playbook Redline is a pre-release control gate for AI-edited trading strategies. When an AI rewrites a trading playbook, Redline does not trust the diff. It replays the edited strategy against a fixed crash-test suite, writes the verdict into a hash-chained ed25519 receipt, and places a real Bitget demo order only after the suite passes. Edits that fail are withheld before they can trade.

<p align="center">
  <img src="submission-evidence/tamper.gif" width="78%" alt="Offline tamper check: flip one byte and the randomart seal voids, the verdict flips to INTEGRITY FAIL, and the proof shows Bitget was never called">
</p>
<p align="center"><sub>Offline, pure-JS tamper check. Flip one byte in the receipt and the randomart seal voids, the verdict flips to <b>INTEGRITY FAIL</b>, and the proof shows Bitget was never called.</sub></p>

## Verify it yourself

A 60-second zero-secret judge review, offline, with no server and no Bitget credentials. Every step is captured under [`submission-evidence/`](submission-evidence/) and re-runnable from a fresh clone. This path is demo-only, uses evidence from Bitget `paptrading: 1`, and is not an official Bitget Playbook release.

```bash
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json  # passing chained release
bash scripts/tamper-demo.sh                                                                            # flip one byte, integrity fails closed -> exit 4
open artifacts/release-demo/current/evidence.html                                                      # the read-only judge evidence page
```

`verify-chain` reports a passing chained release, the tamper demo exits non-zero after a modified bundle fails verification, and the HTML page is the read-only judge evidence view. This review path does not require Bitget demo credentials; they are only needed to rerun `scripts/release-demo.sh` and mint new demo orders.

The real demo order `1453610833413308417` ran on Bitget `paptrading: 1`, demo-only, with no mainnet access and no secrets ([`submission-evidence/05-real-bitget-order.json`](submission-evidence/05-real-bitget-order.json)).

## How it works

1. An AI edits a trading playbook. That edited candidate is what Redline checks, not the prose of the diff.
2. Redline replays the candidate against a **fixed** crash-test suite: max drawdown, crash-window no-entry, and a trade budget. The suite is fixed on purpose, so the AI cannot move its own goalposts after editing its strategy.
3. On FAIL, the candidate is withheld. No order is placed.
4. On PASS, the verdict is written into a hash-chained, ed25519-signed receipt, and one real Bitget demo order is placed under `paptrading: 1`.
5. Anyone can re-verify the receipt offline. Change one byte and the chain breaks, the signature fails, and the seal voids.

## Integration

Redline sits between an AI that edits a strategy and the exchange. Three ways to wire it in:

- **CLI in CI.** Run `redline run` on the edited candidate and gate on the exit code, then `redline verify-release-bundle` before you ship: a non-zero exit stops the pipeline, a PASS leaves a signed receipt to archive. This is the path `make verify-demo` exercises.
- **HTTP service.** Drive it from your orchestrator: `POST /v1/runs` to crash-test a candidate, then `POST /v1/runs/{run_id}/execute` to place the demo order only on a chained, signed PASS. The OpenAPI contract is checked in at `schemas/service-openapi.json` (see [`SERVICE_API.md`](SERVICE_API.md)).
- **MCP tool.** `redline-mcp` (stdio) exposes one read-only tool, `redline_check_receipt`, so an AI agent can verify a receipt mid-conversation without ever touching the verdict path.

## Install

Prerequisites: Python 3.12 and [uv](https://docs.astral.sh/uv/) (or `pip install -e .`).

```bash
make install
make audit
uv run redline doctor --json
make goldens-check
```

Expected demo outcomes:

- `candidate_good`: `pass` with `BASELINE_GENESIS`
- `candidate_bad`: `withheld` with `NEW_BLOCK_BREACH`

The bundled suite is two 24-bar BTCUSDT windows and three blocking probes (max drawdown, crash-window no-entry, trade budget). `BASELINE_GENESIS` exits with code `10` as an amber state, because the fixture baseline is not chained to a previous receipt. Hash-only checks are integrity-only and return `unverified_no_verdict`; trusted verification uses package-bound replay.

## Usage

Run the gate, then verify the receipt:

```bash
uv run redline run fixtures/demo_pack \
  --baseline baseline --candidate candidate_bad \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json \
  --out artifacts/demo/withheld --json

uv run redline verify-proof artifacts/demo/pass/receipt.json \
  --proof-id proof:package_canonical:7bc11572ef15a4a40cdf1856 \
  --package fixtures/demo_pack \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json --json
```

`redline report` without `--verified` renders only an `UNVERIFIED PREVIEW`. A final publish path must use a chained `PASS` receipt plus an ed25519-signed ledger attestation verified against a pinned trust policy; the bundled genesis fixture is not one. Trust-key generation, ledger signing, and the sponsor-adapter publish flow are documented inline in the CLI help and in [`SERVICE_API.md`](SERVICE_API.md).

## Service

The HTTP service is a thin FastAPI boundary over the same proof kernel. It does not shell out to the CLI and does not create a second verdict path: workers call `run_redline`, persist run state, and expose the generated receipt, report, and proof artifacts from isolated per-run directories.

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run redline-api

curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/v1/runs \
  -H 'content-type: application/json' -H 'x-redline-token: redline-demo' \
  -d '{"package_path":"fixtures/demo_pack","candidate":"candidate_good"}'
```

`POST /v1/runs/{run_id}/execute` is the demo execution gate. It consumes a replayed, chained, signed `PASS` receipt and places one Bitget demo order under `paptrading: 1`. WITHHELD, hash-only, unsigned, unchained, tampered, missing-credential, and default-mainnet cases all return `blocked` before any order call. The release backend layers versioned strategy releases, simulated-trading evidence, risk-policy binding, human approval, and a hash-verified evidence bundle on top of that gate, and `/v1/judge/console` renders a read-only review surface over it. The OpenAPI contract is checked in at `schemas/service-openapi.json`. Endpoint semantics live in [`SERVICE_API.md`](SERVICE_API.md); deployment and the judge runbook are in [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Security boundary

Candidate strategies run in a subprocess. On macOS the worker is also wrapped with `sandbox-exec` to deny network access, process forking, and file writes. Inside the worker, Python audit hooks deny sockets, subprocess, fork, exec, filesystem mutation, reads outside the package and runtime allowlist, and `ctypes`/`cffi`. Scenario bars are preloaded by trusted code and are never exposed as readable files to candidate strategies. The verdict path uses only built-in probes, and a separate tripwire rejects network and LLM SDK imports. This is a local proof-kernel sandbox for demo and CI use; production exchange execution should still use the exchange's own runtime sandbox.

## Repository layout

```text
src/redline/      backend package
tests/            backend tests
fixtures/         demo packages, suites, specs
schemas/          exported JSON schemas
artifacts/demo/   checked-in demo receipts and proof artifacts
scripts/          helper verification scripts
SERVICE_API.md    service API contract
DEPLOYMENT.md     container deployment and judge runbook
```

Built for the Bitget AI Hackathon, Trading Infra track. Demo execution uses Bitget `paptrading: 1` only and does not imply Playbook live activation.

## License

[MIT](LICENSE) © 2026 Playbook Redline contributors.
