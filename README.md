# Playbook Redline

Crash-test receipts for AI-edited Bitget Playbooks.

Playbook Redline is a backend proof kernel and verifier for checking whether an edited trading playbook still passes a fixed crash-test suite before it is trusted or published. The core rule is simple: no proof, no verdict.

## Why Now

AI-edited trading playbooks can move faster than manual review, but every edit also changes risk exposure. Playbook Redline makes the handoff from "generated strategy" to "publishable Bitget playbook" auditable: deterministic replay, fixed crash tapes, receipt hashes, proof sidecars, and sponsor read-back all have to line up before a package can be exported.

## Hackathon Fit

- Bitget relevance: focuses on copy-trading/playbook safety before publication, with a sponsor read-back path for live run verification.
- Technical depth: combines deterministic replay, canonical hashing, proof coverage, sandboxing, signed ledger checkpoints, a narrow MCP receipt-check tool, JSON schemas, and CI integration.
- Product clarity: the primary user is a strategy author or reviewer who needs a yes/no publish gate plus machine-checkable evidence, not another dashboard without enforceable provenance.
- Demo strength: checked-in pass and withheld artifacts show both sides of the gate, while `verify-proof` and `check --package` let judges replay the evidence locally.
- Extensibility: probe definitions, suites, package import, report rendering, internal MCP helper surfaces, and sponsor adapters are separated so additional Bitget scenarios can be added without rewriting the proof kernel; the public FastMCP registration exposes only the safe receipt-check tool.

## Hackathon Submission Reference

- Project submission form: https://forms.gle/wemHkddKAxR3wFFz9
- Developer manual and submission rules: https://bitget-ai.gitbook.io/hackathon/untitled#ti-jiao-gui-ze
- Registration/submission window: June 16, 2026 00:00 through June 25, 2026 24:00 (UTC+8).
- Strategy submissions should prepare both simulated-trading and live-trading
  data. Current Playbook trading support is live-only, so simulated data should
  be produced separately, either by running local/backtest data or by using
  tools such as GetAgent Studio.
- Before final submission, re-check the developer manual for the current required fields, judging materials, demo expectations, and any rule changes.

## What Is Included

- Deterministic replay engine for fixture playbooks
- Blocking probes for drawdown, no-entry, and trade budget checks
- Decision kernel with closed reason codes
- Receipt issuer and verifier
- Ed25519-signed ledger checkpoint attestation for production publish verification
- Proof-level verification command
- Machine-readable backend doctor for Day-0 fixture, schema, replay, and proof-map smoke checks
- Static verdict-path import gate for proof/probe/verifier code
- FastAPI service boundary with token-gated run creation, SQLite/Postgres run state, DB-backed queue claiming, OpenAPI, package upload/import, artifact download, and container deployment smoke
- Frontend-facing demo flow script that verifies HTTP artifacts, receipt replay, and sponsor preflight
- JSON schemas for receipts, reports, specs, suites, decisions, doctor results, proof verification, ledger checkpoints, ledger attestations, package annotations, sponsor evidence, and verification results
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
make install
make audit
uv run redline doctor --json
make goldens-check
```

Expected demo outcomes:

- `candidate_good`: `pass` with `BASELINE_GENESIS`
- `candidate_bad`: `withheld` with `NEW_BLOCK_BREACH`

The bundled suite contains two 24-bar BTCUSDT windows and three blocking probes:
max drawdown, crash-window no-entry, and trade budget.

`fixtures/demo_pack/playbook_identity.lock` pins the adapter-supported Playbook
source boundary. `redline import --write-lock fixtures/demo_pack --json`
refreshes that lock; receipts record `package.identity_lock_hash`, and replayed
verification fails closed if a locked source file drifts.

`BASELINE_GENESIS` intentionally exits with code `10` as an amber state because the fixture baseline is not chained to a previous receipt.
Hash-only checks are integrity-only and return `unverified_no_verdict`; trusted verification uses package-bound replay. `redline check --package ...` now replays by default, while `--hash-only` must be supplied explicitly for integrity-only inspection.
Replay verification also checks the local `issuance-ledger.checkpoint.json` beside the receipt. A final publish path must use a chained `PASS` receipt plus an Ed25519-signed ledger attestation verified against a protected trust policy.
The bundled GitHub Action treats that amber demo state as failure unless
`allow-amber-baseline-genesis` is explicitly enabled and the caller workspace
demo package hash matches the bundled fixture hash.

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
  --proof-id proof:package_canonical:7bc11572ef15a4a40cdf1856 \
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

## Service API

The HTTP service is a thin FastAPI boundary over the same proof kernel. It does
not shell out to the CLI and does not create a second verdict path: workers call
`run_redline`, persist run state in SQLite, and expose the generated
receipt/report/proof artifacts from isolated per-run directories.

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run redline-api
```

Minimal local flow:

```bash
curl -s http://127.0.0.1:8080/health

curl -s -X POST http://127.0.0.1:8080/v1/packages/import \
  -H 'content-type: application/json' \
  -H 'x-redline-token: redline-demo' \
  -d '{"package_path":"fixtures/demo_pack"}'

curl -s -X POST http://127.0.0.1:8080/v1/runs \
  -H 'content-type: application/json' \
  -H 'x-redline-token: redline-demo' \
  -d '{"package_path":"fixtures/demo_pack","candidate":"candidate_good"}'
```

The service OpenAPI contract is checked in at `schemas/service-openapi.json`.
Frontend-facing endpoint semantics and response examples are documented in
`SERVICE_API.md`.

### 评委 60 秒零密钥复核

A fresh checkout can verify the checked-in release evidence without calling
Bitget and without any local secret material. This path is intentionally
demo-only, uses evidence from Bitget `paptrading: 1`, and is **非 Bitget Playbook 正式发布**.

```bash
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json
scripts/tamper-demo.sh
open artifacts/release-demo/current/evidence.html
```

Expected result: `verify-chain` reports a passing chained release, the tamper
demo exits non-zero after proving a modified bundle fails verification, and the
HTML page shows the read-only judge evidence view. This review path 不需要 Bitget demo credentials; credentials are only required when you intentionally
rerun `scripts/release-demo.sh` or `scripts/execution-demo.sh` to create new
demo orders.

`POST /v1/runs/{run_id}/execute` is the demo execution gate. It consumes a
replayed, chained, signed `PASS` receipt and places one Bitget demo order using
Demo API credentials plus `paptrading: 1`. WITHHELD, hash-only, unsigned,
unchained, tampered, missing-credential, and default-mainnet cases return
`blocked` before any order call. The gate writes `execution-evidence.json` and
`execution-ledger.jsonl` as hash-checked run artifacts. For the full boundary,
see `BACKEND_COMPLETENESS.md`; for a real demo run, export demo credentials and
run `scripts/execution-demo.sh`.

The production release backend adds versioned strategy releases on top of the
run gate. A release candidate must bind a Redline `PASS` run, import
simulated-trading evidence, bind a risk policy, receive human approval, execute
a Bitget demo order, and generate a hash-verified evidence bundle before it is
`release_ready`. The release API includes `/v1/strategy-versions`,
`/v1/release-candidates`, `/simulation-evidence`, `/risk-policy`, `/approve`,
`/execute-demo`, `/demo-showcase-orders`, `/evidence`, `/evidence.html`,
`/attest`, `/attestation`, `/attestation.html`, `/audit-ledger`, and
`/jobs/showcase-order`, `/jobs/{job_id}/events`, and `/v1/release-safety`.
`redline render-evidence` can render a demo-only,
read-only judge evidence page from existing run/release artifacts, and
release-ready candidates can create additional demo-only showcase orders for
live judge clicks, either synchronously or through a release job with an event
ledger. `/v1/judge/console` is a backend-rendered control surface that lists
release candidates and links through to release detail pages with job events,
bundle verification, and attestation status. `redline attest-release-bundle`
signs a verified release bundle hash into a local attestation that judges can
verify offline. Local/demo human reviewers can use dev session auth so approval
evidence binds to an authenticated principal instead of request-body text.
Mainnet
publish remains gated and disabled by default; demo execution does not imply
Playbook live activation. See `PRODUCTION_RELEASE_BACKEND.md`,
`HACKATHON_SUBMISSION.md`, and run:

```bash
scripts/release-demo.sh
scripts/hackathon-submit-check.sh
```

Deployment shape: Render Blueprint + containerized FastAPI service. Local/CI can
use SQLite under `REDLINE_SERVICE_ROOT`; Render uses Postgres metadata plus a
persistent disk for hash-verified artifacts. This keeps long-running proof jobs
and artifact hashes inside one stable runtime boundary instead of relying on a
serverless filesystem.

```bash
REDLINE_DEPLOYMENT_SMOKE_MODE=local make deployment-smoke
```

CI runs the same flow against the Docker image. Production mode requires a
non-default 32+ character `REDLINE_SERVICE_TOKEN`, explicit CORS origins, and
Postgres connection string when `REDLINE_SERVICE_METADATA_STORE=postgres`.
After Render is live, use `make remote-smoke` for the frontend flow and
`make remote-production-check` for OpenAPI parity, CORS, 401/404, optional 429,
and error-redaction checks. `make remote-smoke-actions` stores the remote URL,
token, and frontend origin as GitHub Actions secrets, then triggers the manual
remote smoke workflow. Deployment details, cleanup, and the judge runbook are in
`DEPLOYMENT.md`.

## Verification Script

```bash
scripts/verify-sponsor-run.sh artifacts/sponsor/demo-readback.json artifacts/demo/pass/receipt.json fixtures/demo_pack
```

The script emits one machine-parseable JSON document containing both the receipt
check and sponsor read-back result. It runs receipt verification in replayed mode
with package binding, then calls `redline verify-sponsor-run`. The bundled
recorded file is not treated as live Bitget proof by itself, so
`BITGET_CREDENTIALS_REQUIRED` / `SPONSOR_EVIDENCE_UNVERIFIED` is expected unless
a sponsor transport and credentials are configured.

`redline publish --execute` is an experimental sponsor-adapter wrapper, not an
official Bitget publish hook. It requires `REDLINE_BITGET_ACCESS_KEY`,
`REDLINE_BITGET_SECRET_KEY`, and `REDLINE_BITGET_PASSPHRASE` (or the same names
without the `REDLINE_` prefix), writes a redacted `sponsor-transcript.jsonl`,
persists `sponsor_evidence`, and still refuses final publish unless the local
preflight is already chained and signed. `--final-publish` additionally requires
`--execute`, `--yes-final-publish`, and `REDLINE_ALLOW_FINAL_PUBLISH=1`; a
credentialed response must include durable publish/readback identifiers before it
can reach `READBACK_VERIFIED` or `PUBLISHED`. The current adapter uses injectable
mock transport for tests plus a conservative HMAC-signed HTTP wrapper for a
future documented Playbook sponsor contract. Sponsor execution uploads the clean
package archive; the Redline annotation stays as local preflight/proof evidence.
Sponsor `metrics_output_hash` records the platform read-back payload and is not
treated as the Redline receipt result hash. Without those credentials and a
proof-eligible live read-back, the award evidence is the local proof kernel,
receipt verifier, proof sidecars, signed ledger path, and reproducible checked-in
artifacts; the recorded sponsor file is only a schema fixture.

## Repository Layout

```text
src/redline/      backend package
tests/            backend P0 tests
fixtures/         demo packages, suites, specs
schemas/          exported JSON schemas
artifacts/demo/   checked-in demo receipts and proof artifacts
artifacts/sponsor recorded sponsor-attestation shape fixture
BACKEND_COMPLETENESS.md demo execution and publish boundary
SERVICE_API.md    service API contract for frontend/demo integration
DEPLOYMENT.md     container deployment and judge runbook
Dockerfile        production-style service image
scripts/          helper verification scripts
```
