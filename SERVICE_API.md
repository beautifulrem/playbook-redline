# Playbook Redline Service API Contract

The service backend wraps the existing Redline proof engine. HTTP handlers
enqueue runs, persist status, and expose artifacts; verdicts still come from
`redline.runner.run_redline` and the existing receipt/proof/report schemas.

## Runtime

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run redline-api
```

Default local URL: `http://127.0.0.1:8080`.

Production/container runtime uses:

```bash
REDLINE_SERVICE_ENV=production
REDLINE_SERVICE_TOKEN=<32+ character secret>
REDLINE_SERVICE_TOKENS='[{"token":"<32+ chars>","principal_id":"reviewer-1","role":"reviewer","scopes":["read-only","release-write"]}]'
REDLINE_SERVICE_ROOT=/data/redline-service
REDLINE_SERVICE_CORS_ORIGINS=http://localhost:3000
REDLINE_SERVICE_METADATA_STORE=postgres
REDLINE_DATABASE_URL=<postgres connection string>
```

Production rejects default demo tokens, duplicate tokens, short tokens, and
wildcard CORS origins. Unknown server errors are redacted from HTTP responses;
correlate logs with the returned `x-request-id`.

`REDLINE_SERVICE_TOKENS` is optional. If it is omitted, the legacy single
`REDLINE_SERVICE_TOKEN` is treated as a local admin token for backward
compatibility. If it is set, each entry binds a token to an authenticated
principal, role, and scopes:

- roles: `author`, `reviewer`, `release_manager`, `admin`
- scopes: `read-only`, `release-write`, `execute-demo`, `admin`

Read endpoints require `read-only`. Package/run/release mutation endpoints
require `release-write`. Bitget demo execution and sponsor live readback require
`execute-demo`. Approval records bind `reviewer_id` to the authenticated
principal; a request-body `reviewer_id` is retained only as
`claimed_reviewer_id` for compatibility and audit comparison.

Session auth is also available for local/demo human review:

```bash
REDLINE_AUTH_SESSION_SECRET=<32+ character secret>
REDLINE_AUTH_USERS='[{"github_login":"alice","principal_id":"github:alice","role":"reviewer","scopes":["read-only","release-write","execute-demo"]}]'
REDLINE_DEV_AUTH_ENABLED=1
REDLINE_DEV_AUTH_USER=alice
REDLINE_GITHUB_OAUTH_CLIENT_ID=<github oauth app client id>
REDLINE_GITHUB_OAUTH_CLIENT_SECRET=<github oauth app client secret>
REDLINE_GITHUB_OAUTH_REDIRECT_URI=http://127.0.0.1:8080/v1/auth/callback/github
REDLINE_AUTH_ALLOWED_GITHUB_LOGINS=alice,bob
```

`POST /v1/auth/dev-login` sets an HttpOnly `redline_session` cookie for a
configured dev principal. `GET /v1/auth/me` returns the authenticated principal
for either a service token or session cookie. `POST /v1/auth/logout` clears the
session cookie.

`GET /v1/auth/login/github` starts the GitHub OAuth web flow with a random
state cookie. `GET /v1/auth/callback/github` exchanges the GitHub `code`, fetches
the GitHub user profile, maps the login through `REDLINE_AUTH_USERS` or
`REDLINE_AUTH_ALLOWED_GITHUB_LOGINS`, then sets the same HttpOnly
`redline_session` cookie. OAuth access tokens are not written to audit ledgers,
bundles, HTML, or artifacts.

Production requires `REDLINE_AUTH_SESSION_SECRET`; default or empty session
secrets are rejected.

All `/v1/*` endpoints require either:

```http
X-Redline-Token: redline-demo
```

or:

```http
Authorization: Bearer redline-demo
```

`/health` and `/openapi.json` are public for local smoke checks and frontend
contract discovery.

## Backend Operators

Check service schema migrations without touching a database:

```bash
uv run redline service-migrations --dry-run --json
```

Check and initialize the configured local service store:

```bash
uv run redline service-migrations --root artifacts/service --json
```

Verify a release evidence bundle on a judge or operator machine:

```bash
uv run redline verify-release-bundle \
  artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json \
  --json
```

The verifier checks manifest file hashes, the release audit hash chain,
simulation evidence hash, risk policy hash, the local execution evidence
artifact, and any Bitget preflight/order-status sidecar evidence when a bundle
includes demo execution.

## Judge 60-second zero-key review

Use this path when a judge or operator wants to verify the checked-in demo
evidence without credentials and without placing a new order. It is demo-only,
based on Bitget `paptrading: 1` artifacts, and is not a Bitget Playbook live
activation.

```bash
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json
scripts/tamper-demo.sh
open artifacts/release-demo/current/evidence.html
```

The first command walks the release chain with public artifacts only. The second
command proves tampering is detected by verifying a modified copy and returning
non-zero. The third opens the read-only evidence page; invalid or missing
evidence renders as `EVIDENCE INVALID`, `UNVERIFIED`, or blocked rather than a
success state. A live judge button should call the job endpoints below only when
the demo operator intentionally wants to create fresh Bitget demo evidence.

Create and verify a local signed release bundle attestation:

```bash
uv run redline attest-release-bundle \
  artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json \
  --out artifacts/release-demo/current/service/releases/release-demo-good/release-attestation.json \
  --json
uv run redline verify-release-attestation \
  artifacts/release-demo/current/service/releases/release-demo-good/release-attestation.json \
  --bundle artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json \
  --json
```

Build an offline-verifiable Hackathon submission pack from an existing bundle:

```bash
uv run redline hackathon-pack \
  artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json \
  --attestation artifacts/release-demo/current/service/releases/release-demo-good/release-attestation.json \
  --out artifacts/hackathon-submission-pack \
  --manifest artifacts/hackathon-submit-manifest.json \
  --json
```

The pack keeps the `service/releases/<release_id>` and
`service/runs/<run_id>` layout so `verify-release-bundle` and
`verify-release-attestation` still work after the files are copied away from the
original demo session.

Render the judge-facing, read-only evidence HTML from existing artifacts:

```bash
uv run redline render-evidence \
  --good artifacts/execution-demo/session-qy4c4dyk/service/runs/run_f6038852ad967c15993aeab3 \
  --bad artifacts/demo/withheld \
  --out artifacts/evidence.html
```

## Core Demo Flow

1. Import or upload a playbook package.
2. Create a run with baseline/candidate/suite/spec.
3. Poll the run until `state` is `pass`, `amber`, `fail`, or `error`.
4. Read the artifact manifest.
5. Download `receipt`, `report`, `envelope`, ledger checkpoint, or proof files.
6. Optionally call sponsor preflight/live readback. Live mode never returns a
   pseudo-success when credentials or proof bindings are missing.
7. Optionally call demo execution. It only places a Bitget demo order when the
   receipt verifies as replayed, chained, signed, and `PASS`.

The repository includes a frontend-facing smoke client for this exact flow:

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run python scripts/frontend-demo-flow.py \
  --base-url http://127.0.0.1:8080 \
  --token redline-demo \
  --allow-demo-baseline-genesis
```

For a deployed service:

```bash
REDLINE_REMOTE_BASE_URL=https://<service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
make remote-smoke
```

For deployed-service contract, CORS, and failure-path checks:

```bash
REDLINE_REMOTE_BASE_URL=https://<service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
REDLINE_REMOTE_RATE_LIMIT_PROBES=130 \
make remote-production-check
```

Set `REDLINE_REMOTE_RATE_LIMIT_PROBES=0` to skip the live 429 probe. The script
still verifies exact OpenAPI parity, frontend CORS, wrong-token 401, missing-run
404, and redacted error envelopes.

To save the deployed URL/token/origin as GitHub repository secrets and run the
manual remote smoke workflow:

```bash
REDLINE_REMOTE_BASE_URL=https://<service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
make remote-smoke-actions
```

## Endpoints

`POST /v1/packages/import`

Imports a local package path. Intended for local demo, CI, and judge machines.

Request:

```json
{
  "package_path": "fixtures/demo_pack",
  "write_lock": false
}
```

`POST /v1/packages/upload`

Uploads a `.tar.gz` playbook package as multipart field `archive`. Archive
members must be relative regular files/directories; links, devices, absolute
paths, and `..` are rejected.

`POST /v1/runs`

Queues a non-blocking Redline run.

Request:

```json
{
  "package_id": "pkg_...",
  "baseline": "baseline",
  "candidate": "candidate_good",
  "suite_path": "fixtures/suites/demo_suite.json",
  "spec_path": "fixtures/specs/redline_spec.json"
}
```

Exactly one of `package_id` or `package_path` is required.

Run states:

- `queued`: accepted but not started
- `running`: worker is executing the proof engine
- `pass`: local pass with chained baseline
- `amber`: local pass but demo/genesis trust boundary
- `fail`: verdict-bearing withheld run
- `error`: bad input, binding failure, engine failure, or unsafe path

`GET /v1/runs/{run_id}`

Returns status, reason code, receipt/report hashes, and artifact manifest when
ready.

`GET /v1/runs/{run_id}/artifacts`

Returns downloadable artifacts with stable `artifact_id`, kind, size, SHA-256,
and download URL.

`GET /v1/runs/{run_id}/artifacts/{artifact_id}`

Downloads an artifact. Path traversal, symlink, missing file, and non-file
targets are rejected.

`POST /v1/runs/{run_id}/sponsor-readback`

Runs sponsor publish preflight or live Bitget readback.

Request:

```json
{
  "mode": "preflight",
  "final_publish": false,
  "allow_demo_baseline_genesis": true
}
```

Live mode reads credentials from `REDLINE_BITGET_ACCESS_KEY`,
`REDLINE_BITGET_SECRET_KEY`, and `REDLINE_BITGET_PASSPHRASE` or the matching
`BITGET_*` variables. Missing credentials, local mismatch, missing package
binding, or sponsor readback mismatch returns `ok: false`.

`POST /v1/runs/{run_id}/execute`

Consumes an already-created run receipt and places one Bitget demo order only
when verification proves `REPLAYED + VERIFIED + PASS + chained + signed trust
policy`. This endpoint is not a verdict path and never calls `decide`.

Request:

```json
{
  "size": "0.0001",
  "side": "buy",
  "trade_side": "open",
  "order_type": "market"
}
```

Optional fields: `symbol`, `product_type`, `margin_coin`, `force`, `price`,
`trust_policy_path`, and `confirm_mainnet_order`.

Demo execution reads credentials only from:

```text
REDLINE_BITGET_DEMO_ACCESS_KEY
REDLINE_BITGET_DEMO_SECRET_KEY
REDLINE_BITGET_DEMO_PASSPHRASE
```

Runtime defaults:

```text
REDLINE_BITGET_PAPTRADING=1
REDLINE_BITGET_BASE_URL=https://api.bitget.com
REDLINE_BITGET_DEMO_SYMBOL=BTCUSDT
REDLINE_BITGET_DEMO_SIZE=0.0001
REDLINE_BITGET_PRODUCT_TYPE=USDT-FUTURES
```

Success returns `ok: true` and writes these artifacts into the run directory:

- `exchange-preflight-evidence.json`: Bitget demo read checks for product,
  symbol, margin coin, size/precision, and account readability. Raw responses
  are represented by hashes only.
- `execution-evidence.json`: the canonical demo order evidence with
  `bitget_order_id`, `client_oid`, `receipt_hash`, and `response_hash`.
- `order-status-evidence.json`: Bitget order-detail reconciliation by
  `clientOid`/`orderId`.
- `execution-ledger.jsonl`: hash-chained execution ledger.

Repeating the same request for the same receipt returns the existing evidence
and does not place a second order. If a POST to Bitget times out after the
`clientOid` is issued, or Bitget reports that the `clientOid` already exists,
the backend queries Bitget by `clientOid` before deciding whether the order was
recovered or requires manual reconciliation.

Blocked responses return HTTP 200 with `ok: false`, `state: "blocked"`, and a
machine-readable `reason_code`. WITHHELD, hash-only, tampered, unchained,
unsigned, missing-credential, non-demo-symbol, preflight failure, and
default-mainnet cases are all blocked before any Bitget order call. If order
status cannot be reconciled after placement, the response fails closed with
`EXCHANGE_RECONCILIATION_REQUIRED`.

## Production Release API

The release API wraps existing runs and the existing demo execution gate. It
does not create a second verdict path and does not duplicate Bitget order
logic.

`POST /v1/strategy-versions`

Creates a versioned strategy/playbook package binding. A `version_id` cannot be
reused for a different `package_hash`.

```json
{
  "version_id": "release-demo-v1",
  "strategy_id": "release-demo-strategy",
  "package_path": "fixtures/demo_pack",
  "package_hash": "sha256:...",
  "source_kind": "fixture",
  "created_by": "strategy-author",
  "metadata": {
    "market": "bitget-demo"
  }
}
```

`GET /v1/strategy-versions`

Lists recent strategy versions.

`GET /v1/strategy-versions/{version_id}`

Returns one strategy version.

`POST /v1/release-candidates`

Creates a backend-owned release candidate state machine for a strategy version.
Supports `Idempotency-Key`: the same key with the same request body replays the
original response; the same key with a different body returns 409.

```json
{
  "release_id": "release-demo-good",
  "version_id": "release-demo-v1",
  "created_by": "strategy-author",
  "metadata": {
    "hackathon": "bitget-ai-s1"
  }
}
```

`GET /v1/release-candidates`

Lists recent release candidates.

`GET /v1/release-candidates/{release_id}`

Returns state, bound run hashes, simulation evidence hash, risk policy hash,
approval record, execution evidence, and evidence manifest hash.

Release states are backend-owned:

- normal: `draft`, `redline_running`, `redline_passed`,
  `evidence_collecting`, `review_required`, `approved`, `demo_executed`,
  `release_ready`
- terminal/gated: `released_demo`, `released_live_gated`, `rejected`, `killed`
- fail-closed: `blocked_withheld`, `blocked_unverified`,
  `blocked_missing_evidence`, `blocked_risk_policy`, `blocked_approval`,
  `blocked_exchange_error`

`POST /v1/release-candidates/{release_id}/redline-run`

Binds an existing run. Only a stored run with `state: "pass"`,
`reason_code: "PASS"`, and a receipt hash can move the release to
`redline_passed`. Failed or amber runs become blocked and cannot approve or
execute.

```json
{
  "run_id": "run_..."
}
```

`POST /v1/release-candidates/{release_id}/simulation-evidence`

Imports simulated-trading/backtest evidence. This is intentionally summary
import, not a backtest engine or GetAgent Studio API integration.

```json
{
  "source": "local_backtest",
  "period_start": "2026-06-01",
  "period_end": "2026-06-22",
  "market": "bitget-demo",
  "symbol": "BTCUSDT",
  "trade_count": 12,
  "pnl": "42.50",
  "max_drawdown": "3.20",
  "win_rate": "0.58",
  "source_file_hash": "sha256:..."
}
```

`GET /v1/release-candidates/{release_id}/simulation-evidence`

Returns imported simulation evidence or 404 if absent.

`POST /v1/release-candidates/{release_id}/simulation-evidence-file`

Uploads a raw CSV/JSON simulation export as multipart field `file`, stores the
source artifact, records `source_file_hash`, and normalizes the evidence into
the same summary shape used by `/simulation-evidence`.

Form fields:

```text
source=getagent_studio | local_backtest | manual_import
market=bitget-demo
symbol=BTCUSDT
file=@getagent-export.csv
```

CSV rows support common columns such as `timestamp`, `symbol`, `pnl`/`profit`,
and `drawdown`. JSON may be either a summary object or a list/object containing
trade rows.

`POST /v1/release-candidates/{release_id}/risk-policy`

Binds a risk policy. Policy breaches return `ok: false` and move the candidate
to `blocked_risk_policy`.

```json
{
  "max_order_notional_usdt": "20",
  "allowed_product_types": ["USDT-FUTURES"],
  "allowed_symbols": ["BTCUSDT", "ETHUSDT", "SOLUSDT"],
  "require_simulation_evidence": true,
  "require_demo_execution": true,
  "require_human_approval": true,
  "mainnet_enabled": false,
  "expected_order_notional_usdt": "5"
}
```

`POST /v1/release-candidates/{release_id}/approve`

Approves a release for demo execution after Redline `PASS`, required simulation
evidence, and risk policy checks. The creator cannot self-approve unless
`demo_mode=true`. The stored approval uses the authenticated principal as
`reviewer_id`; the request-body `reviewer_id` is retained only as
`claimed_reviewer_id`.

```json
{
  "reviewer_id": "release-reviewer",
  "comment": "approved for demo execution",
  "demo_mode": false
}
```

`POST /v1/release-candidates/{release_id}/reject`

Records a human rejection and writes the audit ledger.

`POST /v1/release-candidates/{release_id}/execute-demo`

Calls the existing `/v1/runs/{run_id}/execute` gate internally. Repeating the
same release-level request returns existing evidence and does not place another
order. `REDLINE_EXECUTION_FREEZE=1` blocks this path.

`POST /v1/release-candidates/{release_id}/demo-showcase-orders`

Places an additional Bitget demo-only order for a `release_ready` candidate.
This is for live judge demonstration, not for changing release state. The
endpoint rechecks execution freeze, approval fingerprint, release risk policy,
canonical execution evidence, and Redline receipt verification before calling
Bitget. `Idempotency-Key` is supported: same key plus same body returns the
same showcase order; same key plus different body returns `409`.

The response includes `attempt_id`, `bitget_order_id`, `client_oid`,
`evidence_path`, `evidence_html_path`, and `evidence_html_url`. Artifacts are
written under
`REDLINE_SERVICE_ROOT/releases/{release_id}/demo-showcase-orders/{attempt_id}`.
The release-level showcase ledger is
`REDLINE_SERVICE_ROOT/releases/{release_id}/demo-showcase-execution-ledger.jsonl`.

`GET /v1/release-candidates/{release_id}/demo-showcase-orders`

Lists verified showcase orders for the release. Each item is loaded through
`load_execution_evidence` and checked against the showcase execution ledger.
Invalid attempts are returned with `ok=false` and a structured `reason_code`.

`GET /v1/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html`

Returns a server-rendered HTML evidence page for one showcase order. It is
demo-only, verifies the saved evidence/ledger before rendering, and shows
invalid evidence as `INVALID` rather than success.

`POST /v1/release-candidates/{release_id}/jobs/execute-demo`

Creates a durable canonical demo-execution job and returns immediately with a
`job_id`. The background worker reuses the same
`/release-candidates/{release_id}/execute-demo` path, so approval, risk policy,
freeze, Bitget demo preflight, order placement, reconciliation, and release
state transition stay in one implementation. This is the endpoint a judge
button should call when the release has not yet produced canonical execution
evidence.

Request body is the same shape as `ExecutionRequest`:

```json
{
  "side": "buy",
  "size": "0.0001"
}
```

`Idempotency-Key` is supported: same key plus same body returns the current
state of the same job; same key plus different body returns `409`.

`POST /v1/release-candidates/{release_id}/jobs/showcase-order`

Creates a durable showcase-order job for a `release_ready` candidate and returns
immediately with a `job_id`. The background worker reuses the same
`/demo-showcase-orders` execution path, so freeze checks, approval fingerprint
checks, risk policy checks, canonical execution evidence checks, Bitget demo
mode, idempotency, and evidence writing stay in one place.

Request body is the same shape as `ExecutionRequest`:

```json
{
  "side": "sell",
  "size": "0.0001"
}
```

`Idempotency-Key` is supported: same key plus same body returns the current
state of the same job; same key plus different body returns `409`.

`GET /v1/release-candidates/{release_id}/jobs`

Lists recent release jobs for the candidate.

`GET /v1/release-candidates/{release_id}/jobs/{job_id}`

Returns job status: `queued`, `running`, `succeeded`, `failed`, or
`cancelled`. Successful jobs include the underlying `ReleaseActionResponse` in
`result`.

`POST /v1/release-candidates/{release_id}/jobs/{job_id}/cancel`

Cancels a queued job before a Bitget request is made. Running jobs record
`job_cancel_requested`; the Bitget request may already be in flight, so the
event ledger makes the limit explicit instead of pretending cancellation is
guaranteed.

`GET /v1/release-candidates/{release_id}/jobs/{job_id}/events`

Returns the job event ledger as JSON. Events are hash-chained with
`previous_event_hash` and `event_hash`; reads fail closed with
`RECEIPT_MISMATCH` if the chain or an event payload was tampered.

`GET /v1/release-candidates/{release_id}/jobs/{job_id}/events.ndjson`

Returns the same event ledger as newline-delimited JSON for simple polling or
stream-like judge displays.

On service startup, queued release jobs are drained again and interrupted
`running` jobs are marked `failed` with `JOB_RECOVERY_REQUIRED`.

`POST /v1/release-candidates/{release_id}/kill`

Marks a release candidate killed and records `release_killed`.

`GET /v1/release-candidates/{release_id}/evidence`

Downloads `release-evidence-bundle.json`. If an existing bundle or manifest no
longer matches its recorded SHA-256, the request fails closed with
`RECEIPT_MISMATCH`.

`GET /v1/release-candidates/{release_id}/evidence.html`

Returns a read-only, server-rendered HTML evidence view for the release. It
loads existing run/release artifacts through the same execution evidence,
execution ledger, and release audit hash checks; invalid or missing evidence is
rendered as `EVIDENCE INVALID`, `UNVERIFIED`, or blocked rather than a success.
The view is demo-only and is not a verdict path.

`POST /v1/release-candidates/{release_id}/attest`

Creates a local signed `release-attestation.json` for a `release_ready`
candidate after verifying the current evidence bundle. The attestation records
the authenticated principal and public verification data only.

`GET /v1/release-candidates/{release_id}/attestation`

Returns the saved attestation plus verification against the current evidence
bundle. Tampered or stale bundles return `ok: false` in the verification block.

`GET /v1/release-candidates/{release_id}/attestation.html`

Returns a small server-rendered attestation status page. Missing attestation is
shown as invalid/missing instead of success.

`GET /v1/release-candidates/{release_id}/audit-ledger`

Downloads `release-audit-ledger.jsonl` after validating the hash chain.

`GET /v1/release-safety`

Returns release freeze, execution freeze, and mainnet enablement flags without
exposing any credentials.

```json
{
  "release_freeze": false,
  "execution_freeze": false,
  "mainnet_orders_enabled": false
}
```

## Judge Console

`GET /v1/judge/console`

Returns a backend-rendered HTML console. It requires normal service
authentication and `read-only` scope. The page lists release candidates,
release state, canonical Bitget demo order id, showcase order count,
attestation status, latest job status, and safety flags.

`GET /v1/judge/releases/{release_id}`

Returns a backend-rendered release detail page. It shows Redline verdict fields,
simulation/risk/approval hashes, canonical execution evidence, verified
showcase orders, release jobs, latest job events, audit ledger summary, bundle
verification status, and attestation status.

The page uses small vanilla JavaScript to call:

```text
POST /v1/release-candidates/{release_id}/jobs/showcase-order
GET  /v1/release-candidates/{release_id}/jobs/{job_id}
GET  /v1/release-candidates/{release_id}/jobs/{job_id}/events.ndjson
POST /v1/release-candidates/{release_id}/attest
```

It does not call the synchronous showcase order endpoint directly, does not
create verdicts, and does not render exchange credentials or raw Bitget
responses.

## Error Envelope

All handled errors use:

```json
{
  "schema_version": "redline.service.error.v1",
  "ok": false,
  "request_id": "req_...",
  "error_code": "RECEIPT_BINDING_FAILED",
  "message": "artifact path is outside the run"
}
```

The same `request_id` is returned in the `x-request-id` response header.

## Deployment Smoke

```bash
make deployment-smoke
```

CI runs this against the Docker image. Development machines without Docker can
use:

```bash
REDLINE_DEPLOYMENT_SMOKE_MODE=local make deployment-smoke
```

The smoke test verifies health, OpenAPI, the HTTP flow, artifact manifest
hashes, replayed receipt result, and sponsor preflight.

## Persistence And Queue

The service supports `REDLINE_SERVICE_METADATA_STORE=sqlite` for local/CI and
`REDLINE_SERVICE_METADATA_STORE=postgres` for Render production. Runs are stored
as database rows and claimed by workers from the metadata store, so a restarted
container requeues interrupted `running` rows instead of losing in-memory work.

Artifacts remain on the configured local artifact root. In production this root
must be a persistent disk. The download endpoint always recomputes SHA-256 from
the stored artifact before returning it.
