# Production Release Backend

Date: 2026-06-23

This backend turns Redline from a proof-run service into a controlled trading
release system. A strategy cannot move from AI-edited playbook code to exchange
execution only because a file hash exists. It must become a versioned release
candidate, bind a deterministic Redline `PASS` receipt, import simulated-trading
evidence, bind a risk policy, receive human approval, place a Bitget demo order,
and produce a hash-verified evidence bundle.

## Live Now

- Strategy/playbook version API:
  - `POST /v1/strategy-versions`
  - `GET /v1/strategy-versions`
  - `GET /v1/strategy-versions/{version_id}`
- Release candidate API:
  - `POST /v1/release-candidates`
  - `GET /v1/release-candidates`
  - `GET /v1/release-candidates/{release_id}`
- Release evidence gates:
  - `POST /v1/release-candidates/{release_id}/redline-run`
  - `POST /v1/release-candidates/{release_id}/simulation-evidence`
  - `GET /v1/release-candidates/{release_id}/simulation-evidence`
  - `POST /v1/release-candidates/{release_id}/risk-policy`
  - `POST /v1/release-candidates/{release_id}/approve`
  - `POST /v1/release-candidates/{release_id}/reject`
  - `POST /v1/release-candidates/{release_id}/execute-demo`
  - `POST /v1/release-candidates/{release_id}/demo-showcase-orders`
  - `GET /v1/release-candidates/{release_id}/demo-showcase-orders`
  - `GET /v1/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html`
  - `POST /v1/release-candidates/{release_id}/jobs/execute-demo`
  - `POST /v1/release-candidates/{release_id}/jobs/showcase-order`
  - `GET /v1/release-candidates/{release_id}/jobs`
  - `GET /v1/release-candidates/{release_id}/jobs/{job_id}`
  - `GET /v1/release-candidates/{release_id}/jobs/{job_id}/events`
  - `GET /v1/release-candidates/{release_id}/jobs/{job_id}/events.ndjson`
  - `POST /v1/release-candidates/{release_id}/kill`
  - `GET /v1/release-candidates/{release_id}/evidence`
  - `GET /v1/release-candidates/{release_id}/evidence.html`
  - `POST /v1/release-candidates/{release_id}/attest`
  - `GET /v1/release-candidates/{release_id}/attestation`
  - `GET /v1/release-candidates/{release_id}/attestation.html`
  - `GET /v1/release-candidates/{release_id}/audit-ledger`
  - `GET /v1/release-safety`
  - `GET /v1/judge/console`
  - `GET /v1/judge/releases/{release_id}`
- SQLite and Postgres metadata stores now include strategy versions, release
  candidates, release audit entries, and `schema_migrations`.
- Token RBAC binds backend API tokens to authenticated principals, roles, and
  scopes. Approval evidence uses the authenticated principal as reviewer
  identity.
- Dev session auth is live for local/demo human approvals. Session cookies are
  HMAC-signed, HttpOnly, SameSite=Lax, and expose the same authenticated
  principal shape as service tokens.
- Release state changes route through a centralized transition table, so blocked
  and terminal states cannot be reopened by a later endpoint.
- Release candidate creation supports persistent `Idempotency-Key` replay and
  same-key/different-body conflict detection.
- Release-ready candidates support live demo showcase orders. These are
  additional Bitget demo-only orders for judge interaction; each click rechecks
  freeze, approval fingerprint, risk policy, canonical execution evidence, and
  Redline receipt verification before placing an order. They write independent
  `demo-showcase-orders/{attempt_id}/exchange-preflight-evidence.json`,
  `execution-evidence.json`, `order-status-evidence.json`, `evidence.html`,
  and a release-level
  `demo-showcase-execution-ledger.jsonl`, without changing release state.
- Canonical and showcase demo execution both perform Bitget exchange preflight
  before order placement and order-detail reconciliation after placement.
  Transport timeout after a `clientOid` is issued recovers through clientOid
  lookup instead of retrying a second order.
- Showcase orders can also run as durable release jobs. A job records queued,
  started, verification, exchange-preflight, Bitget-requested,
  reconciliation, evidence-written, placed/failed, cancellation, and terminal
  events in a hash-chained event ledger and exposes JSON, NDJSON, and cancel
  endpoints. Startup recovery drains queued jobs again and marks interrupted
  running jobs `JOB_RECOVERY_REQUIRED`.
- The judge console is backend-rendered HTML. It lists releases, safety flags,
  canonical order ids, showcase counts, latest job status, bundle verification,
  and attestation status. Release detail pages create showcase-order jobs and
  poll the job event ledger; they do not create verdicts.
- Release artifacts are local files under
  `REDLINE_SERVICE_ROOT/releases/{release_id}`:
  - `release-evidence-bundle.json`
  - `release-evidence-manifest.json`
  - `release-attestation.json`
  - `release-audit-ledger.jsonl`
  - `release-simulation-evidence.json`
  - `release-risk-policy.json`
  - `release-decision-record.json`
- `scripts/release-demo.sh` runs the hackathon-facing release flow and prints
  only masked order identifiers.

## State Machine

Release state is backend-owned. Clients cannot submit arbitrary states.

Normal path:

```text
draft
-> redline_passed
-> evidence_collecting
-> review_required
-> approved
-> release_ready
```

Terminal or blocked states:

```text
rejected
killed
blocked_withheld
blocked_unverified
blocked_missing_evidence
blocked_risk_policy
blocked_approval
blocked_exchange_error
```

`redline_passed` requires a stored run whose state is `pass`, whose
`reason_code` is `PASS`, and whose receipt hash is present. A hash-only receipt
or an unverified local artifact cannot enter this state.

## Evidence Requirements

A release candidate must bind:

- a strategy version with canonical `package_hash`
- a Redline run and receipt/report hashes
- simulation/backtest evidence
- optional raw CSV/JSON simulation source file with `source_file_hash`
- risk policy and `risk_policy_hash`
- approval record with an evidence fingerprint
- Bitget demo execution evidence before it is `release_ready`
- a hash-chain release audit ledger

The evidence endpoint creates or verifies the release bundle before returning
it. If an existing manifest or bundle has been tampered with, download is
refused with `RECEIPT_MISMATCH` instead of silently regenerating over the
problem.

Operators can verify a downloaded bundle without starting the service:

```bash
uv run redline verify-release-bundle \
  artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json \
  --json
```

Operators can sign and verify a release bundle attestation without starting the
service:

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

Operators can check service schema state with:

```bash
uv run redline service-migrations --root artifacts/service --json
```

Operators can render the demo-only judge evidence page from existing artifacts:

```bash
uv run redline render-evidence --good <pass-run-dir> --bad <withheld-run-dir> --out evidence.html
```

## Simulation Evidence

The backend does not implement a backtest engine. It imports a summary produced
by local backtests, manual analysis, or GetAgent Studio exports.

Minimum imported fields:

- `source`: `getagent_studio`, `local_backtest`, or `manual_import`
- `period_start`
- `period_end`
- `market`
- `symbol`
- `trade_count`
- `pnl`
- `max_drawdown`
- `win_rate`
- optional `sharpe_or_sortino`
- optional `source_file_hash`

Missing simulation evidence blocks approval when the bound risk policy requires
it.

## Risk Policy

Default release policy is demo-first and mainnet-off:

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

The policy hash is part of the release evidence. Symbol/product/notional or
mainnet breaches return `blocked_risk_policy` before any execution call.

## Approval

Approval records include:

- reviewer id
- decision
- comment
- approval time
- evidence fingerprint
- risk policy hash
- auth method
- auth subject
- reviewer display name/email when configured

The creator cannot self-approve unless the request explicitly sets
`demo_mode=true`. Any evidence-changing action such as rebinding a run,
importing simulation evidence, or rebinding risk policy clears the previous
approval and forces review again.

## Audit Ledger

Every release candidate writes `release-audit-ledger.jsonl`. Each entry contains
`previous_entry_hash` and `entry_hash`. Loading or downloading the ledger
verifies the hash chain and rejects symlinks, hardlinks, malformed JSON, and
hash mismatches.

Tracked events:

- `strategy_version_created`
- `release_candidate_created`
- `redline_run_bound`
- `redline_verified`
- `simulation_evidence_imported`
- `risk_policy_bound`
- `risk_policy_checked`
- `approval_granted`
- `approval_rejected`
- `demo_order_requested`
- `demo_order_placed`
- `demo_order_blocked`
- `release_ready`
- `release_killed`

## Freeze And Kill Switches

`GET /v1/release-safety` reports:

- `release_freeze`: `REDLINE_RELEASE_FREEZE=1`
- `execution_freeze`: `REDLINE_EXECUTION_FREEZE=1`
- `mainnet_orders_enabled`: `REDLINE_ALLOW_MAINNET_ORDER=1`

`REDLINE_RELEASE_FREEZE=1` blocks approval. `REDLINE_EXECUTION_FREEZE=1`
blocks release-level demo execution. `POST /kill` marks a candidate as killed
and records the event in the audit ledger.

## Release Attestation

`POST /v1/release-candidates/{release_id}/attest` creates
`release-attestation.json` for a `release_ready` candidate after verifying the
current evidence bundle. The attestation signs the bundle hash and manifest
hash, records the authenticated principal as the attester, and stores only
public verification material.

`GET /v1/release-candidates/{release_id}/attestation` returns the saved
attestation plus live verification against the current bundle. If the bundle
changes after signing, verification returns invalid instead of trusting stale
evidence. `GET /v1/release-candidates/{release_id}/attestation.html` returns
the same status as a minimal server-rendered page.

## Demo Vs Mainnet

The release backend can place a real Bitget demo order through
`paptrading: 1`. That proves exchange integration and idempotent evidence
binding, but it is not a mainnet publish.

Mainnet remains gated and disabled by default. Demo execution does not imply
Playbook publish, final live activation, fund transfer, withdrawal, or any
asset-management permission.

## Hackathon Commands

After exporting Bitget demo credentials:

```bash
uv run redline doctor --json
uv run python scripts/check-verdict-path-imports.py
env -u REDLINE_TEST_POSTGRES_URL uv run --extra dev pytest -q
scripts/execution-demo.sh
scripts/release-demo.sh
scripts/hackathon-submit-check.sh
```

`scripts/release-demo.sh` demonstrates:

1. strategy version creation
2. release candidate creation
3. deterministic Redline `PASS` binding for `candidate_good`
4. simulation evidence import
5. risk policy binding
6. human approval
7. Bitget demo order execution
8. evidence bundle download/hash verification
9. local signed release attestation generation/verification
10. `candidate_bad` blocked after Redline failure
11. release and execution freeze behavior
