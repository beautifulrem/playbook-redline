# Playbook Redline Hackathon Submission

## Project Title

Playbook Redline: verifiable AI strategy release control for Bitget demo trading.

## One-line Pitch

Playbook Redline turns an AI-edited trading strategy into a controlled release candidate: deterministic verdict, human approval, Bitget demo execution, hash-bound evidence, live showcase orders, and signed release attestation.

## Problem

AI can edit trading strategies faster than humans can review them. A trading platform needs more than a green UI state before it lets an agent publish or execute. It needs a reproducible verdict, a release gate, a real approval identity, an execution record, and evidence that a judge can verify without trusting the server.

## What Is New In This Hackathon Work

- Production-style release candidates on top of existing Redline proof runs.
- Simulation evidence import, including raw CSV/JSON import with `source_file_hash`.
- Release risk policy binding and approval evidence.
- Real Bitget demo execution through `paptrading: 1`.
- Hash-bound execution evidence, Bitget exchange preflight evidence, order
  status reconciliation evidence, and release evidence bundles.
- Judge-facing server-rendered evidence HTML.
- Live demo-only showcase order endpoint for repeated judge clicks.
- Local signed release attestation for evidence bundle hashes.
- Hackathon submission manifest and verification script.
- Dev session identity for local/demo human approvals, with approval evidence
  bound to the authenticated principal rather than request-body text.

## What Was Pre-existing

- The core deterministic Redline proof kernel.
- Fixture strategy package and deterministic crash-tape replay.
- Receipt/report generation and verifier foundations.
- Sponsor read-back adapter foundations.

The verdict path remains unchanged:

```text
run_redline -> decide
```

Showcase orders, judge HTML, release bundles, and attestations are downstream evidence surfaces. They do not create or modify a Redline verdict.

## How AI Tools Were Used

AI coding tools helped implement backend endpoints, tests, scripts, and documentation under human-provided goals and constraints. Human direction defined the safety model, hard constraints, real Bitget demo credentials, approval to run demo-only orders, and final verification commands. The project does not rely on an AI model to decide whether a release is safe; the release gate consumes deterministic Redline receipts and explicit policy evidence.

## Backend Architecture

```text
strategy package
-> deterministic Redline run
-> receipt/report/artifact manifest
-> release candidate
-> simulation evidence
-> risk policy
-> authenticated approval
-> Bitget demo order
-> execution evidence
-> release evidence bundle
-> local signed attestation
-> judge evidence HTML / live showcase order API
```

Important backend files:

- `src/redline/service/app.py` - FastAPI service boundary.
- `src/redline/service/release.py` - release bundle and audit evidence.
- `src/redline/service/transitions.py` - release state transitions.
- `src/redline/sponsor/bitget_execution.py` - Bitget demo order adapter.
- `src/redline/render.py` - server-rendered evidence HTML.
- `src/redline/attestation.py` - local signed release bundle attestation.

## Security Model

- Mainnet order placement is disabled by default.
- Demo execution uses `paptrading: 1`.
- Bitget raw responses are reduced to `response_hash`.
- Execution evidence is hash-bound and checked before rendering.
- Release audit ledger is hash-chained.
- Release bundle verification checks manifest files, audit ledger chain, simulation evidence hash, risk policy hash, and execution evidence.
- Release attestation signs the verified bundle hash and manifest hash.
- API keys, secrets, passphrases, OAuth codes, cookies, and raw Bitget headers must not be written to artifacts, HTML, audit logs, job events, or attestation files.

## Demo Script

```bash
set -a
source .env.local
set +a

scripts/release-demo.sh
scripts/hackathon-submit-check.sh
```

`scripts/release-demo.sh` creates a fresh release-demo session by default, places one canonical Bitget demo order, places three additional demo-only showcase orders, renders evidence HTML, and prints artifact paths.

`scripts/hackathon-submit-check.sh` finds the latest release bundle, creates a
local signed attestation if needed, verifies the bundle and attestation, runs
the backend checks, scans for credential patterns, and calls
`redline hackathon-pack` to write both `artifacts/hackathon-submit-manifest.json`
and an offline-verifiable `artifacts/hackathon-submission-pack/`.

To generate only the pack from an existing verified bundle:

```bash
uv run redline hackathon-pack <latest-bundle> \
  --attestation <latest-attestation> \
  --out artifacts/hackathon-submission-pack \
  --manifest artifacts/hackathon-submit-manifest.json \
  --json
```

## Latest Real Bitget Demo Evidence Paths

The latest session is discovered by:

```bash
find artifacts/release-demo -path '*/release-evidence-bundle.json' -print | sort | tail -1
```

Useful artifacts inside a session:

- `service/releases/release-demo-good/release-evidence-bundle.json`
- `service/releases/release-demo-good/release-evidence-manifest.json`
- `service/releases/release-demo-good/release-attestation.json`
- `service/releases/release-demo-good/demo-showcase-orders/*/execution-evidence.json`
- `evidence.html`

Useful artifacts inside `artifacts/hackathon-submission-pack/`:

- `README.md`
- `hackathon-submit-manifest.json`
- `verify-output.json`
- `showcase-index.json`
- `judge-demo-curl.sh`
- `service/releases/release-demo-good/release-evidence-bundle.json`
- `service/releases/release-demo-good/release-attestation.json`

## Live Judge Console Flow

The backend-rendered judge console is live:

```text
GET /v1/judge/console
GET /v1/judge/releases/{release_id}
```

The release detail page creates showcase-order jobs instead of calling the
synchronous order endpoint directly. The equivalent backend-only API flow is:

```bash
curl -H "X-Redline-Token: $REDLINE_SERVICE_TOKEN" \
  -H "Idempotency-Key: judge-click-1" \
  -H "Content-Type: application/json" \
  -d '{"side":"buy","size":"0.0001"}' \
  "$REDLINE_SERVICE_URL/v1/release-candidates/release-demo-good/demo-showcase-orders"
```

Open the returned `evidence_html_url` to inspect the order evidence, or poll the
job events through `/events.ndjson`.

## Verification Commands

```bash
uv run redline doctor --json
uv run python scripts/check-verdict-path-imports.py
uv run --extra dev pytest -q tests/test_service_api.py -q
uv run redline verify-release-bundle <latest-bundle> --json
uv run redline verify-release-attestation <latest-attestation> --bundle <latest-bundle> --json
```

Full suite:

```bash
uv run --extra dev pytest -q
```

## Known Limitations

- The local signed attestation is file-based. Optional EVM/Hedera anchoring is planned but not required for the local verification story.
- Durable showcase job/event endpoints and the backend-rendered judge console are live for backend-triggered judge clicks.
- Full GitHub OAuth is planned; dev session identity and scoped service tokens are currently live.
- The backend imports simulation evidence but does not implement a full backtest engine.
- Mainnet trading remains intentionally disabled by default.
