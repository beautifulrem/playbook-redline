# Backend Completeness Boundary

Date: 2026-06-23

## Live Now

- Deterministic Redline proof kernel and verifier remain the only verdict path:
  `run_redline -> decide`.
- The service API can create runs, persist artifacts, and download artifacts with
  hash verification before response.
- `POST /v1/runs/{run_id}/execute` is live for Bitget demo trading only. It
  consumes an existing receipt; it does not create a new verdict.
- Production release backend is live for hackathon demo scope:
  - strategy/playbook versions
  - release candidates
  - Redline run binding
  - simulation evidence import
  - raw CSV/JSON simulation evidence file import with `source_file_hash`
  - risk policy binding
  - four-eyes approval
  - release-level Bitget demo execution
  - hash-chain release audit ledger
  - downloadable release evidence bundle
- Token RBAC is live for backend APIs:
  - `REDLINE_SERVICE_TOKENS` binds tokens to authenticated principals
  - roles: `author`, `reviewer`, `release_manager`, `admin`
  - scopes: `read-only`, `release-write`, `execute-demo`, `admin`
  - approval records bind `reviewer_id` to the authenticated principal, not to
    an untrusted request-body identity
- Human identity is live for local/demo review:
  `GET /v1/auth/login/github`, `GET /v1/auth/callback/github`,
  `POST /v1/auth/dev-login`, `GET /v1/auth/me`, and `POST /v1/auth/logout`.
  GitHub OAuth uses a state cookie and maps GitHub login to `AuthPrincipal`;
  dev session remains available for local demo. Session cookies are HMAC-signed,
  HttpOnly, SameSite=Lax, and production requires an explicit
  `REDLINE_AUTH_SESSION_SECRET`.
- Schema migration tracking is live through `schema_migrations` for SQLite and
  Postgres plus `redline service-migrations`.
- Release state transitions are centralized in a transition table; terminal and
  blocked states are no longer silently reversible through later evidence calls.
- Release bundle verification is live through `redline verify-release-bundle`.
- Local signed release bundle attestation is live through
  `redline attest-release-bundle`, `redline verify-release-attestation`, and
  `POST/GET /v1/release-candidates/{release_id}/attestation`.
- Release candidate creation supports persistent `Idempotency-Key` replay and
  conflict detection through the service metadata store.
- 评委可视化证据视图 live（demo-only，只读展示，非 verdict）:
  `redline render-evidence` and
  `GET /v1/release-candidates/{release_id}/evidence.html`.
- 评委实时点击演示订单接口 live（demo-only，release-ready 后可多次执行，非
  verdict）:
  `POST /v1/release-candidates/{release_id}/demo-showcase-orders`,
  `GET /v1/release-candidates/{release_id}/demo-showcase-orders`, and
  per-attempt `evidence.html`.
- Durable release job/event endpoints live（demo-only，复用同一套 release gate
  和 Bitget demo 下单逻辑，非 verdict）:
  `POST /v1/release-candidates/{release_id}/jobs/execute-demo`,
  `POST /v1/release-candidates/{release_id}/jobs/showcase-order`,
  `POST /v1/release-candidates/{release_id}/jobs/{job_id}/cancel`,
  `GET /v1/release-candidates/{release_id}/jobs/{job_id}`,
  `GET /v1/release-candidates/{release_id}/jobs/{job_id}/events`, and
  `events.ndjson`; startup drains queued jobs, interrupted running jobs become
  `JOB_RECOVERY_REQUIRED`, and event reads validate the hash chain.
- Backend-only judge console live（server-rendered HTML，无前端框架，非
  verdict）:
  `GET /v1/judge/console` and `GET /v1/judge/releases/{release_id}`.
- Hackathon submission transparency pack live（离线可验，非 verdict）:
  `redline hackathon-pack` copies the verified release bundle, run evidence,
  attestation, docs, judge curl script, verify output, and showcase index into
  `artifacts/hackathon-submission-pack/`.
- Demo execution requires a receipt that verifies as:
  - `VerificationLevel.REPLAYED`
  - `VerificationStatus.VERIFIED`
  - `ReasonCode.PASS`
  - `chain_status=chained`
  - signed ledger attestation under a trust policy
- A successful demo order writes:
  - `exchange-preflight-evidence.json`
  - `execution-evidence.json`
  - `execution-ledger.jsonl`
  - `order-status-evidence.json`
  Preflight failures stop before Bitget order placement; transport timeouts
  after `clientOid` issuance recover through Bitget order-detail lookup or fail
  closed as `EXCHANGE_RECONCILIATION_REQUIRED`.
- A successful release evidence flow writes:
  - `release-evidence-bundle.json`
  - `release-evidence-manifest.json`
  - `release-audit-ledger.jsonl`
  - `release-simulation-evidence.json`
  - `release-risk-policy.json`
  - `release-decision-record.json`

## Gated

- Playbook upload/publish remains contract-faithful and gated behind the existing
  sponsor adapter and final-publish controls.
- Current Playbook publish/final live activation remains gated. Strategy
  submission evidence now has an import path for simulated-trading summaries,
  but the backend intentionally does not implement a full backtest engine or
  GetAgent Studio API integration.
- Mainnet order placement is blocked unless both controls are present:
  - `REDLINE_ALLOW_MAINNET_ORDER=1`
  - request body includes `confirm_mainnet_order=true`
- The execution gate defaults to `paptrading: 1` and a demo symbol. It rejects
  mainnet by default.
- `REDLINE_RELEASE_FREEZE=1` blocks approval. `REDLINE_EXECUTION_FREEZE=1`
  blocks release-level demo execution.

## Not A Verdict

Hash-only verification is integrity-only. It can prove that a receipt file has
not changed, but it cannot prove package-bound replay. Hash-only therefore
returns `unverified_no_verdict`, not `verified`, and cannot authorize execution.

The execution gate is downstream of the receipt. If verification fails, the gate
returns `blocked` with a reason code and never calls Bitget.

The release gate is downstream of both the receipt and release evidence. A
release candidate cannot approve or execute from a hash-only artifact,
`WITHHELD` run, missing simulation evidence, missing risk policy, stale
approval, or freeze state.

## Known Boundaries (post independent review, 2026-06-24)

Documented limitations confirmed by an independent verdict-path / security
review of the v2 backend (the review the implementing agent could not perform
on itself):

- **Receipt schema v3.3 is a breaking revision (v3.2 → v3.3).** v3.3 binds new
  fields (`prev_receipt_hash`; decision `verdict_tier` / `adjusted_size_cap`;
  leak-free replay fields; checkpoint `merkle_root`) into the canonical receipt
  hash. The `Receipt` model still *reads* v3.2 (model-level back-compat), but a
  pre-v3.3 receipt does **not** re-verify under the v3.3 verifier and must be
  re-issued. This is intentional and fail-closed: the v3.3 verifier does not
  vouch for receipts that lack v3.3 guarantees. Every shipped `artifacts/**`
  receipt is v3.3 and verifies zero-secret. Restoring cross-version
  verification would require switching the receipt hash to exclude-none
  semantics and regenerating every artifact (release-demo regeneration needs
  Bitget demo credentials) — deferred by decision.
- **Offline bundle / attestation verification is integrity-only unless a signer
  is pinned.** By default `verify-chain` / `verify-release-attestation` prove
  internal consistency and that the embedded Ed25519 signature matches the
  attestation's own public key — without a pin, a self-consistent bundle
  self-signed with an attacker's key would pass `ok=true`. Pass
  `--trusted-public-key <ed25519-public:...>` (supported on `verify-chain` and
  `verify-release-attestation`) to require that exact signer; a foreign or
  self-signed key then fails on a `trusted-key-pin` check. The live service is
  unaffected: genuine bundles are produced only after a full REPLAYED verify
  under a server-held trust policy before any order is placed.

## 评委 60 秒零密钥复核

This is the preferred judge path for checking the committed release evidence on
a clean machine. It is demo-only, tied to Bitget `paptrading: 1` artifacts, and
is **非 Bitget Playbook 正式发布**. It verifies existing public artifacts; it
does not place orders and 不需要 Bitget demo credentials.

```bash
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json
scripts/tamper-demo.sh
open artifacts/release-demo/current/evidence.html
```

Expected result:

- `verify-chain` returns a passing full-chain envelope for the committed
  release directory.
- `scripts/tamper-demo.sh` exits non-zero and prints the failed chain check and
  reason code after modifying a copy of the bundle.
- `evidence.html` renders the read-only judge comparison view; invalid or
  missing evidence must show `EVIDENCE INVALID`/blocked, not success.

## Demo Execution Environment

Required for real demo order placement:

```text
REDLINE_BITGET_DEMO_ACCESS_KEY
REDLINE_BITGET_DEMO_SECRET_KEY
REDLINE_BITGET_DEMO_PASSPHRASE
```

Safe defaults:

```text
REDLINE_BITGET_PAPTRADING=1
REDLINE_BITGET_BASE_URL=https://api.bitget.com
REDLINE_BITGET_DEMO_SYMBOL=BTCUSDT
REDLINE_BITGET_DEMO_SIZE=0.0001
REDLINE_BITGET_PRODUCT_TYPE=USDT-FUTURES
REDLINE_ALLOW_MAINNET_ORDER=
```

Run the one-command demo after exporting demo credentials:

```bash
scripts/execution-demo.sh
scripts/release-demo.sh
```

The script creates a chained signed PASS run, calls the service `/execute`
endpoint for `candidate_good`, prints a masked Bitget demo `order_id`, then
proves `candidate_bad` is blocked.

`scripts/release-demo.sh` performs the production-style release flow: create a
strategy version, create a release candidate, bind a Redline PASS run, import
simulation evidence, bind risk policy, approve, execute a Bitget demo order,
download and hash-check the release evidence bundle, show `candidate_bad`
blocked, and demonstrate freeze/kill switch behavior.

Backend-only verification commands:

```bash
uv run redline service-migrations --root artifacts/release-demo/current/service --json
uv run redline verify-release-bundle artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json --json
uv run redline verify-release-attestation artifacts/release-demo/current/service/releases/release-demo-good/release-attestation.json --bundle artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json --json
scripts/hackathon-submit-check.sh
```

## Source Note

Bitget REST details used by the adapter are recorded in
`BITGET_DEMO_TRADING_NOTES.md`.
