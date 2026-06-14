# Playbook Redline Deployment Runbook

Playbook Redline deploys as a containerized FastAPI service. The container path
is the primary deployment shape because Redline runs deterministic replay jobs,
writes receipt/proof artifacts, and needs a durable state directory. A
serverless function shape would make long-running jobs and artifact binding
less predictable.

The selected remote target is Render. The repository includes `render.yaml`
because Render Blueprints can define the Docker web service, managed Postgres,
environment variables, and persistent disk in one Git-backed file. Local
development and CI fixture mode still use the same HTTP API and proof kernel.

Why Render over Fly.io or Railway for this backend:

- Render Blueprints keep the web service, Postgres, disk, and secrets prompt in
  one reviewer-visible file.
- Render Postgres exposes a single connection string, which maps directly to
  `REDLINE_DATABASE_URL`.
- Render persistent disks preserve local artifact files under one mounted path,
  which fits the current hash-verifying artifact download path without adding
  unverified object-storage behavior.

## One-Command Smoke

CI runs the Docker path:

```bash
make deployment-smoke
```

On a development machine without Docker, run the same production-style HTTP flow
through uvicorn:

```bash
REDLINE_DEPLOYMENT_SMOKE_MODE=local make deployment-smoke
```

The smoke test starts a real service, imports `fixtures/demo_pack`, creates a
run, verifies OpenAPI, polls status, downloads artifacts, verifies artifact
SHA-256 values, replays the downloaded receipt with the local verifier, and
calls sponsor preflight with the demo genesis boundary explicitly enabled.

Run the same flow against a deployed service:

```bash
REDLINE_REMOTE_BASE_URL=https://playbook-redline-api.onrender.com \
REDLINE_REMOTE_TOKEN=<service token> \
make remote-smoke
```

Then run the production-facing remote checks:

```bash
REDLINE_REMOTE_BASE_URL=https://playbook-redline-api.onrender.com \
REDLINE_REMOTE_TOKEN=<service token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
REDLINE_REMOTE_RATE_LIMIT_PROBES=130 \
make remote-production-check
```

`remote-production-check` verifies remote health, exact OpenAPI schema parity
with `schemas/service-openapi.json`, CORS for the frontend origin, wrong-token
401, missing-run 404, optional rate-limit 429, and redacted error envelopes.
Artifact hash-mismatch fail-closed behavior is covered by service tests because
creating the mismatch on a live service would require privileged artifact
tampering on the persistent disk.

GitHub Actions also exposes a manual `workflow_dispatch` remote smoke path gated
by `REDLINE_REMOTE_BASE_URL`, `REDLINE_REMOTE_TOKEN`, and
`REDLINE_REMOTE_FRONTEND_ORIGIN` repository secrets. Set
`remote_rate_limit_probes` to a value above the deployed
`REDLINE_SERVICE_RATE_LIMIT_PER_MINUTE` when you want the manual workflow to
verify 429 behavior.

## Container

```bash
docker build -t playbook-redline-service:local .
docker run --rm -p 8080:8080 \
  -e REDLINE_SERVICE_ENV=production \
  -e REDLINE_SERVICE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  -e REDLINE_SERVICE_CORS_ORIGINS=http://localhost:3000 \
  -v redline-service-data:/data/redline-service \
  playbook-redline-service:local
```

The image runs as a non-root user and stores service state under
`/data/redline-service`.

## Render

`render.yaml` provisions:

- Docker web service: `playbook-redline-api`
- Health check: `/health`
- Render Postgres database: `playbook-redline-db`
- Metadata store: `postgres`
- Artifact store: `local`, backed by a Render persistent disk mounted at
  `/data/redline-service`
- Generated `REDLINE_SERVICE_TOKEN`
- Dashboard-provided `REDLINE_SERVICE_CORS_ORIGINS`

Deploy sequence:

1. Validate the Blueprint locally if Render credentials are available:

```bash
make render-preflight
```

With `RENDER_API_KEY` plus `RENDER_OWNER_ID`, this target uses Render's
Blueprint validation API. Without Render credentials, it falls back to the
public Render schema plus project-specific checks for the expected web service,
Postgres database, persistent disk, and production environment variables.

2. Create a Render Blueprint from this repository.
3. Fill `REDLINE_SERVICE_CORS_ORIGINS` in the Render Dashboard.
4. Let Render generate `REDLINE_SERVICE_TOKEN`; copy it into the judging smoke
   environment or GitHub Actions secret.
5. After deploy, run:

```bash
curl -s https://<render-service>.onrender.com/health
REDLINE_REMOTE_BASE_URL=https://<render-service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
make remote-smoke
REDLINE_REMOTE_BASE_URL=https://<render-service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
make remote-production-check
```

Render Postgres should be accessed through its internal connection string from
the web service. External database access is not required for judging.

To configure GitHub Actions secrets and trigger the manual remote smoke in one
step:

```bash
REDLINE_REMOTE_BASE_URL=https://<render-service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
REDLINE_REMOTE_RATE_LIMIT_PROBES=130 \
make remote-smoke-actions
```

The target writes `REDLINE_REMOTE_BASE_URL`, `REDLINE_REMOTE_TOKEN`, and
`REDLINE_REMOTE_FRONTEND_ORIGIN` as repository secrets, triggers
`workflow_dispatch` with `remote_smoke=true`, and watches the run to completion.

## Production Environment

Required:

- `REDLINE_SERVICE_ENV=production`
- `REDLINE_SERVICE_TOKEN`: non-default, at least 32 characters
- `REDLINE_SERVICE_ROOT`: persistent state root, default `/data/redline-service`
- `REDLINE_SERVICE_METADATA_STORE`: `sqlite` for local/CI, `postgres` for Render
- `REDLINE_DATABASE_URL`: required when metadata store is `postgres`

Recommended:

- `REDLINE_SERVICE_CORS_ORIGINS`: comma-separated frontend origins
- `REDLINE_SERVICE_WORKERS`: run worker count, default `2`
- `REDLINE_SERVICE_MAX_UPLOAD_BYTES`: upload/extracted archive limit
- `REDLINE_SERVICE_LOG_LEVEL`: `INFO`, `WARNING`, or `ERROR`
- `REDLINE_SERVICE_RATE_LIMIT_PER_MINUTE`
- `REDLINE_SERVICE_MAX_PACKAGES`
- `REDLINE_SERVICE_MAX_ACTIVE_RUNS`
- `REDLINE_SERVICE_MAX_RUNS_TOTAL`
- `REDLINE_SERVICE_RUN_RETENTION_SECONDS`

Live sponsor mode also needs:

- `REDLINE_BITGET_ACCESS_KEY`
- `REDLINE_BITGET_SECRET_KEY`
- `REDLINE_BITGET_PASSPHRASE`

Production refuses default demo tokens and wildcard CORS origins. Unknown server
errors are redacted from responses; use `x-request-id` and service logs for
debugging.

## Job Queue

Runs are stored as database rows and claimed by workers from the metadata store.
On startup, interrupted `running` jobs are requeued before workers start
claiming new jobs. This gives the container deployment a DB-backed job boundary
without adding Redis, Celery, or another queue service for the hackathon demo.

The service still returns the same terminal states:

- `queued`
- `running`
- `pass`
- `amber`
- `fail`
- `error`

## Frontend Contract Flow

The frontend should call:

1. `POST /v1/packages/import` or `POST /v1/packages/upload`
2. `POST /v1/runs`
3. `GET /v1/runs/{run_id}` until `state` is terminal
4. `GET /v1/runs/{run_id}/artifacts`
5. `GET /v1/runs/{run_id}/artifacts/{artifact_id}`
6. `POST /v1/runs/{run_id}/sponsor-readback` for preflight/live readback

Run the exact frontend-facing flow against any service URL:

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run python scripts/frontend-demo-flow.py \
  --base-url http://127.0.0.1:8080 \
  --token redline-demo \
  --allow-demo-baseline-genesis
```

After the frontend origin is known, verify the deployed contract and CORS:

```bash
REDLINE_REMOTE_BASE_URL=https://<render-service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
make remote-production-check
```

## Persistence Boundary

The shipped adapters are:

- metadata store: `sqlite`
- metadata store: `postgres`
- artifact store: `local`

They sit behind `RunMetadataStore` and `ArtifactStore` protocols. Render uses
Postgres for metadata and a persistent disk for local artifacts.

Object storage design boundary:

- R2/S3/Blob should be added as a new `ArtifactStore` implementation.
- Workers should still write to a safe local staging directory first.
- After `build_artifact_manifest`, every manifest entry must be uploaded with
  its SHA-256 and byte count.
- Downloads must stream or stage the object and recompute SHA-256 before
  returning it.
- Configuration must continue to reject unsupported artifact store modes until
  their hash-verifying download path has tests.

This keeps the current production path honest: durable Render disk today, object
storage adapter later, no unverified remote artifact shortcut.

## Retention

Prune expired terminal runs and artifact directories:

```bash
REDLINE_SERVICE_ROOT=/data/redline-service \
REDLINE_SERVICE_METADATA_STORE=postgres \
REDLINE_DATABASE_URL=<internal database url> \
uv run python scripts/service-cleanup.py --older-than-seconds 604800
```

The cleanup command only deletes terminal runs and refuses paths outside
`REDLINE_SERVICE_ROOT/runs`.

## Judge Demo Script

Use this sequence for a clean judging pass:

```bash
make install
make audit
make goldens-check
REDLINE_DEPLOYMENT_SMOKE_MODE=local make deployment-smoke
REDLINE_REMOTE_BASE_URL=https://<render-service>.onrender.com \
REDLINE_REMOTE_TOKEN=<token> \
REDLINE_REMOTE_FRONTEND_ORIGIN=https://<frontend-origin> \
make remote-smoke remote-production-check
```

Expected service result:

- run `state`: `amber`
- `reason_code`: `BASELINE_GENESIS`
- downloaded receipt hash matches the run summary
- replayed receipt returns the same genesis boundary
- sponsor preflight returns `ok: true` only because
  `allow_demo_baseline_genesis` is explicit

For final publish evidence, use a chained `PASS` receipt and signed ledger
attestation. The bundled genesis fixture is a demo boundary, not final publish
proof.
