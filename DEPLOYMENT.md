# Playbook Redline Deployment Runbook

Playbook Redline deploys as a containerized FastAPI service. The container path
is the primary deployment shape because Redline runs deterministic replay jobs,
writes receipt/proof artifacts, and needs a durable state directory. A
serverless function shape would make long-running jobs and artifact binding
less predictable.

The same image can run on Render, Fly.io, Railway, or any container host that
provides a persistent volume. Local development and CI fixture mode still use
the same HTTP API and proof kernel.

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
run, polls status, downloads artifacts, verifies artifact SHA-256 values,
replays the downloaded receipt with the local verifier, and calls sponsor
preflight with the demo genesis boundary explicitly enabled.

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

## Production Environment

Required:

- `REDLINE_SERVICE_ENV=production`
- `REDLINE_SERVICE_TOKEN`: non-default, at least 32 characters
- `REDLINE_SERVICE_ROOT`: persistent state root, default `/data/redline-service`

Recommended:

- `REDLINE_SERVICE_CORS_ORIGINS`: comma-separated frontend origins
- `REDLINE_SERVICE_WORKERS`: run worker count, default `2`
- `REDLINE_SERVICE_MAX_UPLOAD_BYTES`: upload/extracted archive limit
- `REDLINE_SERVICE_LOG_LEVEL`: `INFO`, `WARNING`, or `ERROR`

Live sponsor mode also needs:

- `REDLINE_BITGET_ACCESS_KEY`
- `REDLINE_BITGET_SECRET_KEY`
- `REDLINE_BITGET_PASSPHRASE`

Production refuses default demo tokens and wildcard CORS origins. Unknown server
errors are redacted from responses; use `x-request-id` and service logs for
debugging.

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

## Persistence Boundary

The current shipped adapters are:

- metadata store: `sqlite`
- artifact store: `local`

They sit behind `RunMetadataStore` and `ArtifactStore` protocols. A production
volume is enough for the hackathon demo. The next adapter step is Postgres for
run metadata plus S3/R2/Blob for artifact objects. Those modes are intentionally
not accepted by configuration until the adapters and hash-verifying download
path are implemented.

## Judge Demo Script

Use this sequence for a clean judging pass:

```bash
make install
make audit
make goldens-check
REDLINE_DEPLOYMENT_SMOKE_MODE=local make deployment-smoke
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
