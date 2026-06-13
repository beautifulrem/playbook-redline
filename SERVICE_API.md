# Playbook Redline Service API Contract

The service backend wraps the existing Redline proof engine. HTTP handlers
enqueue runs, persist status, and expose artifacts; verdicts still come from
`redline.runner.run_redline` and the existing receipt/proof/report schemas.

## Runtime

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run redline-api
```

Default local URL: `http://127.0.0.1:8080`.

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

## Core Demo Flow

1. Import or upload a playbook package.
2. Create a run with baseline/candidate/suite/spec.
3. Poll the run until `state` is `pass`, `amber`, `fail`, or `error`.
4. Read the artifact manifest.
5. Download `receipt`, `report`, `envelope`, ledger checkpoint, or proof files.
6. Optionally call sponsor preflight/live readback. Live mode never returns a
   pseudo-success when credentials or proof bindings are missing.

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
