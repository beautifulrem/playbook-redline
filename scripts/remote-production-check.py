#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_PATHS = {
    "/v1/packages/import",
    "/v1/packages/upload",
    "/v1/auth/dev-login",
    "/v1/auth/login/github",
    "/v1/auth/callback/github",
    "/v1/auth/logout",
    "/v1/auth/me",
    "/v1/runs",
    "/v1/runs/{run_id}",
    "/v1/runs/{run_id}/artifacts",
    "/v1/runs/{run_id}/artifacts/{artifact_id}",
    "/v1/runs/{run_id}/execute",
    "/v1/runs/{run_id}/sponsor-readback",
    "/v1/strategy-versions",
    "/v1/strategy-versions/{version_id}",
    "/v1/release-candidates",
    "/v1/release-candidates/{release_id}",
    "/v1/release-candidates/{release_id}/redline-run",
    "/v1/release-candidates/{release_id}/simulation-evidence",
    "/v1/release-candidates/{release_id}/simulation-evidence-file",
    "/v1/release-candidates/{release_id}/risk-policy",
    "/v1/release-candidates/{release_id}/approve",
    "/v1/release-candidates/{release_id}/reject",
    "/v1/release-candidates/{release_id}/execute-demo",
    "/v1/release-candidates/{release_id}/demo-showcase-orders",
    "/v1/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html",
    "/v1/release-candidates/{release_id}/jobs/showcase-order",
    "/v1/release-candidates/{release_id}/jobs",
    "/v1/release-candidates/{release_id}/jobs/{job_id}",
    "/v1/release-candidates/{release_id}/jobs/{job_id}/cancel",
    "/v1/release-candidates/{release_id}/jobs/{job_id}/events",
    "/v1/release-candidates/{release_id}/jobs/{job_id}/events.ndjson",
    "/v1/release-candidates/{release_id}/attest",
    "/v1/release-candidates/{release_id}/attestation",
    "/v1/release-candidates/{release_id}/attestation.html",
    "/v1/judge/console",
    "/v1/judge/releases/{release_id}",
    "/v1/release-candidates/{release_id}/kill",
    "/v1/release-candidates/{release_id}/evidence",
    "/v1/release-candidates/{release_id}/evidence.html",
    "/v1/release-candidates/{release_id}/audit-ledger",
    "/v1/release-safety",
}

REDACTION_DENYLIST = (
    "traceback",
    'file "',
    "/volumes/",
    "/users/",
    "psycopg.",
    "sqlite3.",
)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> dict[str, Any]:
        return json.loads(self.text())


class HttpClient:
    def __init__(self, *, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        token: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["x-redline-token"] = token
        if payload is not None:
            request_headers["content-type"] = "application/json"
        request_headers.setdefault("x-request-id", f"remote-production-check-{int(time.time() * 1000)}")
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return HttpResponse(
                    status=response.status,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=response.read(),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status=exc.code,
                headers={key.lower(): value for key, value in exc.headers.items()},
                body=exc.read(),
            )

    def json(self, method: str, path: str, *, token: str | None = None) -> dict[str, Any]:
        response = self.request(method, path, token=token)
        if response.status >= 400:
            raise RuntimeError(f"{method} {path} failed with {response.status}: {response.text()}")
        return response.json()


def main() -> int:
    args = _parse_args()
    client = HttpClient(base_url=args.base_url, token=args.token)
    result: dict[str, Any] = {"ok": True, "base_url": args.base_url.rstrip("/"), "checks": {}}

    health = client.json("GET", "/health")
    if health.get("ok") is not True:
        raise RuntimeError(f"remote health is not ok: {health}")
    result["checks"]["health"] = health

    remote_openapi = client.json("GET", "/openapi.json")
    _assert_openapi_contract(remote_openapi, schema_path=args.schema)
    result["checks"]["openapi"] = {"paths_checked": sorted(REQUIRED_PATHS), "schema": str(args.schema)}

    if args.frontend_origin:
        _assert_cors(client, origin=args.frontend_origin)
        result["checks"]["cors"] = {"origin": args.frontend_origin}
    elif args.require_cors:
        raise RuntimeError("REDLINE_REMOTE_FRONTEND_ORIGIN or --frontend-origin is required when --require-cors is set")
    else:
        result["checks"]["cors"] = {"skipped": True}

    _assert_error_response(
        client.request("GET", "/v1/runs", token="definitely-wrong-redline-token"),
        expected_status=401,
        label="wrong token",
    )
    result["checks"]["wrong_token"] = {"status": 401}

    missing_run = f"run_missing_{int(time.time() * 1000)}"
    _assert_error_response(
        client.request("GET", f"/v1/runs/{missing_run}", token=args.token),
        expected_status=404,
        label="missing run",
    )
    result["checks"]["missing_run"] = {"status": 404}

    if args.rate_limit_probes > 0:
        _assert_rate_limit(client, token=args.token, probes=args.rate_limit_probes)
        result["checks"]["rate_limit"] = {"probes": args.rate_limit_probes, "status": 429}
    else:
        result["checks"]["rate_limit"] = {"skipped": True}

    print(json.dumps(result, sort_keys=True))
    return 0


def _assert_openapi_contract(remote_openapi: dict[str, Any], *, schema_path: Path) -> None:
    paths = remote_openapi.get("paths") or {}
    missing = sorted(REQUIRED_PATHS.difference(paths))
    if missing:
        raise RuntimeError(f"remote OpenAPI is missing frontend paths: {missing}")
    expected = json.loads(schema_path.read_text(encoding="utf-8"))
    if _normalized_json(remote_openapi) != _normalized_json(expected):
        remote_paths = set((remote_openapi.get("paths") or {}).keys())
        expected_paths = set((expected.get("paths") or {}).keys())
        raise RuntimeError(
            "remote OpenAPI differs from checked-in schema: "
            f"missing={sorted(expected_paths - remote_paths)} extra={sorted(remote_paths - expected_paths)}"
        )


def _assert_cors(client: HttpClient, *, origin: str) -> None:
    response = client.request(
        "OPTIONS",
        "/v1/runs",
        headers={
            "origin": origin,
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-redline-token,x-request-id",
        },
    )
    if response.status not in {200, 204}:
        raise RuntimeError(f"CORS preflight failed with {response.status}: {response.text()}")
    allow_origin = response.headers.get("access-control-allow-origin")
    if allow_origin != origin:
        raise RuntimeError(f"CORS allow-origin mismatch: {allow_origin!r} != {origin!r}")
    allow_headers = response.headers.get("access-control-allow-headers", "").lower()
    for header in {"content-type", "x-redline-token", "x-request-id"}:
        if header not in allow_headers:
            raise RuntimeError(f"CORS preflight did not allow {header}: {allow_headers}")


def _assert_error_response(response: HttpResponse, *, expected_status: int, label: str) -> None:
    if response.status != expected_status:
        raise RuntimeError(f"{label} expected HTTP {expected_status}, got {response.status}: {response.text()}")
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} did not return JSON: {response.text()}") from exc
    if payload.get("ok") is not False:
        raise RuntimeError(f"{label} did not return the Redline error envelope: {payload}")
    _assert_redacted(response.text(), label=label)


def _assert_rate_limit(client: HttpClient, *, token: str, probes: int) -> None:
    last_response: HttpResponse | None = None
    for _ in range(probes):
        last_response = client.request("GET", "/v1/runs?limit=1", token=token)
        if last_response.status == 429:
            _assert_error_response(last_response, expected_status=429, label="rate limit")
            return
        if last_response.status >= 500:
            raise RuntimeError(f"rate-limit probe hit server error {last_response.status}: {last_response.text()}")
    status = None if last_response is None else last_response.status
    raise RuntimeError(f"rate limit did not trigger within {probes} probes; last_status={status}")


def _assert_redacted(body: str, *, label: str) -> None:
    lowered = body.lower()
    leaked = [needle for needle in REDACTION_DENYLIST if needle in lowered]
    if leaked:
        raise RuntimeError(f"{label} response appears to expose internals: {leaked}")


def _normalized_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _parse_args() -> argparse.Namespace:
    base_url = os.environ.get("REDLINE_REMOTE_BASE_URL") or os.environ.get("REDLINE_SERVICE_BASE_URL")
    token = os.environ.get("REDLINE_REMOTE_TOKEN") or os.environ.get("REDLINE_SERVICE_TOKEN")
    frontend_origin = os.environ.get("REDLINE_REMOTE_FRONTEND_ORIGIN") or os.environ.get("REDLINE_SERVICE_FRONTEND_ORIGIN")
    parser = argparse.ArgumentParser(description="Verify a deployed Redline service beyond the happy-path smoke flow.")
    parser.add_argument("--base-url", default=base_url)
    parser.add_argument("--token", default=token)
    parser.add_argument("--frontend-origin", default=frontend_origin)
    parser.add_argument("--schema", type=Path, default=Path("schemas/service-openapi.json"))
    parser.add_argument("--require-cors", action="store_true")
    parser.add_argument(
        "--rate-limit-probes",
        type=int,
        default=int(os.environ.get("REDLINE_REMOTE_RATE_LIMIT_PROBES", "0")),
        help="Number of authenticated requests to issue while expecting at least one 429. Use 0 to skip.",
    )
    args = parser.parse_args()
    if not args.base_url:
        parser.error("REDLINE_REMOTE_BASE_URL or --base-url is required")
    if not args.token:
        parser.error("REDLINE_REMOTE_TOKEN or --token is required")
    if args.rate_limit_probes < 0:
        parser.error("--rate-limit-probes must be non-negative")
    if not args.schema.is_file():
        parser.error(f"schema file not found: {args.schema}")
    return args


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        raise
