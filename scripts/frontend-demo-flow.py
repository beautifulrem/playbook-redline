#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

from redline.models import ReasonCode, VerificationLevel
from redline.verifier import verify


TERMINAL_STATES = {"pass", "amber", "fail", "error"}


def main() -> int:
    args = _parse_args()
    client = HttpClient(base_url=args.base_url.rstrip("/"), token=args.token)
    health = client.json("GET", "/health")
    if health.get("ok") is not True:
        raise RuntimeError(f"service is unhealthy: {health}")

    package = client.json("POST", "/v1/packages/import", {"package_path": args.package_path})
    run = client.json(
        "POST",
        "/v1/runs",
        {
            "package_id": package["package_id"],
            "baseline": args.baseline,
            "candidate": args.candidate,
            "suite_path": args.suite,
            "spec_path": args.spec,
        },
    )
    run = _poll_run(client, run["run_id"], timeout_seconds=args.timeout_seconds)
    if run["state"] != args.expected_state or run["reason_code"] != args.expected_reason:
        raise RuntimeError(f"unexpected run result: {run}")

    manifest = client.json("GET", f"/v1/runs/{run['run_id']}/artifacts")
    with tempfile.TemporaryDirectory(prefix="redline-frontend-flow.") as tmp:
        artifact_root = Path(tmp)
        downloaded = _download_artifacts(client, artifact_root=artifact_root, manifest=manifest)
        receipt_path = downloaded["receipt"]
        report_path = downloaded["report"]
        replay = verify(
            receipt_path=receipt_path,
            package=Path(args.replay_package),
            suite_path=Path(args.suite),
            spec_path=Path(args.spec),
            report_path=report_path,
            ledger_checkpoint_path=downloaded.get("issuance-ledger.checkpoint.json"),
            level=VerificationLevel.REPLAYED,
        )
        if replay.reason_code != ReasonCode(args.expected_reason) or replay.proof_coverage != "complete":
            raise RuntimeError(f"receipt replay did not match service verdict: {replay.model_dump(mode='json')}")

    sponsor = client.json(
        "POST",
        f"/v1/runs/{run['run_id']}/sponsor-readback",
        {"mode": "preflight", "allow_demo_baseline_genesis": args.allow_demo_baseline_genesis},
    )
    if sponsor.get("ok") is not True:
        raise RuntimeError(f"sponsor preflight failed: {sponsor}")

    print(
        json.dumps(
            {
                "ok": True,
                "run_id": run["run_id"],
                "state": run["state"],
                "reason_code": run["reason_code"],
                "receipt_hash": run["receipt_hash"],
                "report_hash": run["report_hash"],
                "replay_status": replay.status.value,
                "sponsor_state": sponsor["state"],
            },
            sort_keys=True,
        )
    )
    return 0


class HttpClient:
    def __init__(self, *, base_url: str, token: str) -> None:
        self.base_url = base_url
        self.token = token

    def json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = self._headers(json_body=payload is not None)
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} failed with {exc.code}: {body}") from exc

    def bytes(self, path: str) -> bytes:
        request = urllib.request.Request(f"{self.base_url}{path}", headers=self._headers(json_body=False), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GET {path} failed with {exc.code}: {body}") from exc

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        headers = {"x-redline-token": self.token, "x-request-id": f"frontend-flow-{int(time.time() * 1000)}"}
        if json_body:
            headers["content-type"] = "application/json"
        return headers


def _poll_run(client: HttpClient, run_id: str, *, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        run = client.json("GET", f"/v1/runs/{run_id}")
        if run["state"] in TERMINAL_STATES:
            return run
        if time.monotonic() > deadline:
            raise RuntimeError(f"run did not finish before timeout: {run_id}")
        time.sleep(0.2)


def _download_artifacts(client: HttpClient, *, artifact_root: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    downloaded: dict[str, Path] = {}
    for item in manifest["artifacts"]:
        rel_path = _safe_rel_path(item["path"])
        target = artifact_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = client.bytes(item["download_url"])
        actual_hash = _sha256(data)
        if actual_hash != item["sha256"]:
            raise RuntimeError(f"artifact hash mismatch for {item['artifact_id']}: {actual_hash} != {item['sha256']}")
        target.write_bytes(data)
        downloaded[item["artifact_id"]] = target
        downloaded[item["path"]] = target
    for required in {"receipt", "report", "issuance-ledger-checkpoint"}:
        if required not in downloaded:
            raise RuntimeError(f"required artifact is missing: {required}")
    return downloaded


def _safe_rel_path(value: str) -> Path:
    raw = PurePosixPath(value)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise RuntimeError(f"unsafe artifact path in manifest: {value}")
    return Path(*raw.parts)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the frontend-facing Redline service demo flow.")
    parser.add_argument("--base-url", default=os.environ.get("REDLINE_SERVICE_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--token", default=os.environ.get("REDLINE_SERVICE_TOKEN", "redline-demo"))
    parser.add_argument("--package-path", default="fixtures/demo_pack", help="Package path as seen by the service process.")
    parser.add_argument("--replay-package", default="fixtures/demo_pack", help="Package path used by the local verifier.")
    parser.add_argument("--baseline", default="baseline")
    parser.add_argument("--candidate", default="candidate_good")
    parser.add_argument("--suite", default="fixtures/suites/demo_suite.json")
    parser.add_argument("--spec", default="fixtures/specs/redline_spec.json")
    parser.add_argument("--expected-state", default="amber")
    parser.add_argument("--expected-reason", default=ReasonCode.BASELINE_GENESIS.value)
    parser.add_argument("--timeout-seconds", type=float, default=45)
    parser.add_argument("--allow-demo-baseline-genesis", action="store_true", default=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        raise
