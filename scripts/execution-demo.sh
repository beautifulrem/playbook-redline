#!/usr/bin/env bash
set -euo pipefail

for name in REDLINE_BITGET_DEMO_ACCESS_KEY REDLINE_BITGET_DEMO_SECRET_KEY REDLINE_BITGET_DEMO_PASSPHRASE; do
  if [ -z "${!name:-}" ]; then
    echo "missing required env: ${name}" >&2
    exit 2
  fi
done

uv run --extra dev python - <<'PY'
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from redline.io_safety import atomic_write_text, ensure_safe_output_dir
from redline.models import LedgerCheckpoint
from redline.render import load_evidence_panel, render_evidence_comparison_html, write_evidence_html
from redline.runner import run_redline
from redline.service.app import create_app
from redline.service.config import ServiceConfig
from redline.trust import generate_trust_keypair, make_trust_policy, sign_checkpoint


ROOT = Path.cwd()
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"
ARTIFACT_ROOT = ROOT / "artifacts/execution-demo"
TOKEN = "redline-execution-demo"


def sign_run_checkpoint(run_dir: Path, private_key: str) -> None:
    checkpoint = LedgerCheckpoint.model_validate(json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8")))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="redline-execution-demo",
        trust_policy_id="execution-demo-policy",
        key_id="execution-demo-key",
        issuer="redline-execution-demo",
    )
    atomic_write_text(run_dir / "issuance-ledger.attestation.json", attestation.model_dump_json(indent=2) + "\n")


def wait_for_run(client: TestClient, run_id: str) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = client.get(f"/v1/runs/{run_id}", headers=headers())
        response.raise_for_status()
        payload = response.json()
        if payload["state"] in {"pass", "fail", "amber", "error"}:
            return payload
        time.sleep(0.1)
    raise TimeoutError(f"run did not finish: {run_id}")


def headers() -> dict[str, str]:
    return {"X-Redline-Token": TOKEN}


def mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


def execution_request() -> dict[str, str]:
    payload: dict[str, str] = {}
    if os.environ.get("REDLINE_BITGET_DEMO_SYMBOL"):
        payload["symbol"] = os.environ["REDLINE_BITGET_DEMO_SYMBOL"]
    if os.environ.get("REDLINE_BITGET_DEMO_SIZE"):
        payload["size"] = os.environ["REDLINE_BITGET_DEMO_SIZE"]
    return payload


ensure_safe_output_dir(ARTIFACT_ROOT)
work = Path(tempfile.mkdtemp(prefix="session-", dir=ARTIFACT_ROOT))
package = PACKAGE

private_key, public_key = generate_trust_keypair()
policy = make_trust_policy(
    policy_id="execution-demo-policy",
    key_id="execution-demo-key",
    public_key=public_key,
    issuer="redline-execution-demo",
)
policy_path = work / "trust-policy.json"
atomic_write_text(policy_path, policy.model_dump_json(indent=2) + "\n")

baseline_dir = work / "baseline"
baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=baseline_dir)
if baseline.receipt is None:
    raise RuntimeError("baseline did not produce a receipt")
sign_run_checkpoint(baseline_dir, private_key)

app = create_app(ServiceConfig(root=work / "service", token=TOKEN, workers=1))
client = TestClient(app)

created = client.post(
    "/v1/runs",
    headers=headers(),
    json={
        "package_path": str(package),
        "candidate": "candidate_good",
        "suite_path": str(SUITE),
        "spec_path": str(SPEC),
        "baseline_receipt_path": str(baseline_dir / "receipt.json"),
        "baseline_trust_policy_path": str(policy_path),
    },
)
created.raise_for_status()
good_run = wait_for_run(client, created.json()["run_id"])
if good_run["state"] != "pass":
    raise RuntimeError(f"candidate_good did not pass: {good_run['state']} {good_run.get('reason_code')}")
sign_run_checkpoint(Path(good_run["out_dir"]), private_key)

execute = client.post(f"/v1/runs/{good_run['run_id']}/execute", headers=headers(), json=execution_request())
execute.raise_for_status()
execute_payload = execute.json()
if not execute_payload["ok"]:
    raise RuntimeError(f"PASS execution was blocked: {execute_payload}")
order_id = execute_payload["evidence"]["bitget_order_id"]
evidence_path = Path(good_run["out_dir"]) / "execution-evidence.json"
print(json.dumps({
    "candidate_good": "placed",
    "run_id": good_run["run_id"],
    "masked_order_id": mask(order_id),
    "receipt_hash": execute_payload["evidence"]["receipt_hash"],
    "client_oid": execute_payload["evidence"]["client_oid"],
    "execution_evidence": str(evidence_path),
}, sort_keys=True))

bad_created = client.post(
    "/v1/runs",
    headers=headers(),
    json={
        "package_path": str(package),
        "candidate": "candidate_bad",
        "suite_path": str(SUITE),
        "spec_path": str(SPEC),
        "baseline_receipt_path": str(baseline_dir / "receipt.json"),
        "baseline_trust_policy_path": str(policy_path),
    },
)
bad_created.raise_for_status()
bad_run = wait_for_run(client, bad_created.json()["run_id"])
blocked = client.post(f"/v1/runs/{bad_run['run_id']}/execute", headers=headers(), json={})
blocked.raise_for_status()
blocked_payload = blocked.json()
if blocked_payload["ok"]:
    raise RuntimeError("candidate_bad unexpectedly placed an order")
print(json.dumps({
    "candidate_bad": "blocked",
    "run_id": bad_run["run_id"],
    "state": bad_run["state"],
    "reason_code": blocked_payload["reason_code"],
}, sort_keys=True))

html_path = work / "evidence.html"
write_evidence_html(
    html_path,
    render_evidence_comparison_html(
        load_evidence_panel(Path(good_run["out_dir"]), title="PASS -> Bitget demo order"),
        load_evidence_panel(Path(bad_run["out_dir"]), title="WITHHELD -> blocked before Bitget"),
    ),
)
print(json.dumps({"evidence_html": str(html_path)}, sort_keys=True))
PY
