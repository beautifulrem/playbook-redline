#!/usr/bin/env bash
set -euo pipefail

for name in REDLINE_BITGET_DEMO_ACCESS_KEY REDLINE_BITGET_DEMO_SECRET_KEY REDLINE_BITGET_DEMO_PASSPHRASE; do
  if [ -z "${!name:-}" ]; then
    echo "missing required env: ${name}" >&2
    exit 2
  fi
done

export UV_CACHE_DIR="${UV_CACHE_DIR:-.uv-cache}"

uv run --extra dev python - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from fastapi.testclient import TestClient

from redline.canonical import hash_file
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
ARTIFACT_ROOT = ROOT / "artifacts/release-demo"
CURRENT_DIR = ARTIFACT_ROOT / "current"
TOKEN = "redline-release-demo"
SESSION_ID = str(int(time.time() * 1000))


def headers() -> dict[str, str]:
    return {"X-Redline-Token": TOKEN}


def mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


def sign_run_checkpoint(run_dir: Path, private_key: str) -> None:
    checkpoint = LedgerCheckpoint.model_validate(json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8")))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer="redline-release-demo",
        trust_policy_id="release-demo-policy",
        key_id="release-demo-key",
        issuer="redline-release-demo",
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


def execution_request() -> dict[str, str]:
    sizes = ["0.0002", "0.0003", "0.0004", "0.0005"]
    default_size = sizes[int(SESSION_ID[-1]) % len(sizes)]
    payload: dict[str, str] = {
        "side": os.environ.get("REDLINE_RELEASE_DEMO_SIDE", "sell"),
        "size": os.environ.get("REDLINE_RELEASE_DEMO_SIZE") or os.environ.get("REDLINE_BITGET_DEMO_SIZE", default_size),
    }
    if os.environ.get("REDLINE_BITGET_DEMO_SYMBOL"):
        payload["symbol"] = os.environ["REDLINE_BITGET_DEMO_SYMBOL"]
    return payload


def simulation_payload() -> dict[str, object]:
    return {
        "source": "local_backtest",
        "period_start": "2026-06-01",
        "period_end": "2026-06-22",
        "market": "bitget-demo",
        "symbol": os.environ.get("REDLINE_BITGET_DEMO_SYMBOL", "BTCUSDT"),
        "trade_count": 12,
        "pnl": "42.50",
        "max_drawdown": "3.20",
        "win_rate": "0.58",
        "source_file_hash": "sha256:" + "8" * 64,
    }


def risk_policy_payload() -> dict[str, object]:
    symbol = os.environ.get("REDLINE_BITGET_DEMO_SYMBOL", "BTCUSDT")
    return {
        "max_order_notional_usdt": "20",
        "allowed_product_types": ["USDT-FUTURES"],
        "allowed_symbols": sorted({"BTCUSDT", "ETHUSDT", "SOLUSDT", symbol}),
        "require_simulation_evidence": True,
        "require_demo_execution": True,
        "require_human_approval": True,
        "mainnet_enabled": False,
        "expected_order_notional_usdt": "5",
    }


def json_line(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def remove_safe_tree(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing to remove symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise RuntimeError(f"refusing to remove non-directory: {path}")
        shutil.rmtree(path)


def publish_current_session(work_dir: Path) -> None:
    tmp_current = ARTIFACT_ROOT / f".current-{SESSION_ID}.tmp"
    old_current = ARTIFACT_ROOT / f".current-{SESSION_ID}.old"
    remove_safe_tree(tmp_current)
    remove_safe_tree(old_current)
    shutil.copytree(work_dir, tmp_current, symlinks=False)
    if CURRENT_DIR.is_symlink():
        raise RuntimeError(f"refusing to replace symlink: {CURRENT_DIR}")
    if CURRENT_DIR.exists():
        if not CURRENT_DIR.is_dir():
            raise RuntimeError(f"refusing to replace non-directory: {CURRENT_DIR}")
        CURRENT_DIR.rename(old_current)
    try:
        tmp_current.rename(CURRENT_DIR)
    except Exception:
        if old_current.exists() and not CURRENT_DIR.exists():
            old_current.rename(CURRENT_DIR)
        raise
    remove_safe_tree(old_current)


ensure_safe_output_dir(ARTIFACT_ROOT)
work = Path(os.environ.get("REDLINE_RELEASE_DEMO_WORKDIR", str(ARTIFACT_ROOT / f"session-{SESSION_ID}")))
ensure_safe_output_dir(work)

private_key, public_key = generate_trust_keypair()
policy = make_trust_policy(
    policy_id="release-demo-policy",
    key_id="release-demo-key",
    public_key=public_key,
    issuer="redline-release-demo",
)
policy_path = work / f"trust-policy-{SESSION_ID}.json"
atomic_write_text(policy_path, policy.model_dump_json(indent=2) + "\n")

baseline_dir = work / "baselines" / SESSION_ID
baseline = run_redline(package_dir=PACKAGE, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=baseline_dir)
if baseline.receipt is None:
    raise RuntimeError(f"baseline did not produce a receipt: {baseline.envelope.status} {baseline.envelope.reason_code}")
sign_run_checkpoint(baseline_dir, private_key)

app = create_app(ServiceConfig(root=work / "service", token=TOKEN, workers=1))
client = TestClient(app)

version = client.post(
    "/v1/strategy-versions",
    headers=headers(),
    json={
        "version_id": "release-demo-v1",
        "strategy_id": "release-demo-strategy",
        "package_path": str(PACKAGE),
        "source_kind": "fixture",
        "created_by": "strategy-author",
        "metadata": {"name": "Release Demo Strategy", "market": "bitget-demo"},
    },
)
version.raise_for_status()

release = client.post(
    "/v1/release-candidates",
    headers=headers(),
    json={
        "release_id": "release-demo-good",
        "version_id": "release-demo-v1",
        "created_by": "strategy-author",
        "metadata": {"hackathon": "bitget-ai-s1"},
    },
)
release.raise_for_status()
release_id = release.json()["release_id"]
release_payload = release.json()

if release_payload.get("execution_evidence") is None:
    good_created = client.post(
        "/v1/runs",
        headers=headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
            "baseline_receipt_path": str(baseline_dir / "receipt.json"),
            "baseline_trust_policy_path": str(policy_path),
        },
    )
    good_created.raise_for_status()
    good_run = wait_for_run(client, good_created.json()["run_id"])
    if good_run["state"] != "pass":
        raise RuntimeError(f"candidate_good did not pass: {good_run['state']} {good_run.get('reason_code')}")
    sign_run_checkpoint(Path(good_run["out_dir"]), private_key)

    for path, payload in [
        (f"/v1/release-candidates/{release_id}/redline-run", {"run_id": good_run["run_id"]}),
        (f"/v1/release-candidates/{release_id}/simulation-evidence", simulation_payload()),
        (f"/v1/release-candidates/{release_id}/risk-policy", risk_policy_payload()),
        (f"/v1/release-candidates/{release_id}/approve", {"reviewer_id": "release-reviewer", "comment": "hackathon demo approval"}),
    ]:
        response = client.post(path, headers=headers(), json=payload)
        response.raise_for_status()
        body = response.json()
        if not body.get("ok"):
            raise RuntimeError(f"release step blocked at {path}: {body}")

    execute = client.post(f"/v1/release-candidates/{release_id}/execute-demo", headers=headers(), json=execution_request())
    execute.raise_for_status()
    execute_payload = execute.json()
    if not execute_payload["ok"]:
        raise RuntimeError(f"release demo execution blocked: {execute_payload}")
else:
    good_run = {"run_id": release_payload.get("execution_run_id") or release_payload["execution_evidence"].get("run_id")}
    execute_payload = {"ok": True, "evidence": release_payload["execution_evidence"]}

second_execute = client.post(f"/v1/release-candidates/{release_id}/execute-demo", headers=headers(), json=execution_request())
second_execute.raise_for_status()
if second_execute.json()["evidence"]["client_oid"] != execute_payload["evidence"]["client_oid"]:
    raise RuntimeError("release execute-demo was not idempotent")

showcase_orders = []
for index, payload in enumerate(
    [
        {"side": "buy", "size": "0.0001"},
        {"side": "sell", "size": "0.0001"},
        {"side": "buy", "size": "0.0002"},
    ],
    start=1,
):
    approval = client.post(
        f"/v1/release-candidates/{release_id}/approve",
        headers=headers(),
        json={"reviewer_id": "release-reviewer", "comment": f"hackathon showcase approval {index}"},
    )
    approval.raise_for_status()
    approval_payload = approval.json()
    if not approval_payload.get("ok"):
        raise RuntimeError(f"release showcase approval blocked: {approval_payload}")
    showcase = client.post(
        f"/v1/release-candidates/{release_id}/demo-showcase-orders",
        headers={**headers(), "Idempotency-Key": f"{SESSION_ID}-showcase-{index}"},
        json=payload,
    )
    showcase.raise_for_status()
    showcase_payload = showcase.json()
    if not showcase_payload["ok"]:
        raise RuntimeError(f"release showcase demo execution blocked: {showcase_payload}")
    evidence = showcase_payload["evidence"]
    showcase_orders.append(
        {
            "attempt_id": evidence["attempt_id"],
            "side": payload["side"],
            "size": payload["size"],
            "masked_order_id": mask(evidence["bitget_order_id"]),
            "client_oid": evidence["client_oid"],
            "evidence_html_path": evidence["evidence_html_path"],
        }
    )

evidence_response = client.get(f"/v1/release-candidates/{release_id}/evidence", headers=headers())
evidence_response.raise_for_status()
download_hash = "sha256:" + hashlib.sha256(evidence_response.content).hexdigest()
release_after_evidence = client.get(f"/v1/release-candidates/{release_id}", headers=headers())
release_after_evidence.raise_for_status()
release_payload = release_after_evidence.json()
bundle_path = work / "service" / "releases" / release_id / "release-evidence-bundle.json"
manifest_hash = release_payload["evidence_manifest_hash"]
if hash_file(bundle_path) != download_hash:
    raise RuntimeError("downloaded release evidence bundle hash mismatch")

attestation_response = client.post(f"/v1/release-candidates/{release_id}/attest", headers=headers(), json={})
attestation_response.raise_for_status()
attestation_payload = attestation_response.json()
if not attestation_payload["ok"]:
    raise RuntimeError(f"release attestation failed: {attestation_payload}")

json_line(
    {
        "candidate_good": "release_ready",
        "release_candidate_id": release_id,
        "run_id": good_run["run_id"],
        "masked_order_id": mask(execute_payload["evidence"]["bitget_order_id"]),
        "client_oid": execute_payload["evidence"]["client_oid"],
        "showcase_orders": showcase_orders,
        "evidence_bundle_path": str(bundle_path),
        "bundle_hash": download_hash,
        "manifest_hash": manifest_hash,
        "attestation_hash": attestation_payload["evidence"]["attestation_hash"],
    }
)

bad_created = client.post(
    "/v1/runs",
    headers=headers(),
    json={
        "package_path": str(PACKAGE),
        "candidate": "candidate_bad",
        "suite_path": str(SUITE),
        "spec_path": str(SPEC),
        "baseline_receipt_path": str(baseline_dir / "receipt.json"),
        "baseline_trust_policy_path": str(policy_path),
    },
)
bad_created.raise_for_status()
bad_run = wait_for_run(client, bad_created.json()["run_id"])
bad_release = client.post(
    "/v1/release-candidates",
    headers=headers(),
    json={"release_id": "release-demo-bad", "version_id": "release-demo-v1", "created_by": "strategy-author"},
)
bad_release.raise_for_status()
bad_bound = client.post(
    "/v1/release-candidates/release-demo-bad/redline-run",
    headers=headers(),
    json={"run_id": bad_run["run_id"]},
)
bad_bound.raise_for_status()
json_line(
    {
        "candidate_bad": "blocked",
        "release_candidate_id": "release-demo-bad",
        "run_id": bad_run["run_id"],
        "state": bad_bound.json()["state"],
        "reason_code": bad_run.get("reason_code"),
    }
)

freeze_release_id = f"release-demo-freeze-{int(time.time())}"
freeze_release = client.post(
    "/v1/release-candidates",
    headers=headers(),
    json={"release_id": freeze_release_id, "version_id": "release-demo-v1", "created_by": "strategy-author"},
)
freeze_release.raise_for_status()
os.environ["REDLINE_RELEASE_FREEZE"] = "1"
freeze_approval = client.post(
    f"/v1/release-candidates/{freeze_release_id}/approve",
    headers=headers(),
    json={"reviewer_id": "release-reviewer", "comment": "freeze check"},
)
freeze_approval.raise_for_status()
os.environ["REDLINE_RELEASE_FREEZE"] = "0"
os.environ["REDLINE_EXECUTION_FREEZE"] = "1"
freeze_execute = client.post(f"/v1/release-candidates/{freeze_release_id}/execute-demo", headers=headers(), json=execution_request())
freeze_execute.raise_for_status()
os.environ["REDLINE_EXECUTION_FREEZE"] = "0"
kill = client.post(f"/v1/release-candidates/{freeze_release_id}/kill", headers=headers())
kill.raise_for_status()
json_line(
    {
        "freeze_and_kill_switch": "blocked",
        "release_freeze_reason": freeze_approval.json().get("reason_code"),
        "execution_freeze_reason": freeze_execute.json().get("reason_code"),
        "kill_state": kill.json()["state"],
    }
)

good_run_dir = Path(good_run.get("out_dir") or (work / "service" / "runs" / good_run["run_id"]))
bad_run_dir = Path(bad_run["out_dir"])
html_path = work / "evidence.html"
write_evidence_html(
    html_path,
    render_evidence_comparison_html(
        load_evidence_panel(good_run_dir, title="PASS -> Bitget demo order"),
        load_evidence_panel(bad_run_dir, title="WITHHELD -> blocked before Bitget"),
    ),
)
publish_current_session(work)
json_line(
    {
        "evidence_html": str(html_path),
        "current_release_dir": str(CURRENT_DIR / "service" / "releases" / release_id),
        "current_evidence_html": str(CURRENT_DIR / "evidence.html"),
    }
)
PY
