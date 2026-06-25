from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import time
import urllib.parse
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import redline.service.app as service_app
from redline.cli import app as cli_app
from redline.service.cleanup import cleanup_expired_runs
from redline.service.app import create_app
from redline.service.config import ServiceConfig
from redline.service.migrations import CURRENT_SCHEMA_VERSION, expected_migration_versions
from redline.service.auth import parse_service_tokens
from redline.service.release import compute_release_tier, verify_release_evidence_bundle
from redline.service.storage import LocalArtifactStore, create_artifact_store, create_metadata_store
from redline.service.postgres_store import PostgresServiceStore
from redline.service.models import (
    ArtifactInfo,
    ArtifactManifest,
    ExecutionResponse,
    PackageResponse,
    ReleaseCandidateResponse,
    ReleaseJobStatus,
    ReleaseJobType,
    ReleaseState,
    ReleaseTier,
    RunCreateRequest,
    RunState,
    StrategyVersionResponse,
)
from redline.service.store import ServiceStore
from redline.service.transitions import ReleaseTransitionMissingEvidenceError, transition_release
from redline.io_safety import atomic_write_text
from redline.canonical import hash_file, hash_obj
from redline.merkle import merkle_root
from redline.models import ExecutionLedgerEntry, LedgerCheckpoint, Status
from redline.runner import run_redline
from redline.trust import generate_trust_keypair, make_trust_policy, sign_checkpoint
from redline.sponsor.bitget_execution import (
    BitgetOrderPlacement,
    default_execution_intent,
    load_exchange_preflight_evidence,
    load_execution_evidence,
    load_execution_ledger,
    load_order_status_evidence,
    make_client_oid,
    write_execution_evidence,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"


def _client(tmp_path: Path, *, max_upload_bytes: int = 50 * 1024 * 1024) -> TestClient:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", workers=2, max_upload_bytes=max_upload_bytes))
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"X-Redline-Token": "test-token"}


def _scoped_client(tmp_path: Path, tokens: list[dict]) -> TestClient:
    config = ServiceConfig(
        root=tmp_path / "service",
        token="unused-token",
        workers=1,
        service_tokens=parse_service_tokens(json.dumps(tokens), fallback_token="unused-token"),
    )
    return TestClient(create_app(config))


def _run_request() -> RunCreateRequest:
    return RunCreateRequest(package_path=str(PACKAGE), candidate="candidate_good", suite_path=str(SUITE), spec_path=str(SPEC))


def _wait_for_run(client: TestClient, run_id: str, *, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/v1/runs/{run_id}", headers=_headers())
        assert response.status_code == 200
        payload = response.json()
        if payload["state"] in {"pass", "fail", "amber", "error"}:
            return payload
        time.sleep(0.05)
    raise AssertionError(f"run did not finish: {run_id}")


def _wait_for_release_job(client: TestClient, release_id: str, job_id: str, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/v1/release-candidates/{release_id}/jobs/{job_id}", headers=_headers())
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"succeeded", "failed", "cancelled"}:
            return payload
        time.sleep(0.05)
    raise AssertionError(f"release job did not finish: {job_id}")


def _single_file_tar(member_name: str, data: bytes = b"x") -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as tar:
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return archive_bytes.getvalue()


def _special_member_tar(member: tarfile.TarInfo) -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as tar:
        tar.addfile(member)
    return archive_bytes.getvalue()


def _sign_run_checkpoint(run_dir: Path, private_key: str, *, policy_id: str = "test-policy", key_id: str = "test-key", issuer: str = "test-ci") -> None:
    checkpoint = LedgerCheckpoint.model_validate(json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8")))
    attestation = sign_checkpoint(
        checkpoint=checkpoint,
        private_key_text=private_key,
        signer=issuer,
        trust_policy_id=policy_id,
        key_id=key_id,
        issuer=issuer,
    )
    atomic_write_text(run_dir / "issuance-ledger.attestation.json", attestation.model_dump_json(indent=2) + "\n")


def _create_chained_service_run(client: TestClient, tmp_path: Path, *, candidate: str = "candidate_good") -> dict:
    package = tmp_path / f"package-{candidate}"
    shutil.copytree(PACKAGE, package)
    private_key, public_key = generate_trust_keypair()
    policy = make_trust_policy(policy_id="test-policy", key_id="test-key", public_key=public_key, issuer="test-ci")
    policy_path = tmp_path / f"trust-policy-{candidate}.json"
    atomic_write_text(policy_path, policy.model_dump_json(indent=2) + "\n")
    baseline = run_redline(package_dir=package, baseline="baseline", candidate="baseline", suite_path=SUITE, spec_path=SPEC, out_dir=tmp_path / f"baseline-{candidate}")
    assert baseline.receipt is not None
    _sign_run_checkpoint(tmp_path / f"baseline-{candidate}", private_key)

    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(package),
            "candidate": candidate,
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
            "baseline_receipt_path": str(tmp_path / f"baseline-{candidate}" / "receipt.json"),
            "baseline_trust_policy_path": str(policy_path),
        },
    )
    assert created.status_code == 202
    run = _wait_for_run(client, created.json()["run_id"])
    if (Path(run["out_dir"]) / "issuance-ledger.checkpoint.json").exists():
        _sign_run_checkpoint(Path(run["out_dir"]), private_key)
    return run


def _seed_service_run(client: TestClient, tmp_path: Path, *, run_id: str, state: RunState = RunState.PASS, reason_code: str = "PASS") -> dict:
    service = client.app.state.redline_service
    out_dir = tmp_path / run_id
    out_dir.mkdir(parents=True)
    receipt_path = out_dir / "receipt.json"
    report_path = out_dir / "report.json"
    receipt_hash = "sha256:" + hash_obj({"run_id": run_id, "kind": "receipt"}).removeprefix("sha256:")
    report_hash = "sha256:" + hash_obj({"run_id": run_id, "kind": "report"}).removeprefix("sha256:")
    atomic_write_text(receipt_path, json.dumps({"receipt_hash": receipt_hash, "run_id": run_id}, sort_keys=True) + "\n")
    atomic_write_text(report_path, json.dumps({"report_hash": report_hash, "run_id": run_id}, sort_keys=True) + "\n")
    request = RunCreateRequest(package_path=str(PACKAGE), candidate="candidate_good", suite_path=str(SUITE), spec_path=str(SPEC))
    service.store.create_run(run_id=run_id, request_id="req_seed", request=request, package_path=PACKAGE, out_dir=out_dir)
    manifest = ArtifactManifest(
        run_id=run_id,
        artifacts=[
            ArtifactInfo(
                artifact_id="receipt",
                kind="receipt",
                path="receipt.json",
                sha256=hash_file(receipt_path),
                bytes=receipt_path.stat().st_size,
                download_url=f"/v1/runs/{run_id}/artifacts/receipt",
            ),
            ArtifactInfo(
                artifact_id="report",
                kind="report",
                path="report.json",
                sha256=hash_file(report_path),
                bytes=report_path.stat().st_size,
                download_url=f"/v1/runs/{run_id}/artifacts/report",
            ),
        ],
    )
    service.store.mark_completed(
        run_id=run_id,
        state=state,
        reason_code=reason_code,
        envelope_status="pass" if state == RunState.PASS else "reject",
        package_hash=hash_obj({"package": str(PACKAGE)}),
        receipt_hash=receipt_hash if state == RunState.PASS else None,
        report_hash=report_hash,
        artifact_manifest=manifest,
    )
    run = service.store.get_run(run_id)
    assert run is not None
    return run.model_dump(mode="json")


def _create_release_for_run(client: TestClient, run: dict, *, release_id: str = "rel_test", version_id: str = "strategy-v1") -> dict:
    created_version = client.post(
        "/v1/strategy-versions",
        headers=_headers(),
        json={
            "version_id": version_id,
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": "strategy-author",
            "metadata": {"name": "Demo Strategy"},
        },
    )
    assert created_version.status_code == 201
    created_release = client.post(
        "/v1/release-candidates",
        headers=_headers(),
        json={
            "release_id": release_id,
            "version_id": version_id,
            "created_by": "strategy-author",
            "metadata": {"purpose": "pytest"},
        },
    )
    assert created_release.status_code == 201
    return created_release.json()


def _simulation_payload() -> dict:
    return {
        "source": "local_backtest",
        "period_start": "2026-06-01",
        "period_end": "2026-06-22",
        "market": "bitget-demo",
        "symbol": "BTCUSDT",
        "trade_count": 12,
        "pnl": "42.50",
        "max_drawdown": "3.20",
        "win_rate": "0.58",
        "source_file_hash": "sha256:" + "8" * 64,
    }


def _risk_policy_payload(**overrides) -> dict:
    payload = {
        "max_order_notional_usdt": "20",
        "allowed_product_types": ["USDT-FUTURES"],
        "allowed_symbols": ["BTCUSDT", "ETHUSDT", "SOLUSDT"],
        "require_simulation_evidence": True,
        "require_demo_execution": True,
        "require_human_approval": True,
        "mainnet_enabled": False,
        "expected_order_notional_usdt": "5",
    }
    payload.update(overrides)
    return payload


def _bitget_demo_transport(
    calls: list[dict[str, object]],
    *,
    order_id_prefix: str = "demo-order",
    order_id_factory=None,
    reject_place_from_call: int | None = None,
    reject_code: str = "40017",
    reject_message: str = "demo exchange rejected order",
    reject_http_status: int = 200,
    invalid_place_from_call: int | None = None,
    raise_place_from_call: int | None = None,
    recover_raised_order: bool = False,
    recover_rejected_order: bool = False,
    order_status: str = "live",
):
    orders_by_client_oid: dict[str, str] = {}

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        assert headers["paptrading"] == "1"
        parsed = urllib.parse.urlsplit(url)
        if method == "GET" and parsed.path.endswith("/api/v2/mix/market/contracts"):
            response = {
                "code": "00000",
                "msg": "success",
                "data": [
                    {
                        "symbol": symbol,
                        "symbolStatus": "normal",
                        "supportMarginCoins": ["USDT"],
                        "minTradeNum": "0.0001",
                        "minTradeUSDT": "0",
                        "pricePlace": "2",
                        "volumePlace": "4",
                    }
                    for symbol in ["BTCUSDT", "ETHUSDT", "SOLUSDT", "XRPUSDT"]
                ],
            }
            return 200, json.dumps(response).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/api/v2/mix/account/account"):
            response = {"code": "00000", "msg": "success", "data": {"marginCoin": "USDT", "available": "100"}}
            return 200, json.dumps(response).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/api/v2/mix/order/detail"):
            query = dict(urllib.parse.parse_qsl(parsed.query))
            client_oid = str(query.get("clientOid") or "")
            order_id = str(query.get("orderId") or orders_by_client_oid.get(client_oid) or "")
            response = {"code": "00000", "msg": "success", "data": {"orderId": order_id, "clientOid": client_oid, "state": order_status}}
            return 200, json.dumps(response).encode("utf-8")
        request = json.loads(body.decode("utf-8"))
        calls.append({"method": method, "url": url, "paptrading": headers["paptrading"], "body": request})
        if raise_place_from_call is not None and len(calls) == raise_place_from_call:
            if recover_raised_order:
                order_id = str(order_id_factory(len(calls))) if order_id_factory is not None else f"{order_id_prefix}-{len(calls)}"
                orders_by_client_oid[str(request["clientOid"])] = order_id
            raise TimeoutError("simulated timeout")
        if reject_place_from_call is not None and len(calls) >= reject_place_from_call:
            if recover_rejected_order:
                order_id = str(order_id_factory(len(calls))) if order_id_factory is not None else f"{order_id_prefix}-{len(calls)}"
                orders_by_client_oid[str(request["clientOid"])] = order_id
            response = {"code": reject_code, "msg": reject_message}
            return reject_http_status, json.dumps(response).encode("utf-8")
        if invalid_place_from_call is not None and len(calls) == invalid_place_from_call:
            response = {"code": "00000", "msg": "success", "data": {"clientOid": request["clientOid"]}}
            return 200, json.dumps(response).encode("utf-8")
        order_id = str(order_id_factory(len(calls))) if order_id_factory is not None else f"{order_id_prefix}-{len(calls)}"
        orders_by_client_oid[str(request["clientOid"])] = order_id
        response = {"code": "00000", "msg": "success", "data": {"orderId": order_id, "clientOid": request["clientOid"]}}
        return 200, json.dumps(response).encode("utf-8")

    return transport


def _create_release_ready_for_showcase_job(client: TestClient, tmp_path: Path, *, release_id: str, version_id: str) -> tuple[dict, dict]:
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id=release_id, version_id=version_id)
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase job approved"},
    ).status_code == 200
    executed = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase job approval after canonical execution"},
    ).status_code == 200
    return run, release


def test_service_requires_demo_token(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.get("/v1/runs")

    assert response.status_code == 401
    assert response.json()["schema_version"] == "redline.service.error.v1"
    assert response.json()["error_code"] == "401"


def test_service_rejects_wrong_demo_token(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.get("/v1/runs", headers={"X-Redline-Token": "wrong"})

    assert response.status_code == 401
    assert response.json()["ok"] is False
    assert response.headers["x-request-id"].startswith("req_")


def test_service_scoped_token_can_read_but_not_write(tmp_path: Path) -> None:
    client = _scoped_client(
        tmp_path,
        [
            {"token": "read-token", "principal_id": "auditor", "role": "reviewer", "scopes": ["read-only"]},
            {"token": "write-token", "principal_id": "release-manager", "role": "release_manager"},
        ],
    )

    read = client.get("/v1/release-safety", headers={"X-Redline-Token": "read-token"})
    blocked_write = client.post(
        "/v1/release-candidates",
        headers={"X-Redline-Token": "read-token"},
        json={"release_id": "rel_readonly", "version_id": "missing", "created_by": "author"},
    )

    assert read.status_code == 200
    assert blocked_write.status_code == 403
    assert blocked_write.json()["message"] == "Redline token lacks required scope: release-write"


def test_release_approval_binds_authenticated_principal(tmp_path: Path) -> None:
    client = _scoped_client(
        tmp_path,
        [
            {"token": "author-token", "principal_id": "actual-author", "role": "author"},
            {"token": "writer-token", "principal_id": "actual-reviewer", "role": "reviewer"},
        ],
    )
    author_headers = {"X-Redline-Token": "author-token"}
    reviewer_headers = {"X-Redline-Token": "writer-token"}
    run = _seed_service_run(client, tmp_path, run_id="run_auth_release")
    created_version = client.post(
        "/v1/strategy-versions",
        headers=author_headers,
        json={
            "version_id": "strategy-auth-v1",
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": "strategy-author",
            "metadata": {"name": "Demo Strategy"},
        },
    )
    created_release = client.post(
        "/v1/release-candidates",
        headers=author_headers,
        json={
            "release_id": "rel_auth",
            "version_id": "strategy-auth-v1",
            "created_by": "strategy-author",
        },
    )
    assert created_version.status_code == 201
    assert created_release.status_code == 201
    assert created_release.json()["created_by"] == "actual-author"
    assert client.post("/v1/release-candidates/rel_auth/redline-run", headers=author_headers, json={"run_id": run["run_id"]}).status_code == 200
    assert client.post("/v1/release-candidates/rel_auth/simulation-evidence", headers=author_headers, json=_simulation_payload()).status_code == 200
    assert client.post("/v1/release-candidates/rel_auth/risk-policy", headers=author_headers, json=_risk_policy_payload()).status_code == 200

    approval = client.post(
        "/v1/release-candidates/rel_auth/approve",
        headers=reviewer_headers,
        json={"reviewer_id": "spoofed-reviewer", "comment": "approved"},
    )
    ledger = client.get("/v1/release-candidates/rel_auth/audit-ledger", headers=reviewer_headers)

    assert approval.status_code == 200
    approval_payload = approval.json()["evidence"]["approval"]
    assert approval_payload["reviewer_id"] == "actual-reviewer"
    assert approval_payload["reviewer_role"] == "reviewer"
    assert approval_payload["auth_method"] == "service_token"
    assert approval_payload["claimed_reviewer_id"] == "spoofed-reviewer"
    assert ledger.status_code == 200
    audit_entries = [json.loads(line) for line in ledger.text.splitlines() if line.strip()]
    approval_entries = [entry for entry in audit_entries if entry["event_type"] == "approval_granted"]
    assert approval_entries[-1]["actor"] == "actual-reviewer"
    assert approval_entries[-1]["payload"]["actor_auth"]["auth_method"] == "service_token"


def _create_review_ready_release_with_headers(
    client: TestClient,
    tmp_path: Path,
    *,
    headers: dict[str, str],
    run_id: str,
    release_id: str,
    version_id: str,
    request_created_by: str = "spoofed-author",
) -> dict:
    run = _seed_service_run(client, tmp_path, run_id=run_id)
    created_version = client.post(
        "/v1/strategy-versions",
        headers=headers,
        json={
            "version_id": version_id,
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": request_created_by,
            "metadata": {"name": "Demo Strategy"},
        },
    )
    created_release = client.post(
        "/v1/release-candidates",
        headers=headers,
        json={"release_id": release_id, "version_id": version_id, "created_by": request_created_by},
    )
    assert created_version.status_code == 201
    assert created_release.status_code == 201
    assert client.post(f"/v1/release-candidates/{release_id}/redline-run", headers=headers, json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release_id}/simulation-evidence", headers=headers, json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release_id}/risk-policy", headers=headers, json=_risk_policy_payload()).status_code == 200
    return created_release.json()


def test_release_created_by_uses_authenticated_principal_snapshot_not_request_body(tmp_path: Path) -> None:
    client = _scoped_client(
        tmp_path,
        [
            {"token": "author-token", "principal_id": "actual-author", "role": "author"},
        ],
    )

    release = _create_review_ready_release_with_headers(
        client,
        tmp_path,
        headers={"X-Redline-Token": "author-token"},
        run_id="run_created_by_principal",
        release_id="rel_created_by_principal",
        version_id="strategy-created-by-principal",
        request_created_by="spoofed-author",
    )
    stored = client.get("/v1/release-candidates/rel_created_by_principal", headers={"X-Redline-Token": "author-token"})
    ledger = client.get("/v1/release-candidates/rel_created_by_principal/audit-ledger", headers={"X-Redline-Token": "author-token"})

    assert release["created_by"] == "actual-author"
    assert stored.status_code == 200
    assert stored.json()["created_by"] == "actual-author"
    audit_entries = [json.loads(line) for line in ledger.text.splitlines() if line.strip()]
    created_entries = [entry for entry in audit_entries if entry["event_type"] == "release_candidate_created"]
    assert created_entries[-1]["actor"] == "actual-author"
    assert created_entries[-1]["payload"]["actor_auth"]["principal_id"] == "actual-author"


def test_self_approval_forbidden_even_in_demo_mode(tmp_path: Path) -> None:
    client = _scoped_client(
        tmp_path,
        [
            {"token": "manager-token", "principal_id": "same-manager", "role": "release_manager"},
        ],
    )
    headers = {"X-Redline-Token": "manager-token"}
    release = _create_review_ready_release_with_headers(
        client,
        tmp_path,
        headers=headers,
        run_id="run_self_approval",
        release_id="rel_self_approval",
        version_id="strategy-self-approval",
    )

    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=headers,
        json={"reviewer_id": "same-manager", "comment": "self approval must fail", "demo_mode": True},
    )

    assert approval.status_code == 200
    assert approval.json()["ok"] is False
    assert approval.json()["state"] == ReleaseState.BLOCKED_APPROVAL
    assert approval.json()["reason_code"] == "SELF_APPROVAL_FORBIDDEN"


def test_non_reviewer_role_cannot_approve_release(tmp_path: Path) -> None:
    client = _scoped_client(
        tmp_path,
        [
            {"token": "manager-token", "principal_id": "release-manager", "role": "release_manager"},
            {"token": "author-token", "principal_id": "strategy-author", "role": "author", "scopes": ["read-only", "release-write"]},
        ],
    )
    release = _create_review_ready_release_with_headers(
        client,
        tmp_path,
        headers={"X-Redline-Token": "manager-token"},
        run_id="run_non_reviewer",
        release_id="rel_non_reviewer",
        version_id="strategy-non-reviewer",
    )

    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers={"X-Redline-Token": "author-token"},
        json={"reviewer_id": "strategy-author", "comment": "author cannot approve"},
    )

    assert approval.status_code == 200
    assert approval.json()["ok"] is False
    assert approval.json()["state"] == ReleaseState.BLOCKED_APPROVAL
    assert approval.json()["reason_code"] == "APPROVAL_ROLE_DENIED"


def test_approval_single_use_ttl_fields_are_persisted(tmp_path: Path) -> None:
    client = _client(tmp_path)
    service = client.app.state.redline_service
    run = _seed_service_run(client, tmp_path, run_id="run_approval_ttl")
    release = _create_release_for_run(client, run, release_id="rel_approval_ttl", version_id="strategy-approval-ttl")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200

    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "ttl approval"},
    )

    assert approval.status_code == 200
    approval_payload = approval.json()["evidence"]["approval"]
    assert approval_payload["nonce"].startswith("appr_")
    assert approval_payload["expires_at"] > approval_payload["approved_at"]
    assert approval_payload["consumed_at"] is None
    persisted = service.store.get_release_candidate(release["release_id"])
    assert persisted is not None
    assert persisted.approval["nonce"] == approval_payload["nonce"]
    assert persisted.approval["expires_at"] == approval_payload["expires_at"]
    assert persisted.approval["consumed_at"] is None
    with sqlite3.connect(service.store.db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(release_candidates)").fetchall()}
    assert {"approval_nonce", "approval_expires_at", "approval_consumed_at"} <= columns
    assert "20260624_0004_approval_lifecycle" in {item["version"] for item in service.store.list_schema_migrations()}


def test_approval_single_use_consumed_by_execute_and_showcase(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-single-use")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_approval_single_use", version_id="strategy-approval-single-use")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "canonical approval"},
    ).json()["ok"] is True

    canonical = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    stale_showcase = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "single-use-stale"},
        json={"size": "0.0001"},
    )
    reapproval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase approval"},
    )
    first_showcase = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "single-use-showcase-1"},
        json={"size": "0.0001"},
    )
    second_showcase = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "single-use-showcase-2"},
        json={"size": "0.0001"},
    )

    assert canonical.status_code == 200
    assert canonical.json()["ok"] is True
    consumed_after_canonical = client.app.state.redline_service.store.get_release_candidate(release["release_id"]).approval["consumed_at"]
    assert consumed_after_canonical is not None
    assert stale_showcase.json()["ok"] is False
    assert stale_showcase.json()["reason_code"] == "APPROVAL_CONSUMED"
    assert reapproval.status_code == 200
    assert reapproval.json()["ok"] is True
    assert reapproval.json()["state"] == ReleaseState.RELEASE_READY
    assert first_showcase.json()["ok"] is True
    assert second_showcase.json()["ok"] is False
    assert second_showcase.json()["reason_code"] == "APPROVAL_CONSUMED"
    assert len(calls) == 2


def test_dev_session_approval_binds_authenticated_principal_and_logout(tmp_path: Path) -> None:
    auth_users = json.dumps(
        [
            {
                "github_login": "bob",
                "principal_id": "github:bob",
                "role": "author",
                "scopes": ["read-only", "release-write"],
                "display_name": "Bob Author",
            },
            {
                "github_login": "alice",
                "principal_id": "github:alice",
                "role": "reviewer",
                "scopes": ["read-only", "release-write", "execute-demo"],
                "display_name": "Alice Reviewer",
                "email": "alice@example.test",
            }
        ]
    )
    config = ServiceConfig(
        root=tmp_path / "service",
        token="unused-token",
        workers=1,
        auth_session_secret="s" * 32,
        auth_users=auth_users,
        dev_auth_user="alice",
    )
    client = TestClient(create_app(config))

    author_login = client.post("/v1/auth/dev-login", json={"login": "bob"})
    run = _seed_service_run(client, tmp_path, run_id="run_dev_session")
    created_version = client.post(
        "/v1/strategy-versions",
        json={
            "version_id": "strategy-dev-session-v1",
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": "strategy-author",
        },
    )
    created_release = client.post(
        "/v1/release-candidates",
        json={"release_id": "rel_dev_session", "version_id": "strategy-dev-session-v1", "created_by": "strategy-author"},
    )
    assert author_login.status_code == 200
    assert author_login.json()["principal"]["principal_id"] == "github:bob"
    assert created_version.status_code == 201
    assert created_release.status_code == 201
    assert created_release.json()["created_by"] == "github:bob"
    assert client.post("/v1/release-candidates/rel_dev_session/redline-run", json={"run_id": run["run_id"]}).status_code == 200
    assert client.post("/v1/release-candidates/rel_dev_session/simulation-evidence", json=_simulation_payload()).status_code == 200
    assert client.post("/v1/release-candidates/rel_dev_session/risk-policy", json=_risk_policy_payload()).status_code == 200

    login = client.post("/v1/auth/dev-login", json={"login": "alice"})
    me = client.get("/v1/auth/me")
    assert login.status_code == 200
    assert login.json()["principal"]["principal_id"] == "github:alice"
    assert login.json()["principal"]["auth_method"] == "dev_session"
    assert "redline_session" in login.headers.get("set-cookie", "")
    assert me.status_code == 200
    assert me.json()["principal"]["display_name"] == "Alice Reviewer"

    approval = client.post(
        "/v1/release-candidates/rel_dev_session/approve",
        json={"reviewer_id": "spoofed-reviewer", "comment": "approved by dev session"},
    )
    ledger = client.get("/v1/release-candidates/rel_dev_session/audit-ledger")
    logout = client.post("/v1/auth/logout")
    after_logout = client.get("/v1/auth/me")

    assert approval.status_code == 200
    approval_payload = approval.json()["evidence"]["approval"]
    assert approval_payload["reviewer_id"] == "github:alice"
    assert approval_payload["reviewer_role"] == "reviewer"
    assert approval_payload["auth_method"] == "dev_session"
    assert approval_payload["auth_subject"] == "alice"
    assert approval_payload["reviewer_display_name"] == "Alice Reviewer"
    assert approval_payload["claimed_reviewer_id"] == "spoofed-reviewer"
    audit_entries = [json.loads(line) for line in ledger.text.splitlines() if line.strip()]
    approval_entries = [entry for entry in audit_entries if entry["event_type"] == "approval_granted"]
    assert approval_entries[-1]["payload"]["actor_auth"]["auth_method"] == "dev_session"
    assert approval_entries[-1]["payload"]["actor_auth"]["auth_subject"] == "alice"
    assert logout.status_code == 200
    assert after_logout.status_code == 401


def test_github_oauth_callback_binds_authenticated_principal_to_approval(tmp_path: Path, monkeypatch) -> None:
    auth_users = json.dumps(
        [
            {
                "github_login": "alice",
                "principal_id": "github:alice",
                "role": "reviewer",
                "scopes": ["read-only", "release-write", "execute-demo"],
                "display_name": "Alice OAuth",
                "email": "alice@example.test",
            }
        ]
    )
    config = ServiceConfig(
        root=tmp_path / "service",
        token="setup-token",
        workers=1,
        auth_session_secret="s" * 32,
        auth_users=auth_users,
        github_oauth_client_id="github-client",
        github_oauth_client_secret="github-secret-do-not-leak",
        github_oauth_redirect_uri="http://testserver/v1/auth/callback/github",
    )
    client = TestClient(create_app(config))
    monkeypatch.setattr(service_app, "_github_exchange_code", lambda _config, *, code: "oauth-token-do-not-leak")
    monkeypatch.setattr(
        service_app,
        "_github_fetch_user",
        lambda access_token: {"login": "alice", "name": "Alice OAuth", "email": "alice@example.test"},
    )

    login = client.get("/v1/auth/login/github", follow_redirects=False)

    assert login.status_code == 302
    assert "github.com/login/oauth/authorize" in login.headers["location"]
    assert "redline_github_oauth_state" in login.headers.get("set-cookie", "")
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(login.headers["location"]).query))
    assert query["client_id"] == "github-client"
    assert query["redirect_uri"] == "http://testserver/v1/auth/callback/github"
    assert query["state"]

    callback = client.get(f"/v1/auth/callback/github?code=oauth-code&state={query['state']}")
    me = client.get("/v1/auth/me")
    run = _seed_service_run(client, tmp_path, run_id="run_github_oauth")
    created_version = client.post(
        "/v1/strategy-versions",
        headers={"X-Redline-Token": "setup-token"},
        json={
            "version_id": "strategy-github-oauth-v1",
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": "strategy-author",
        },
    )
    created_release = client.post(
        "/v1/release-candidates",
        headers={"X-Redline-Token": "setup-token"},
        json={"release_id": "rel_github_oauth", "version_id": "strategy-github-oauth-v1", "created_by": "strategy-author"},
    )

    assert callback.status_code == 200
    assert callback.json()["principal"]["principal_id"] == "github:alice"
    assert callback.json()["principal"]["auth_method"] == "github_oauth"
    assert "redline_session" in callback.headers.get("set-cookie", "")
    assert "github-secret-do-not-leak" not in callback.text
    assert "oauth-token-do-not-leak" not in callback.text
    assert me.status_code == 200
    assert me.json()["principal"]["auth_method"] == "github_oauth"
    assert created_version.status_code == 201
    assert created_release.status_code == 201
    assert created_release.json()["created_by"] == "strategy-author"
    assert client.post("/v1/release-candidates/rel_github_oauth/redline-run", json={"run_id": run["run_id"]}).status_code == 200
    assert client.post("/v1/release-candidates/rel_github_oauth/simulation-evidence", json=_simulation_payload()).status_code == 200
    assert client.post("/v1/release-candidates/rel_github_oauth/risk-policy", json=_risk_policy_payload()).status_code == 200

    approval = client.post(
        "/v1/release-candidates/rel_github_oauth/approve",
        json={"reviewer_id": "spoofed-reviewer", "comment": "approved by github oauth"},
    )
    ledger = client.get("/v1/release-candidates/rel_github_oauth/audit-ledger")

    assert approval.status_code == 200
    approval_payload = approval.json()["evidence"]["approval"]
    assert approval_payload["reviewer_id"] == "github:alice"
    assert approval_payload["auth_method"] == "github_oauth"
    assert approval_payload["auth_subject"] == "alice"
    assert approval_payload["claimed_reviewer_id"] == "spoofed-reviewer"
    audit_entries = [json.loads(line) for line in ledger.text.splitlines() if line.strip()]
    approval_entries = [entry for entry in audit_entries if entry["event_type"] == "approval_granted"]
    assert approval_entries[-1]["payload"]["actor_auth"]["auth_method"] == "github_oauth"
    assert approval_entries[-1]["payload"]["actor_auth"]["auth_subject"] == "alice"


def test_github_oauth_rejects_state_mismatch_and_unknown_login(tmp_path: Path, monkeypatch) -> None:
    config = ServiceConfig(
        root=tmp_path / "service",
        token="unused-token",
        workers=1,
        auth_session_secret="s" * 32,
        github_oauth_client_id="github-client",
        github_oauth_client_secret="github-secret",
        github_oauth_redirect_uri="http://testserver/v1/auth/callback/github",
        github_oauth_allowed_logins=("alice",),
    )
    client = TestClient(create_app(config))
    monkeypatch.setattr(service_app, "_github_exchange_code", lambda _config, *, code: "oauth-token")
    monkeypatch.setattr(service_app, "_github_fetch_user", lambda access_token: {"login": "bob", "name": "Bob"})

    login = client.get("/v1/auth/login/github", follow_redirects=False)
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(login.headers["location"]).query))
    mismatch = client.get("/v1/auth/callback/github?code=oauth-code&state=wrong-state")
    rejected = client.get(f"/v1/auth/callback/github?code=oauth-code&state={query['state']}")

    assert login.status_code == 302
    assert mismatch.status_code == 400
    assert rejected.status_code == 403
    assert client.get("/v1/auth/me").status_code == 401


def test_release_simulation_evidence_file_upload_normalizes_csv(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run = _seed_service_run(client, tmp_path, run_id="run_file_sim")
    release = _create_release_for_run(client, run, release_id="rel_file_sim", version_id="strategy-file-sim")
    csv_bytes = b"timestamp,symbol,pnl,drawdown\n2026-06-01T00:00:00Z,BTCUSDT,5,-1\n2026-06-02T00:00:00Z,BTCUSDT,-1.5,-2\n"

    uploaded = client.post(
        f"/v1/release-candidates/{release['release_id']}/simulation-evidence-file",
        headers=_headers(),
        data={"source": "getagent_studio", "market": "bitget-demo", "symbol": "BTCUSDT"},
        files={"file": ("getagent-export.csv", csv_bytes, "text/csv")},
    )
    evidence = client.get(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers())
    audit = client.get(f"/v1/release-candidates/{release['release_id']}/audit-ledger", headers=_headers())
    source_path = tmp_path / "service" / "releases" / release["release_id"] / "release-simulation-source.csv"

    assert uploaded.status_code == 200
    assert uploaded.json()["ok"] is True
    payload = evidence.json()
    assert payload["source"] == "getagent_studio"
    assert payload["trade_count"] == 2
    assert payload["pnl"] == "3.5"
    assert payload["max_drawdown"] == "2"
    assert payload["win_rate"] == "0.5"
    assert payload["source_file_hash"] == hash_file(source_path)
    assert json.loads(audit.text.splitlines()[-1])["event_type"] == "simulation_evidence_file_imported"


def test_release_create_idempotency_key_replays_or_conflicts(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run = _seed_service_run(client, tmp_path, run_id="run_idempotency")
    created_version = client.post(
        "/v1/strategy-versions",
        headers=_headers(),
        json={
            "version_id": "strategy-idem-v1",
            "strategy_id": "demo-strategy",
            "package_path": run["package_path"],
            "source_kind": "fixture",
            "created_by": "strategy-author",
            "metadata": {"name": "Demo Strategy"},
        },
    )
    assert created_version.status_code == 201
    headers = {**_headers(), "Idempotency-Key": "idem-release-1"}
    body = {"version_id": "strategy-idem-v1", "created_by": "strategy-author", "metadata": {"purpose": "idempotency"}}

    first = client.post("/v1/release-candidates", headers=headers, json=body)
    replay = client.post("/v1/release-candidates", headers=headers, json=body)
    conflict = client.post(
        "/v1/release-candidates",
        headers=headers,
        json={**body, "metadata": {"purpose": "different"}},
    )

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["release_id"] == first.json()["release_id"]
    assert conflict.status_code == 409
    assert "Idempotency-Key" in conflict.json()["message"]


def test_service_config_rejects_production_default_token(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.delenv("REDLINE_SERVICE_TOKEN", raising=False)

    with pytest.raises(ValueError, match="production service requires"):
        ServiceConfig.from_env()


def test_service_config_rejects_production_dev_auth(monkeypatch) -> None:
    # a production deploy must fail closed if dev-auth knobs are set: /v1/auth/dev-login would
    # otherwise mint a privileged session for unauthenticated callers (privilege-escalation footgun).
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.setenv("REDLINE_SERVICE_TOKEN", "p" * 40)
    monkeypatch.setenv("REDLINE_AUTH_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("REDLINE_SERVICE_CORS_ORIGINS", "https://example.com")
    monkeypatch.setenv("REDLINE_DEV_AUTH_ENABLED", "true")
    with pytest.raises(ValueError, match="must not enable dev auth"):
        ServiceConfig.from_env()
    monkeypatch.delenv("REDLINE_DEV_AUTH_ENABLED", raising=False)
    monkeypatch.setenv("REDLINE_DEV_AUTH_USER", "release-manager")
    with pytest.raises(ValueError, match="must not enable dev auth"):
        ServiceConfig.from_env()


def test_service_records_schema_migration_status(tmp_path: Path) -> None:
    client = _client(tmp_path)

    applied = client.app.state.redline_service.store.list_schema_migrations()
    cli = CliRunner().invoke(cli_app, ["service-migrations", "--root", str(tmp_path / "cli-service"), "--json"])

    assert applied[-1]["version"] == CURRENT_SCHEMA_VERSION
    assert cli.exit_code == 0
    payload = json.loads(cli.stdout)
    assert payload["expected_versions"] == expected_migration_versions()
    assert payload["pending_versions"] == []


def test_service_config_rejects_wildcard_production_cors(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.setenv("REDLINE_SERVICE_TOKEN", "x" * 32)
    monkeypatch.setenv("REDLINE_SERVICE_CORS_ORIGINS", "*")

    with pytest.raises(ValueError, match="CORS origins"):
        ServiceConfig.from_env()


def test_service_config_rejects_missing_production_session_secret(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.setenv("REDLINE_SERVICE_TOKEN", "x" * 32)
    monkeypatch.delenv("REDLINE_SERVICE_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("REDLINE_AUTH_SESSION_SECRET", raising=False)

    with pytest.raises(ValueError, match="REDLINE_AUTH_SESSION_SECRET"):
        ServiceConfig.from_env()


def test_service_config_rejects_invalid_log_level(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_LOG_LEVEL", "verbose")

    with pytest.raises(ValueError, match="LOG_LEVEL"):
        ServiceConfig.from_env()


def test_service_config_accepts_postgres_metadata_store(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_METADATA_STORE", "postgres")
    monkeypatch.setenv("REDLINE_DATABASE_URL", "postgresql://redline:redline@localhost:5432/redline")

    config = ServiceConfig.from_env()

    assert config.metadata_store == "postgres"
    assert config.database_url == "postgresql://redline:redline@localhost:5432/redline"


def test_service_config_rejects_postgres_without_database_url(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_METADATA_STORE", "postgres")
    monkeypatch.delenv("REDLINE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match="REDLINE_DATABASE_URL"):
        ServiceConfig.from_env()


def test_service_cors_origin_is_configurable(tmp_path: Path) -> None:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", cors_origins=("http://localhost:3000",)))
    client = TestClient(app)

    response = client.options(
        "/v1/runs",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-redline-token",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_service_uses_swappable_storage_adapters(tmp_path: Path) -> None:
    config = ServiceConfig(root=tmp_path / "service", token="test-token")

    metadata_store = create_metadata_store(config)
    artifact_store = create_artifact_store(config)

    assert isinstance(metadata_store, ServiceStore)
    assert isinstance(artifact_store, LocalArtifactStore)
    assert artifact_store.run_dir("run_abc") == config.runs_dir / "run_abc"


def test_sqlite_store_claims_and_requeues_runs(tmp_path: Path) -> None:
    store = ServiceStore(tmp_path / "service.sqlite3")
    request = _run_request()
    store.create_run(run_id="run_queue_test", request_id="req_1", request=request, package_path=PACKAGE, out_dir=tmp_path / "run")

    work = store.claim_next_run(worker_id="worker_1")

    assert work is not None
    assert work.run_id == "run_queue_test"
    assert work.request.candidate == "candidate_good"
    assert store.get_run("run_queue_test").state == RunState.RUNNING
    assert store.claim_next_run(worker_id="worker_2") is None
    assert store.requeue_interrupted_runs() == 1
    assert store.get_run("run_queue_test").state == RunState.QUEUED


def test_service_rate_limit_fails_closed(tmp_path: Path) -> None:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", request_rate_limit_per_minute=2))
    client = TestClient(app)

    assert client.get("/v1/runs", headers=_headers()).status_code == 200
    assert client.get("/v1/runs", headers=_headers()).status_code == 200
    response = client.get("/v1/runs", headers=_headers())

    assert response.status_code == 429
    assert response.json()["ok"] is False


def test_service_run_quota_fails_closed(tmp_path: Path) -> None:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", max_runs_total=1))
    client = TestClient(app)

    first = client.post(
        "/v1/runs",
        headers=_headers(),
        json={"package_path": str(PACKAGE), "candidate": "candidate_good", "suite_path": str(SUITE), "spec_path": str(SPEC)},
    )
    assert first.status_code == 202
    second = client.post(
        "/v1/runs",
        headers=_headers(),
        json={"package_path": str(PACKAGE), "candidate": "candidate_good", "suite_path": str(SUITE), "spec_path": str(SPEC)},
    )

    assert second.status_code == 429
    assert second.json()["ok"] is False


def test_service_package_quota_fails_closed(tmp_path: Path) -> None:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", max_packages=1))
    client = TestClient(app)

    assert client.post("/v1/packages/import", headers=_headers(), json={"package_path": str(PACKAGE)}).status_code == 201
    response = client.post("/v1/packages/import", headers=_headers(), json={"package_path": str(PACKAGE)})

    assert response.status_code == 429
    assert response.json()["ok"] is False


def test_service_cleanup_prunes_terminal_runs_and_artifacts(tmp_path: Path) -> None:
    config = ServiceConfig(root=tmp_path / "service", token="test-token", run_retention_seconds=0)
    store = ServiceStore(config.db_path)
    out_dir = config.runs_dir / "run_cleanup"
    out_dir.mkdir(parents=True)
    store.create_run(run_id="run_cleanup", request_id="req_1", request=_run_request(), package_path=PACKAGE, out_dir=out_dir)
    store.mark_error(run_id="run_cleanup", error_code="DATA_MISSING", message="done")
    with sqlite3.connect(config.db_path) as conn:
        conn.execute("UPDATE runs SET updated_at = ? WHERE run_id = ?", ("2020-01-01T00:00:00Z", "run_cleanup"))

    result = cleanup_expired_runs(config=config, older_than_seconds=0)

    assert result.deleted_runs == 1
    assert result.deleted_artifact_dirs == 1
    assert store.get_run("run_cleanup") is None
    assert not out_dir.exists()


def test_service_import_run_and_download_artifacts(tmp_path: Path) -> None:
    client = _client(tmp_path)
    imported = client.post(
        "/v1/packages/import",
        headers=_headers(),
        json={"package_path": str(PACKAGE)},
    )
    assert imported.status_code == 201
    package_id = imported.json()["package_id"]

    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_id": package_id,
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    assert created.status_code == 202
    run_id = created.json()["run_id"]
    run = _wait_for_run(client, run_id)

    assert run["state"] == "amber"
    assert run["reason_code"] == "BASELINE_GENESIS"
    assert run["receipt_hash"].startswith("sha256:")
    assert run["artifact_manifest"]["artifacts"]

    manifest = client.get(f"/v1/runs/{run_id}/artifacts", headers=_headers())
    assert manifest.status_code == 200
    artifact_ids = {item["artifact_id"] for item in manifest.json()["artifacts"]}
    assert {"envelope", "report", "receipt", "issuance-ledger-checkpoint"}.issubset(artifact_ids)

    receipt = client.get(f"/v1/runs/{run_id}/artifacts/receipt", headers=_headers())
    assert receipt.status_code == 200
    assert receipt.json()["receipt_hash"] == run["receipt_hash"]


def test_service_missing_candidate_fails_closed_as_error(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "does_not_exist",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    assert created.status_code == 202

    run = _wait_for_run(client, created.json()["run_id"])

    assert run["state"] == "error"
    assert run["error_code"] == "DATA_MISSING"
    assert "does_not_exist" in run["error_message"]


def test_service_artifact_download_rejects_path_traversal(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])

    response = client.get(f"/v1/runs/{run['run_id']}/artifacts/../receipt.json", headers=_headers())

    assert response.status_code in {400, 404}
    assert response.json()["ok"] is False


def test_service_artifact_download_rejects_tampered_file(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])
    receipt_path = Path(run["out_dir"]) / "receipt.json"
    receipt_text = receipt_path.read_text(encoding="utf-8")
    receipt_text = receipt_text.replace("redline.receipt.v3.3", "redline.receipt.v3.x").replace("redline.receipt.v3.2", "redline.receipt.v3.x")
    receipt_path.write_text(receipt_text, encoding="utf-8")

    response = client.get(f"/v1/runs/{run['run_id']}/artifacts/receipt", headers=_headers())

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_MISMATCH"


def test_service_artifact_download_rejects_symlink_file(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])
    report_path = Path(run["out_dir"]) / "report.json"
    report_path.unlink()
    os.symlink(Path(run["out_dir"]) / "envelope.json", report_path)

    response = client.get(f"/v1/runs/{run['run_id']}/artifacts/report", headers=_headers())

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_BINDING_FAILED"


def test_service_artifact_download_rejects_hardlink_file(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])
    report_path = Path(run["out_dir"]) / "report.json"
    report_path.unlink()
    os.link(Path(run["out_dir"]) / "envelope.json", report_path)

    response = client.get(f"/v1/runs/{run['run_id']}/artifacts/report", headers=_headers())

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_BINDING_FAILED"


def test_service_concurrent_runs_and_replay_determinism(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run_ids = []
    for _ in range(3):
        created = client.post(
            "/v1/runs",
            headers=_headers(),
            json={
                "package_path": str(PACKAGE),
                "candidate": "candidate_good",
                "suite_path": str(SUITE),
                "spec_path": str(SPEC),
            },
        )
        assert created.status_code == 202
        run_ids.append(created.json()["run_id"])

    runs = [_wait_for_run(client, run_id) for run_id in run_ids]

    assert len(set(run_ids)) == 3
    assert {run["state"] for run in runs} == {"amber"}
    assert len({run["receipt_hash"] for run in runs}) == 1
    assert len({run["report_hash"] for run in runs}) == 1


def test_service_upload_package_archive_and_run(tmp_path: Path) -> None:
    client = _client(tmp_path)
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as tar:
        for path in sorted(PACKAGE.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=Path("demo_pack") / path.relative_to(PACKAGE))
    archive_bytes.seek(0)

    uploaded = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", archive_bytes.getvalue(), "application/gzip")},
    )
    assert uploaded.status_code == 201

    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_id": uploaded.json()["package_id"],
            "candidate": "candidate_bad",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])

    assert run["state"] == "fail"
    assert run["reason_code"] == "NEW_BLOCK_BREACH"


def test_service_upload_rejects_wrong_content_type(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.txt", b"not a tarball", "text/plain")},
    )

    assert response.status_code == 415
    assert response.json()["ok"] is False


def test_service_upload_rejects_archive_path_escape(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", _single_file_tar("../evil.txt"), "application/gzip")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_BINDING_FAILED"


def test_service_upload_rejects_archive_symlink_member(tmp_path: Path) -> None:
    client = _client(tmp_path)
    member = tarfile.TarInfo("demo_pack/baseline/strategy.py")
    member.type = tarfile.SYMTYPE
    member.linkname = "candidate_good/strategy.py"

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", _special_member_tar(member), "application/gzip")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_BINDING_FAILED"


def test_service_upload_rejects_archive_hardlink_member(tmp_path: Path) -> None:
    client = _client(tmp_path)
    member = tarfile.TarInfo("demo_pack/baseline/strategy.py")
    member.type = tarfile.LNKTYPE
    member.linkname = "demo_pack/candidate_good/strategy.py"

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", _special_member_tar(member), "application/gzip")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "RECEIPT_BINDING_FAILED"


def test_service_upload_rejects_bad_tarball(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", b"not a tarball", "application/gzip")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSE_ERROR"


def test_service_upload_rejects_empty_package(tmp_path: Path) -> None:
    client = _client(tmp_path)
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz"):
        pass

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", archive_bytes.getvalue(), "application/gzip")},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_service_upload_rejects_oversized_archive(tmp_path: Path) -> None:
    client = _client(tmp_path, max_upload_bytes=8)

    response = client.post(
        "/v1/packages/upload",
        headers=_headers(),
        files={"archive": ("package.tar.gz", b"x" * 9, "application/gzip")},
    )

    assert response.status_code == 413
    assert response.json()["ok"] is False


def test_service_sponsor_preflight_rejects_tampered_receipt(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])
    receipt_path = Path(run["out_dir"]) / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["receipt_hash"] = "sha256:" + "0" * 64
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    response = client.post(
        f"/v1/runs/{run['run_id']}/sponsor-readback",
        headers=_headers(),
        json={"mode": "preflight", "allow_demo_baseline_genesis": True},
    )

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "RECEIPT_MISMATCH"


def test_service_sponsor_live_requires_credentials_without_pseudo_success(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REDLINE_BITGET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("BITGET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("REDLINE_BITGET_SECRET_KEY", raising=False)
    monkeypatch.delenv("BITGET_SECRET_KEY", raising=False)
    monkeypatch.delenv("REDLINE_BITGET_PASSPHRASE", raising=False)
    monkeypatch.delenv("BITGET_PASSPHRASE", raising=False)
    client = _client(tmp_path)
    created = client.post(
        "/v1/runs",
        headers=_headers(),
        json={
            "package_path": str(PACKAGE),
            "candidate": "candidate_good",
            "suite_path": str(SUITE),
            "spec_path": str(SPEC),
        },
    )
    run = _wait_for_run(client, created.json()["run_id"])

    response = client.post(
        f"/v1/runs/{run['run_id']}/sponsor-readback",
        headers=_headers(),
        json={"mode": "live", "allow_demo_baseline_genesis": True},
    )

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["state"] in {"BITGET_CREDENTIALS_REQUIRED", "LOCAL_PASS_REQUIRED", "CHAINED_PASS_REQUIRED"}


def test_service_execute_places_demo_order_once_and_writes_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    base_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-123")

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        if method == "GET":
            return base_transport(method, url, headers, body)
        request = json.loads(body.decode("utf-8"))
        assert headers["paptrading"] == "1"
        calls.append({"method": method, "url": url, "paptrading": headers["paptrading"], "body": request})
        assert request["symbol"] == "BTCUSDT"
        assert request["productType"] == "USDT-FUTURES"
        assert request["marginCoin"] == "USDT"
        assert request["clientOid"].startswith("rl-")
        if len(calls) == 1:
            return 500, json.dumps({"code": "50000", "msg": "retry"}).encode("utf-8")
        response = {"code": "00000", "msg": "success", "data": {"orderId": "demo-order-123", "clientOid": request["clientOid"]}}
        return 200, json.dumps(response).encode("utf-8")

    client.app.state.redline_service.execution_transport = transport
    run = _create_chained_service_run(client, tmp_path)

    first = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    second = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert first.status_code == 200
    assert first.json()["ok"] is True
    assert first.json()["state"] == "placed"
    assert first.json()["evidence"]["bitget_order_id"] == "demo-order-123"
    assert second.status_code == 200
    assert second.json()["ok"] is True
    assert second.json()["state"] == "already_placed"
    assert second.json()["evidence"]["client_oid"] == first.json()["evidence"]["client_oid"]
    assert len(calls) == 2

    manifest = client.get(f"/v1/runs/{run['run_id']}/artifacts", headers=_headers())
    assert manifest.status_code == 200
    artifact_ids = {item["artifact_id"] for item in manifest.json()["artifacts"]}
    assert {"execution-evidence", "execution-ledger"}.issubset(artifact_ids)
    evidence_download = client.get(f"/v1/runs/{run['run_id']}/artifacts/execution-evidence", headers=_headers())
    assert evidence_download.status_code == 200
    assert evidence_download.json()["artifact_hash"] == first.json()["evidence"]["artifact_hash"]
    combined_output = json.dumps(first.json()) + (Path(run["out_dir"]) / "execution-evidence.json").read_text(encoding="utf-8")
    combined_output += (Path(run["out_dir"]) / "execution-ledger.jsonl").read_text(encoding="utf-8")
    assert "demo-secret-do-not-leak" not in combined_output
    assert "demo-passphrase" not in combined_output


def test_service_execute_writes_preflight_and_order_status_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-sidecars")
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    manifest = client.get(f"/v1/runs/{run['run_id']}/artifacts", headers=_headers())
    out_dir = Path(run["out_dir"])
    preflight = load_exchange_preflight_evidence(out_dir / "exchange-preflight-evidence.json")
    order_status = load_order_status_evidence(out_dir / "order-status-evidence.json")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["evidence"]["preflight_hash"] == preflight.preflight_hash
    assert response.json()["evidence"]["order_status_hash"] == order_status.evidence_hash
    assert response.json()["evidence"]["order_status"] == "placed"
    assert preflight.ok is True
    assert order_status.bitget_order_id == "demo-order-sidecars"
    artifact_ids = {item["artifact_id"] for item in manifest.json()["artifacts"]}
    assert {"exchange-preflight-evidence", "order-status-evidence"}.issubset(artifact_ids)
    assert len(calls) == 1


def test_service_execute_preflight_failure_blocks_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls)
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={"symbol": "DOGEUSDT"})
    out_dir = Path(run["out_dir"])
    preflight = load_exchange_preflight_evidence(out_dir / "exchange-preflight-evidence.json")

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "EXCHANGE_PREFLIGHT_FAILED"
    assert preflight.ok is False
    assert len(calls) == 0
    assert not (out_dir / "execution-evidence.json").exists()


def test_service_execute_timeout_recovers_order_by_client_oid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(
        calls,
        order_id_factory=lambda _count: "demo-order-timeout-recovered",
        raise_place_from_call=1,
        recover_raised_order=True,
    )
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    evidence = load_execution_evidence(Path(run["out_dir"]) / "execution-evidence.json")
    order_status = load_order_status_evidence(Path(run["out_dir"]) / "order-status-evidence.json")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert evidence.bitget_order_id == "demo-order-timeout-recovered"
    assert order_status.bitget_order_id == "demo-order-timeout-recovered"
    assert len(calls) == 1


def test_service_execute_duplicate_client_oid_recovers_order_by_client_oid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(
        calls,
        order_id_factory=lambda _count: "demo-order-duplicate-recovered",
        reject_place_from_call=1,
        reject_code="40786",
        reject_message="Duplicate clientOid",
        reject_http_status=400,
        recover_rejected_order=True,
    )
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    evidence = load_execution_evidence(Path(run["out_dir"]) / "execution-evidence.json")
    order_status = load_order_status_evidence(Path(run["out_dir"]) / "order-status-evidence.json")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert evidence.bitget_order_id == "demo-order-duplicate-recovered"
    assert order_status.bitget_order_id == "demo-order-duplicate-recovered"
    assert order_status.status == "placed"
    assert len(calls) == 1


def test_execution_evidence_links_issuance_checkpoint_and_approval(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-links")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_execution_links", version_id="strategy-execution-links")

    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "execution links approved"},
    )
    approval_hash = hash_obj(approval.json()["evidence"]["approval"])

    execute = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})

    run_dir = Path(run["out_dir"])
    evidence = load_execution_evidence(run_dir / "execution-evidence.json")
    execution_entry = load_execution_ledger(run_dir / "execution-ledger.jsonl")[-1]
    issuance_entries = [json.loads(line) for line in (run_dir / "issuance-ledger.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    issuance_entry = next(entry for entry in issuance_entries if entry["receipt_hash"] == evidence.receipt_hash)
    checkpoint = json.loads((run_dir / "issuance-ledger.checkpoint.json").read_text(encoding="utf-8"))

    assert execute.status_code == 200
    assert execute.json()["ok"] is True
    assert evidence.issuance_ledger_entry_hash == issuance_entry["entry_hash"]
    assert evidence.issuance_checkpoint_hash == checkpoint["checkpoint_hash"]
    assert evidence.approval_hash == approval_hash
    assert execution_entry.issuance_ledger_entry_hash == evidence.issuance_ledger_entry_hash
    assert execution_entry.issuance_checkpoint_hash == evidence.issuance_checkpoint_hash
    assert execution_entry.approval_hash == evidence.approval_hash
    assert execute.json()["evidence"]["issuance_ledger_entry_hash"] == evidence.issuance_ledger_entry_hash
    assert execute.json()["evidence"]["approval_hash"] == approval_hash


def test_execution_evidence_links_legacy_artifacts_default_to_unapproved(tmp_path: Path) -> None:
    evidence_payload = {
        "version": "redline.execution.evidence.v1",
        "run_id": "run_legacy_execution_links",
        "receipt_hash": "sha256:" + "1" * 64,
        "verdict": "pass",
        "client_oid": "rl-legacy",
        "bitget_order_id": "demo-order-legacy",
        "response_hash": "sha256:" + "2" * 64,
        "placed_at": "2026-06-24T00:00:00Z",
        "symbol": "BTCUSDT",
        "product_type": "USDT-FUTURES",
        "order_mode": "demo",
        "paptrading": "1",
        "execution_ledger_entry_hash": "sha256:" + "3" * 64,
        "artifact_hash": "",
    }
    evidence_payload["artifact_hash"] = hash_obj({key: value for key, value in evidence_payload.items() if key != "artifact_hash"})
    evidence_path = tmp_path / "execution-evidence.json"
    atomic_write_text(evidence_path, json.dumps(evidence_payload, sort_keys=True) + "\n")

    ledger_payload = {
        "version": "redline.execution.ledger_entry.v1",
        "run_id": "run_legacy_execution_links",
        "receipt_hash": "sha256:" + "1" * 64,
        "verdict": "pass",
        "client_oid": "rl-legacy",
        "bitget_order_id": "demo-order-legacy",
        "response_hash": "sha256:" + "2" * 64,
        "placed_at": "2026-06-24T00:00:00Z",
        "previous_entry_hash": "sha256:genesis",
        "entry_hash": "",
    }
    ledger_payload["entry_hash"] = hash_obj({key: value for key, value in ledger_payload.items() if key != "entry_hash"})
    ledger_path = tmp_path / "execution-ledger.jsonl"
    atomic_write_text(ledger_path, json.dumps(ledger_payload, sort_keys=True) + "\n")

    evidence = load_execution_evidence(evidence_path)
    ledger_entry = load_execution_ledger(ledger_path)[0]

    assert evidence.issuance_ledger_entry_hash == "sha256:genesis"
    assert evidence.issuance_checkpoint_hash == "sha256:genesis"
    assert evidence.approval_hash == "sha256:unapproved"
    assert "approval_hash" not in evidence.model_fields_set
    assert ledger_entry.issuance_ledger_entry_hash == "sha256:genesis"
    assert ledger_entry.issuance_checkpoint_hash == "sha256:genesis"
    assert ledger_entry.approval_hash == "sha256:unapproved"
    assert "approval_hash" not in ledger_entry.model_fields_set


def test_execution_evidence_links_release_rejects_unapproved_existing_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-unapproved")
    run = _create_chained_service_run(client, tmp_path)
    direct = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    direct_evidence = load_execution_evidence(Path(run["out_dir"]) / "execution-evidence.json")
    release = _create_release_for_run(client, run, release_id="rel_unapproved_existing", version_id="strategy-unapproved-existing")

    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "must not reuse unapproved evidence"},
    )
    execute = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})

    assert direct.status_code == 200
    assert direct.json()["ok"] is True
    assert direct_evidence.approval_hash == "sha256:unapproved"
    assert approval.status_code == 200
    assert execute.status_code == 200
    assert execute.json()["ok"] is False
    assert execute.json()["reason_code"] == "EXECUTION_EVIDENCE_MISMATCH"
    assert "current approval" in execute.json()["evidence"]["detail"]
    assert len(calls) == 1


def test_service_execute_blocks_withheld_without_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path, candidate="candidate_bad")

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["state"] == "blocked"
    assert response.json()["reason_code"] == "NEW_BLOCK_BREACH"
    assert not (Path(run["out_dir"]) / "execution-evidence.json").exists()


def test_service_execute_blocks_tampered_receipt_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)
    receipt_path = Path(run["out_dir"]) / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["receipt_hash"] = "sha256:" + "0" * 64
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "RECEIPT_MISMATCH"


def test_service_execute_rejects_mainnet_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    monkeypatch.setenv("REDLINE_BITGET_PAPTRADING", "0")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={"symbol": "NOTADEMOUSDT"})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "BITGET_MAINNET_DISABLED"


def test_service_execute_rejects_invalid_paptrading_value_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    monkeypatch.setenv("REDLINE_BITGET_PAPTRADING", "true")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "BITGET_PAPTRADING_INVALID"


def test_service_execute_rejects_non_demo_symbol_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={"symbol": "NOTADEMOUSDT"})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "BITGET_DEMO_SYMBOL_REQUIRED"


def test_service_execute_rejects_invalid_order_fields_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={"size": "not-a-decimal"})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "SCHEMA_INVALID"


def test_service_execute_rejects_bad_bitget_response_without_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, invalid_place_from_call=1)
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "BITGET_RESPONSE_INVALID"
    assert not (Path(run["out_dir"]) / "execution-evidence.json").exists()


def test_service_execute_includes_safe_bitget_error_detail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(
        calls,
        reject_place_from_call=1,
        reject_code="40099",
        reject_message="exchange environment is incorrect",
        reject_http_status=400,
    )
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert payload["reason_code"] == "BITGET_ORDER_REJECTED"
    assert payload["evidence"]["detail"] == "Bitget order request failed with HTTP 400 code 40099: exchange environment is incorrect"
    assert "demo-secret-do-not-leak" not in json.dumps(payload)


def test_service_execute_does_not_reorder_when_ledger_exists_without_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)
    client_oid = make_client_oid(receipt_hash=run["receipt_hash"], intent=default_execution_intent())
    entry = ExecutionLedgerEntry(
        run_id=run["run_id"],
        receipt_hash=run["receipt_hash"],
        verdict=Status.PASS,
        client_oid=client_oid,
        bitget_order_id="demo-order-recovered",
        response_hash="sha256:" + "1" * 64,
        placed_at="2026-06-23T00:00:00Z",
        previous_entry_hash="sha256:genesis",
        entry_hash="sha256:" + "0" * 64,
    )
    entry = entry.model_copy(update={"entry_hash": hash_obj(entry.model_dump(mode="json", exclude={"entry_hash"}))})
    atomic_write_text(Path(run["out_dir"]) / "execution-ledger.jsonl", json.dumps(entry.model_dump(mode="json"), sort_keys=True) + "\n")

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "EXECUTION_EVIDENCE_MISSING"


def test_service_execute_requires_nonempty_demo_credentials(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "")
    client = _client(tmp_path)
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))
    run = _create_chained_service_run(client, tmp_path)

    response = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "BITGET_DEMO_CREDENTIALS_REQUIRED"


def test_release_candidate_happy_path_generates_bundle_and_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict] = []

    def fake_execute(*, service, run, payload, approval_hash="sha256:unapproved"):
        _ = service, payload
        calls.append({"run_id": run.run_id})
        order = BitgetOrderPlacement(
            client_oid="rl-release-client-oid",
            bitget_order_id="demo-order-release-123",
            response_hash="sha256:" + "3" * 64,
            placed_at="2026-06-24T00:00:00Z",
            status_code=200,
        )
        evidence = write_execution_evidence(
            run_id=run.run_id,
            out_dir=Path(run.out_dir),
            receipt_hash=run.receipt_hash or "sha256:" + "0" * 64,
            verdict=Status.PASS,
            intent=default_execution_intent(),
            order=order,
            issuance_ledger_entry_hash="sha256:genesis",
            issuance_checkpoint_hash="sha256:genesis",
            approval_hash=approval_hash,
        )
        return ExecutionResponse(
            run_id=run.run_id,
            ok=True,
            state="placed",
            evidence=evidence.model_dump(mode="json"),
        )

    monkeypatch.setattr(service_app, "_execute_bitget_demo_order", fake_execute)
    run = _seed_service_run(client, tmp_path, run_id="run_release_good")
    release = _create_release_for_run(client, run)

    bound = client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]})
    simulation = client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload())
    risk = client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload())
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "demo release approved"},
    )
    first_execute = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    second_execute = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    evidence = client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers())
    audit = client.get(f"/v1/release-candidates/{release['release_id']}/audit-ledger", headers=_headers())

    assert bound.status_code == 200
    assert bound.json()["ok"] is True
    assert bound.json()["state"] == "redline_passed"
    assert simulation.status_code == 200
    assert risk.status_code == 200
    assert risk.json()["ok"] is True
    assert approval.status_code == 200
    assert approval.json()["ok"] is True
    assert first_execute.status_code == 200
    assert first_execute.json()["ok"] is True
    assert first_execute.json()["state"] == "release_ready"
    assert second_execute.status_code == 200
    assert second_execute.json()["ok"] is True
    assert second_execute.json()["evidence"]["client_oid"] == first_execute.json()["evidence"]["client_oid"]
    assert len(calls) == 1
    assert evidence.status_code == 200
    bundle = evidence.json()
    assert bundle["release_candidate"]["release_id"] == release["release_id"]
    assert bundle["execution_evidence"]["bitget_order_id"] == "demo-order-release-123"
    assert {"redline_run_bound", "simulation_evidence_imported", "approval_granted", "demo_order_placed", "release_ready"}.issubset(
        {entry["event_type"] for entry in bundle["audit_log_slice"]}
    )
    assert audit.status_code == 200
    combined = json.dumps(bundle) + audit.text
    assert "demo-secret-do-not-leak" not in combined
    assert "demo-passphrase" not in combined


def test_release_tier_l0_l1_l2_transitions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)

    def fake_execute(*, service, run, payload, approval_hash="sha256:unapproved"):
        _ = service, payload
        order = BitgetOrderPlacement(
            client_oid="rl-tier-client-oid",
            bitget_order_id="demo-order-tier-123",
            response_hash="sha256:" + "7" * 64,
            placed_at="2026-06-24T00:00:00Z",
            status_code=200,
        )
        evidence = write_execution_evidence(
            run_id=run.run_id,
            out_dir=Path(run.out_dir),
            receipt_hash=run.receipt_hash or "sha256:" + "0" * 64,
            verdict=Status.PASS,
            intent=default_execution_intent(),
            order=order,
            issuance_ledger_entry_hash="sha256:genesis",
            issuance_checkpoint_hash="sha256:genesis",
            approval_hash=approval_hash,
        )
        return ExecutionResponse(run_id=run.run_id, ok=True, state="placed", evidence=evidence.model_dump(mode="json"))

    monkeypatch.setattr(service_app, "_execute_bitget_demo_order", fake_execute)
    run = _seed_service_run(client, tmp_path, run_id="run_release_tier")
    release = _create_release_for_run(client, run, release_id="rel_tier", version_id="strategy-tier")

    assert release["release_tier"] == ReleaseTier.L0.value
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).json()["state"] == "redline_passed"
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "tier approved"},
    ).json()["ok"] is True

    approved = client.get(f"/v1/release-candidates/{release['release_id']}", headers=_headers()).json()
    assert approved["state"] == "approved"
    assert approved["release_tier"] == ReleaseTier.L0.value

    executed = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    ready = client.get(f"/v1/release-candidates/{release['release_id']}", headers=_headers()).json()
    assert ready["state"] == "release_ready"
    assert ready["release_tier"] == ReleaseTier.L1.value

    bundle = client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).json()
    assert bundle["release_candidate"]["release_tier"] == ReleaseTier.L1.value
    assert bundle["release_decision_record"]["release_tier"] == ReleaseTier.L1.value

    live_gated = ReleaseCandidateResponse.model_validate(ready).model_copy(
        update={
            "state": ReleaseState.RELEASED_LIVE_GATED,
            "risk_policy": {**(ready["risk_policy"] or {}), "mainnet_enabled": True},
            "metadata": {
                **ready["metadata"],
                "live_gate": {
                    "confirm_mainnet_order": True,
                    "allow_live_gated_release": True,
                    "release_manager_id": "release-manager",
                    "second_reviewer_id": "second-reviewer",
                },
            },
        }
    )
    assert compute_release_tier(live_gated).tier == ReleaseTier.L2


def test_live_gated_requires_l2_and_double_control() -> None:
    release_ready = ReleaseCandidateResponse(
        release_id="rel_live_gated",
        strategy_id="demo-strategy",
        version_id="strategy-live-gated",
        state=ReleaseState.RELEASE_READY,
        release_tier=ReleaseTier.L1,
        created_by="strategy-author",
        metadata={},
        run_id="run-live-gated",
        redline_reason_code="PASS",
        redline_receipt_hash="sha256:" + "1" * 64,
        redline_report_hash="sha256:" + "2" * 64,
        simulation_evidence={"schema_version": "redline.release.simulation_evidence.v1"},
        simulation_evidence_hash="sha256:" + "3" * 64,
        risk_policy={"require_simulation_evidence": True, "require_demo_execution": True, "require_human_approval": True, "mainnet_enabled": False},
        risk_policy_hash="sha256:" + "4" * 64,
        approval={"reviewer_id": "release-reviewer", "consumed_at": "2026-06-24T00:00:00Z"},
        execution_run_id="run-live-gated",
        execution_evidence={"bitget_order_id": "demo-order-live-gated"},
        created_at="2026-06-24T00:00:00Z",
        updated_at="2026-06-24T00:00:00Z",
    )

    with pytest.raises(ReleaseTransitionMissingEvidenceError) as missing:
        transition_release(release_ready, ReleaseState.RELEASED_LIVE_GATED)
    assert {"mainnet_risk_policy", "live_gate_controls"} <= set(missing.value.missing)

    one_reviewer = release_ready.model_copy(
        update={
            "risk_policy": {**(release_ready.risk_policy or {}), "mainnet_enabled": True},
            "metadata": {
                "live_gate": {
                    "confirm_mainnet_order": True,
                    "allow_live_gated_release": True,
                    "release_manager_id": "release-manager",
                    "second_reviewer_id": "release-manager",
                }
            },
        }
    )
    with pytest.raises(ReleaseTransitionMissingEvidenceError) as single_reviewer_missing:
        transition_release(one_reviewer, ReleaseState.RELEASED_LIVE_GATED)
    assert "second_reviewer" in single_reviewer_missing.value.missing

    double_control = one_reviewer.model_copy(
        update={
            "metadata": {
                "live_gate": {
                    "confirm_mainnet_order": True,
                    "allow_live_gated_release": True,
                    "release_manager_id": "release-manager",
                    "second_reviewer_id": "second-reviewer",
                }
            }
        }
    )
    live_gated = transition_release(double_control, ReleaseState.RELEASED_LIVE_GATED)
    assert live_gated.state == ReleaseState.RELEASED_LIVE_GATED
    assert compute_release_tier(live_gated).tier == ReleaseTier.L2


def test_risk_policy_reduce_decision_executes_adjusted_size(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-reduce")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_reduce_risk", version_id="strategy-risk-reduce")

    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    risk = client.post(
        f"/v1/release-candidates/{release['release_id']}/risk-policy",
        headers=_headers(),
        json=_risk_policy_payload(max_order_notional_usdt="2.5", expected_order_notional_usdt="5"),
    )
    assert risk.status_code == 200
    assert risk.json()["ok"] is True
    assert risk.json()["state"] == "review_required"
    assert risk.json()["evidence"]["risk_policy_decision"]["decision"] == "reduce"
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "reduce-size approved"},
    )
    assert approval.status_code == 200
    assert approval.json()["ok"] is True

    executed = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={"size": "0.0002"})

    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    assert executed.json()["evidence"]["risk_policy_decision"] == {
        "decision": "reduce",
        "reason": "expected order notional exceeds release risk policy",
        "adjusted_size": "0.0001",
    }
    assert len(calls) == 1
    assert calls[0]["body"]["size"] == "0.0001"


def test_verify_release_bundle_cli_checks_generated_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-bundle")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_bundle_verify", version_id="strategy-bundle-verify")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "demo release approved"},
    ).status_code == 200
    executed = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    html_endpoint = client.get(f"/v1/release-candidates/{release['release_id']}/evidence.html", headers=_headers())
    bad_run = _create_chained_service_run(client, tmp_path, candidate="candidate_bad")
    html_out = tmp_path / "comparison.html"
    rendered = CliRunner().invoke(
        cli_app,
        [
            "render-evidence",
            "--good",
            run["out_dir"],
            "--bad",
            bad_run["out_dir"],
            "--out",
            str(html_out),
        ],
    )
    tampered_dir = tmp_path / "tampered-run"
    shutil.copytree(run["out_dir"], tampered_dir)
    tampered_payload = json.loads((tampered_dir / "execution-evidence.json").read_text(encoding="utf-8"))
    tampered_payload["bitget_order_id"] = "forged-order-999"
    atomic_write_text(tampered_dir / "execution-evidence.json", json.dumps(tampered_payload, indent=2, sort_keys=True) + "\n")
    tampered_out = tmp_path / "tampered.html"
    tampered_render = CliRunner().invoke(cli_app, ["render-evidence", str(tampered_dir), "--out", str(tampered_out)])

    verified = CliRunner().invoke(cli_app, ["verify-release-bundle", str(bundle_path), "--json"])
    order_status_path = Path(run["out_dir"]) / "order-status-evidence.json"
    order_status_payload = json.loads(order_status_path.read_text(encoding="utf-8"))
    order_status_payload["status"] = "filled"
    atomic_write_text(order_status_path, json.dumps(order_status_payload, indent=2, sort_keys=True) + "\n")
    tampered_order_status_bundle = CliRunner().invoke(cli_app, ["verify-release-bundle", str(bundle_path), "--json"])
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_payload["risk_policy"]["expected_order_notional_usdt"] = "999"
    atomic_write_text(bundle_path, json.dumps(bundle_payload, indent=2, sort_keys=True) + "\n")
    tampered_bundle = CliRunner().invoke(cli_app, ["verify-release-bundle", str(bundle_path), "--json"])

    assert html_endpoint.status_code == 200
    assert html_endpoint.headers["content-type"].startswith("text/html")
    assert "demo-order-bundle" in html_endpoint.text
    assert "DEMO" in html_endpoint.text
    assert "这不是 Bitget Playbook 正式发布" in html_endpoint.text
    endpoint_lower = html_endpoint.text.lower()
    assert "secret" not in endpoint_lower
    assert "passphrase" not in endpoint_lower
    assert "access key" not in endpoint_lower
    assert rendered.exit_code == 0, rendered.stdout
    comparison_html = html_out.read_text(encoding="utf-8")
    assert "demo-order-bundle" in comparison_html
    assert "NEW_BLOCK_BREACH" in comparison_html
    assert "Bitget 未被调用" in comparison_html
    assert "DEMO" in comparison_html
    assert "这不是 Bitget Playbook 正式发布" in comparison_html
    assert "secret" not in comparison_html.lower()
    assert "passphrase" not in comparison_html.lower()
    assert "access key" not in comparison_html.lower()
    assert tampered_render.exit_code == 0, tampered_render.stdout
    tampered_html = tampered_out.read_text(encoding="utf-8")
    assert "EVIDENCE INVALID" in tampered_html
    assert "hash mismatch" in tampered_html
    assert "forged-order-999" not in tampered_html
    assert verified.exit_code == 0, verified.stdout
    verified_payload = json.loads(verified.stdout)
    assert verified_payload["ok"] is True
    assert {"exchange-preflight-evidence", "order-status-evidence"}.issubset({check["name"] for check in verified_payload["checks"]})
    assert tampered_order_status_bundle.exit_code == 4
    assert json.loads(tampered_order_status_bundle.stdout)["ok"] is False
    assert tampered_bundle.exit_code == 4
    assert json.loads(tampered_bundle.stdout)["ok"] is False


def test_release_showcase_orders_place_multiple_demo_orders_after_release_ready(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-showcase")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_showcase", version_id="strategy-showcase")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase approved"},
    ).status_code == 200
    canonical = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "first showcase approval"},
    ).status_code == 200
    first = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "showcase-click-1"},
        json={"side": "buy", "size": "0.0001"},
    )
    replay = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "showcase-click-1"},
        json={"side": "buy", "size": "0.0001"},
    )
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "second showcase approval"},
    ).status_code == 200
    second = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "showcase-click-2"},
        json={"side": "sell", "size": "0.0001"},
    )
    listing = client.get(f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders", headers=_headers())

    assert canonical.status_code == 200
    assert canonical.json()["ok"] is True
    assert first.status_code == 200
    assert first.json()["ok"] is True
    assert first.json()["evidence"]["bitget_order_id"] == "demo-order-showcase-2"
    assert first.json()["evidence"]["showcase"] is True
    assert replay.status_code == 200
    assert replay.json()["evidence"]["attempt_id"] == first.json()["evidence"]["attempt_id"]
    assert second.status_code == 200
    assert second.json()["ok"] is True
    assert second.json()["evidence"]["bitget_order_id"] == "demo-order-showcase-3"
    assert first.json()["evidence"]["client_oid"] != second.json()["evidence"]["client_oid"]
    assert len(calls) == 3

    assert listing.status_code == 200
    payload = listing.json()
    assert payload["count"] == 2
    assert {order["bitget_order_id"] for order in payload["orders"]} == {"demo-order-showcase-2", "demo-order-showcase-3"}
    html = client.get(first.json()["evidence"]["evidence_html_url"], headers=_headers())
    assert html.status_code == 200
    assert "demo-order-showcase-2" in html.text
    assert "DEMO" in html.text
    assert "这不是 Bitget Playbook 正式发布" in html.text
    assert "secret" not in html.text.lower()
    assert "passphrase" not in html.text.lower()
    assert "access key" not in html.text.lower()
    evidence_path = Path(first.json()["evidence"]["evidence_path"])
    assert load_execution_evidence(evidence_path).bitget_order_id == "demo-order-showcase-2"
    ledger_path = tmp_path / "service" / "releases" / release["release_id"] / "demo-showcase-execution-ledger.jsonl"
    assert ledger_path.exists()
    assert "demo-order-showcase-2" in ledger_path.read_text(encoding="utf-8")


def test_release_showcase_order_job_runs_and_records_events(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-job")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_showcase_job", version_id="strategy-showcase-job")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase job approved"},
    ).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={}).json()["ok"] is True
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase job approval after canonical execution"},
    ).status_code == 200

    created = client.post(
        f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order",
        headers={**_headers(), "Idempotency-Key": "showcase-job-click-1"},
        json={"side": "sell", "size": "0.0001"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job_id}", headers=_headers())
        assert job.status_code == 200
        if job.json()["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.05)
    assert job.json()["status"] == "succeeded"
    assert job.json()["result"]["evidence"]["bitget_order_id"] == "demo-order-job-2"

    replay = client.post(
        f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order",
        headers={**_headers(), "Idempotency-Key": "showcase-job-click-1"},
        json={"side": "sell", "size": "0.0001"},
    )
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job_id}/events", headers=_headers())
    ndjson = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job_id}/events.ndjson", headers=_headers())
    jobs = client.get(f"/v1/release-candidates/{release['release_id']}/jobs", headers=_headers())

    assert replay.status_code == 200
    assert replay.json()["job_id"] == job_id
    assert replay.json()["status"] == "succeeded"
    assert len(calls) == 2
    assert events.status_code == 200
    event_payload = events.json()["events"]
    assert [item["event_type"] for item in event_payload][0] == "job_queued"
    assert "job_succeeded" in {item["event_type"] for item in event_payload}
    previous = "sha256:genesis"
    for item in event_payload:
        assert item["previous_event_hash"] == previous
        previous = item["event_hash"]
    assert ndjson.status_code == 200
    assert "job_succeeded" in ndjson.text
    assert jobs.status_code == 200
    assert {item["job_id"] for item in jobs.json()["jobs"]} == {job_id}
    combined = json.dumps(job.json()) + json.dumps(event_payload) + ndjson.text
    assert "demo-secret-do-not-leak" not in combined
    assert "demo-passphrase" not in combined
    assert "access key" not in combined.lower()


def test_release_execute_demo_job_runs_canonical_execution_and_records_events(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-canonical-job")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_execute_job", version_id="strategy-execute-job")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "execute job approved"},
    ).status_code == 200

    created = client.post(
        f"/v1/release-candidates/{release['release_id']}/jobs/execute-demo",
        headers={**_headers(), "Idempotency-Key": "execute-job-click-1"},
        json={"side": "buy", "size": "0.0001"},
    )
    assert created.status_code == 200
    assert created.json()["job_type"] == "canonical_execute_demo"
    job = _wait_for_release_job(client, release["release_id"], created.json()["job_id"])
    replay = client.post(
        f"/v1/release-candidates/{release['release_id']}/jobs/execute-demo",
        headers={**_headers(), "Idempotency-Key": "execute-job-click-1"},
        json={"side": "buy", "size": "0.0001"},
    )
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job['job_id']}/events", headers=_headers())
    release_after = client.get(f"/v1/release-candidates/{release['release_id']}", headers=_headers())

    assert job["status"] == "succeeded"
    assert job["result"]["state"] == "release_ready"
    assert job["result"]["evidence"]["bitget_order_id"] == "demo-order-canonical-job-1"
    assert replay.status_code == 200
    assert replay.json()["job_id"] == job["job_id"]
    assert replay.json()["status"] == "succeeded"
    assert release_after.json()["state"] == "release_ready"
    assert release_after.json()["execution_evidence"]["bitget_order_id"] == "demo-order-canonical-job-1"
    assert len(calls) == 1
    event_types = {event["event_type"] for event in events.json()["events"]}
    assert {"job_queued", "job_started", "redline_verification_passed", "risk_policy_checked", "exchange_preflight_passed", "bitget_order_requested", "bitget_order_placed", "bitget_reconciliation_succeeded", "evidence_written", "job_succeeded"} <= event_types
    combined = json.dumps(job) + events.text
    assert "demo-secret-do-not-leak" not in combined
    assert "demo-passphrase" not in combined
    assert "access key" not in combined.lower()


def test_release_showcase_job_can_cancel_queued_job(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run = _seed_service_run(client, tmp_path, run_id="run_cancel_job")
    release = _create_release_for_run(client, run, release_id="rel_cancel_job", version_id="strategy-cancel-job")
    service = client.app.state.redline_service
    request_payload = {"side": "buy", "size": "0.0001"}
    job = service.store.create_release_job(
        job_id="job_cancel_queued",
        release_id=release["release_id"],
        job_type=ReleaseJobType.SHOWCASE_ORDER,
        request_hash=hash_obj(request_payload),
        request=request_payload,
        idempotency_key=None,
        requested_by="pytest",
    )
    service.store.append_release_job_event(release_id=release["release_id"], job_id=job.job_id, event_type="job_queued", payload={"job_type": job.job_type.value})

    cancelled = client.post(f"/v1/release-candidates/{release['release_id']}/jobs/{job.job_id}/cancel", headers=_headers())
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job.job_id}/events", headers=_headers())

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["error_code"] == "JOB_CANCELLED"
    assert service.store.claim_next_release_job(worker_id="pytest") is None
    assert events.status_code == 200
    assert [event["event_type"] for event in events.json()["events"]] == ["job_queued", "job_cancelled"]


def test_release_showcase_job_running_state_recovers_on_startup(tmp_path: Path) -> None:
    root = tmp_path / "service"
    client = TestClient(create_app(ServiceConfig(root=root, token="test-token", workers=1)))
    run = _seed_service_run(client, tmp_path, run_id="run_recover_job")
    release = _create_release_for_run(client, run, release_id="rel_recover_job", version_id="strategy-recover-job")
    service = client.app.state.redline_service
    request_payload = {"side": "buy", "size": "0.0001"}
    job = service.store.create_release_job(
        job_id="job_recover_running",
        release_id=release["release_id"],
        job_type=ReleaseJobType.SHOWCASE_ORDER,
        request_hash=hash_obj(request_payload),
        request=request_payload,
        idempotency_key=None,
        requested_by="pytest",
    )
    service.store.append_release_job_event(release_id=release["release_id"], job_id=job.job_id, event_type="job_queued", payload={"job_type": job.job_type.value})
    service.store.mark_release_job_status(job_id=job.job_id, status=ReleaseJobStatus.RUNNING)
    client.close()

    restarted = TestClient(create_app(ServiceConfig(root=root, token="test-token", workers=1)))
    recovered = restarted.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job.job_id}", headers=_headers())
    events = restarted.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job.job_id}/events", headers=_headers())

    assert recovered.status_code == 200
    assert recovered.json()["status"] == "failed"
    assert recovered.json()["error_code"] == "JOB_RECOVERY_REQUIRED"
    assert events.status_code == 200
    assert "job_failed" in {event["event_type"] for event in events.json()["events"]}


def test_release_job_event_chain_tamper_is_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run = _seed_service_run(client, tmp_path, run_id="run_tamper_job_event")
    release = _create_release_for_run(client, run, release_id="rel_tamper_job_event", version_id="strategy-tamper-job-event")
    service = client.app.state.redline_service
    request_payload = {"side": "buy", "size": "0.0001"}
    job = service.store.create_release_job(
        job_id="job_tamper_event",
        release_id=release["release_id"],
        job_type=ReleaseJobType.SHOWCASE_ORDER,
        request_hash=hash_obj(request_payload),
        request=request_payload,
        idempotency_key=None,
        requested_by="pytest",
    )
    service.store.append_release_job_event(release_id=release["release_id"], job_id=job.job_id, event_type="job_queued", payload={"job_type": job.job_type.value})
    with sqlite3.connect(tmp_path / "service" / "redline-service.sqlite3") as conn:
        conn.execute(
            "UPDATE release_job_events SET payload_json = ? WHERE job_id = ? AND sequence = 0",
            (json.dumps({"job_type": "forged"}), job.job_id),
        )

    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job.job_id}/events", headers=_headers())

    assert events.status_code == 400
    assert events.json()["error_code"] == "RECEIPT_MISMATCH"


def test_release_showcase_job_records_bitget_rejected_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(
        calls,
        order_id_factory=lambda _count: "demo-order-canonical",
        reject_place_from_call=2,
    )
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_job_rejected", version_id="strategy-job-rejected")
    created = client.post(f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order", headers=_headers(), json={"size": "0.0001"})

    assert created.status_code == 200
    job = _wait_for_release_job(client, release["release_id"], created.json()["job_id"])
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job['job_id']}/events", headers=_headers()).json()["events"]

    assert job["status"] == "failed"
    assert job["error_code"] == "BITGET_ORDER_REJECTED"
    assert len(calls) == 2
    event_types = [event["event_type"] for event in events]
    assert "bitget_order_requested" in event_types
    assert event_types[-1] == "job_failed"


def test_release_showcase_job_risk_breach_fails_before_bitget(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-canonical-risk")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_job_risk_breach", version_id="strategy-job-risk-breach")
    created = client.post(f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order", headers=_headers(), json={"symbol": "XRPUSDT", "size": "0.0001"})

    assert created.status_code == 200
    job = _wait_for_release_job(client, release["release_id"], created.json()["job_id"])
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job['job_id']}/events", headers=_headers()).json()["events"]

    assert job["status"] == "failed"
    assert job["error_code"] == "RISK_POLICY_BREACH"
    assert len(calls) == 1
    assert "bitget_order_requested" not in {event["event_type"] for event in events}


def test_release_showcase_job_stale_approval_fails_before_bitget(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-canonical-stale")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_job_stale_approval", version_id="strategy-job-stale-approval")
    service = client.app.state.redline_service
    current = service.store.get_release_candidate(release["release_id"])
    assert current is not None
    changed_policy = dict(current.risk_policy or {})
    changed_policy["expected_order_notional_usdt"] = "6"
    service.store.update_release_candidate(current.model_copy(update={"risk_policy": changed_policy, "risk_policy_hash": hash_obj(changed_policy)}))
    created = client.post(f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order", headers=_headers(), json={"size": "0.0001"})

    assert created.status_code == 200
    job = _wait_for_release_job(client, release["release_id"], created.json()["job_id"])
    events = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job['job_id']}/events", headers=_headers()).json()["events"]

    assert job["status"] == "failed"
    assert job["error_code"] == "APPROVAL_EVIDENCE_CHANGED"
    assert len(calls) == 1
    assert "bitget_order_requested" not in {event["event_type"] for event in events}


def test_judge_console_renders_release_jobs_and_attestation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    assert client.get("/v1/judge/console").status_code == 401

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-judge")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_judge_console", version_id="strategy-judge-console")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "judge console approved"},
    ).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={}).json()["ok"] is True
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "judge console showcase approval"},
    ).status_code == 200
    created = client.post(
        f"/v1/release-candidates/{release['release_id']}/jobs/showcase-order",
        headers={**_headers(), "Idempotency-Key": "judge-console-job"},
        json={"side": "buy", "size": "0.0001"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f"/v1/release-candidates/{release['release_id']}/jobs/{job_id}", headers=_headers())
        assert job.status_code == 200
        if job.json()["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.05)
    assert job.json()["status"] == "succeeded"
    assert client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={}).json()["ok"] is True

    console = client.get("/v1/judge/console", headers=_headers())
    detail = client.get(f"/v1/judge/releases/{release['release_id']}", headers=_headers())

    assert console.status_code == 200
    assert console.headers["content-type"].startswith("text/html")
    assert release["release_id"] in console.text
    assert "release_ready" in console.text
    assert "ATTESTED" in console.text
    assert "succeeded" in console.text
    assert detail.status_code == 200
    assert "DEMO / paptrading:1 / non-mainnet" in detail.text
    assert "Run live Bitget demo showcase order" in detail.text
    assert "/jobs/showcase-order" in detail.text
    assert "events.ndjson" in detail.text
    assert "demo-order-judge-2" in detail.text
    assert "job_succeeded" in detail.text
    assert "bundle verify" in detail.text
    assert "ATTESTED" in detail.text
    combined = console.text + detail.text
    assert "demo-secret-do-not-leak" not in combined
    assert "demo-passphrase" not in combined
    assert "secret" not in combined.lower()
    assert "passphrase" not in combined.lower()
    assert "access key" not in combined.lower()


def test_release_showcase_orders_reject_tampered_canonical_evidence_before_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-tamper")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_showcase_tamper", version_id="strategy-showcase-tamper")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase approved"},
    ).status_code == 200
    canonical = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert canonical.status_code == 200
    assert canonical.json()["ok"] is True
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "showcase approval after canonical execution"},
    ).status_code == 200
    evidence_path = Path(run["out_dir"]) / "execution-evidence.json"
    tampered = json.loads(evidence_path.read_text(encoding="utf-8"))
    tampered["bitget_order_id"] = "forged-showcase-order"
    atomic_write_text(evidence_path, json.dumps(tampered, indent=2, sort_keys=True) + "\n")

    response = client.post(f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders", headers=_headers(), json={})

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["reason_code"] == "RELEASE_EVIDENCE_CHANGED"
    assert len(calls) == 1


def test_release_attestation_cli_and_service_verify_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-attest")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_attest", version_id="strategy-attest")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "attestation approved"},
    ).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={}).json()["ok"] is True
    missing = client.get(f"/v1/release-candidates/{release['release_id']}/attestation", headers=_headers())
    assert missing.status_code == 404
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    cli_attestation_path = tmp_path / "service" / "releases" / release["release_id"] / "cli-release-attestation.json"

    cli_attest = CliRunner().invoke(cli_app, ["attest-release-bundle", str(bundle_path), "--out", str(cli_attestation_path), "--json"])
    cli_verify = CliRunner().invoke(cli_app, ["verify-release-attestation", str(cli_attestation_path), "--bundle", str(bundle_path), "--json"])
    service_attest = client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={})
    service_get = client.get(f"/v1/release-candidates/{release['release_id']}/attestation", headers=_headers())
    service_html = client.get(f"/v1/release-candidates/{release['release_id']}/attestation.html", headers=_headers())
    evidence_html = client.get(f"/v1/release-candidates/{release['release_id']}/evidence.html", headers=_headers())

    assert cli_attest.exit_code == 0, cli_attest.stdout
    assert cli_verify.exit_code == 0, cli_verify.stdout
    assert json.loads(cli_verify.stdout)["ok"] is True
    assert service_attest.status_code == 200
    assert service_attest.json()["ok"] is True
    assert service_attest.json()["evidence"]["bundle_hash"] == json.loads(cli_verify.stdout)["bundle_hash"]
    assert service_get.status_code == 200
    assert service_get.json()["verification"]["ok"] is True
    assert service_html.status_code == 200
    assert "ATTESTED" in service_html.text
    assert evidence_html.status_code == 200
    assert "ATTESTED" in evidence_html.text
    combined = json.dumps(service_attest.json()) + service_html.text + evidence_html.text
    assert "demo-secret-do-not-leak" not in combined
    assert "passphrase" not in combined.lower()
    assert "access key" not in combined.lower()

    tampered = json.loads(bundle_path.read_text(encoding="utf-8"))
    tampered["risk_policy"]["expected_order_notional_usdt"] = "999"
    atomic_write_text(bundle_path, json.dumps(tampered, indent=2, sort_keys=True) + "\n")
    tampered_verify = CliRunner().invoke(cli_app, ["verify-release-attestation", str(cli_attestation_path), "--bundle", str(bundle_path), "--json"])

    assert tampered_verify.exit_code == 4
    assert json.loads(tampered_verify.stdout)["ok"] is False


def test_release_attestation_covers_execution_evidence_merkle_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-attest-merkle")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_attest_merkle", version_id="strategy-attest-merkle")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    attestation_path = tmp_path / "service" / "releases" / release["release_id"] / "release-attestation.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    execution = bundle["execution_evidence"]
    expected_root = merkle_root(
        [
            bundle["redline"]["receipt_hash"],
            execution["approval_hash"],
            execution["artifact_hash"],
        ]
    )

    cli_attest = CliRunner().invoke(cli_app, ["attest-release-bundle", str(bundle_path), "--out", str(attestation_path), "--json"])
    cli_verify = CliRunner().invoke(cli_app, ["verify-release-attestation", str(attestation_path), "--bundle", str(bundle_path), "--json"])
    service_attest = client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={})

    assert cli_attest.exit_code == 0, cli_attest.stdout
    attest_payload = json.loads(cli_attest.stdout)
    assert attest_payload["evidence_merkle_root"] == expected_root
    assert cli_verify.exit_code == 0, cli_verify.stdout
    verify_payload = json.loads(cli_verify.stdout)
    assert verify_payload["ok"] is True
    assert verify_payload["evidence_merkle_root"] == expected_root
    assert {"name": "evidence-merkle-root", "ok": True, "detail": expected_root} in verify_payload["checks"]
    assert service_attest.status_code == 200
    assert service_attest.json()["ok"] is True
    assert service_attest.json()["evidence"]["evidence_merkle_root"] == expected_root
    assert service_attest.json()["evidence"]["verification"]["evidence_merkle_root"] == expected_root


def test_chain_break_pinpoints_broken_link(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-chain-break")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_chain_break", version_id="strategy-chain-break")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    original = json.loads(bundle_path.read_text(encoding="utf-8"))
    baseline = verify_release_evidence_bundle(bundle_path)
    baseline_checks = {item["name"]: item for item in baseline["checks"]}
    for name in ("chain-receipt-link", "chain-approval-link", "chain-execution-link", "chain-checkpoint-link"):
        assert baseline_checks[name]["ok"] is True

    def verify_after_tamper(mutator) -> tuple[dict, dict[str, dict]]:
        tampered = json.loads(json.dumps(original))
        mutator(tampered)
        atomic_write_text(bundle_path, json.dumps(tampered, indent=2, sort_keys=True) + "\n")
        result = verify_release_evidence_bundle(bundle_path)
        return result, {item["name"]: item for item in result["checks"]}

    receipt_result, receipt_checks = verify_after_tamper(lambda bundle: bundle["redline"].update({"receipt_hash": "sha256:" + "1" * 64}))
    assert receipt_result["ok"] is False
    assert receipt_checks["chain-receipt-link"]["ok"] is False
    assert "receipt" in receipt_checks["chain-receipt-link"]["detail"]

    approval_result, approval_checks = verify_after_tamper(lambda bundle: bundle["release_candidate"]["approval"].update({"reviewer_id": "forged-reviewer"}))
    assert approval_result["ok"] is False
    assert approval_checks["chain-approval-link"]["ok"] is False
    assert "approval" in approval_checks["chain-approval-link"]["detail"]

    execution_result, execution_checks = verify_after_tamper(lambda bundle: bundle["execution_evidence"].update({"receipt_hash": "sha256:" + "2" * 64}))
    assert execution_result["ok"] is False
    assert execution_checks["chain-execution-link"]["ok"] is False
    assert "execution" in execution_checks["chain-execution-link"]["detail"]

    def tamper_checkpoint(bundle: dict) -> None:
        checkpoint_artifact = next(item for item in bundle["redline"]["artifacts"] if item["artifact_id"] == "issuance-ledger-checkpoint")
        checkpoint_artifact["content"]["subject_receipt_hashes"] = []

    checkpoint_result, checkpoint_checks = verify_after_tamper(tamper_checkpoint)
    assert checkpoint_result["ok"] is False
    assert checkpoint_checks["chain-checkpoint-link"]["ok"] is False
    assert "checkpoint" in checkpoint_checks["chain-checkpoint-link"]["detail"]

    atomic_write_text(bundle_path, json.dumps(original, indent=2, sort_keys=True) + "\n")


def test_release_bundle_verifier_rejects_unsafe_execution_run_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-unsafe-run-id")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_unsafe_run_id", version_id="strategy-unsafe-run-id")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["execution_evidence"]["run_id"] = "../outside"
    atomic_write_text(bundle_path, json.dumps(bundle, indent=2, sort_keys=True) + "\n")

    result = verify_release_evidence_bundle(bundle_path)

    checks = {item["name"]: item for item in result["checks"]}
    assert result["ok"] is False
    assert checks["execution-evidence"]["ok"] is False
    assert "safe artifact path" in checks["execution-evidence"]["detail"]


def test_verify_chain_happy_path_zero_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-verify-chain")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_verify_chain", version_id="strategy-verify-chain")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={}).json()["ok"] is True
    release_dir_path = tmp_path / "service" / "releases" / release["release_id"]
    for secret_name in (
        "REDLINE_BITGET_DEMO_ACCESS_KEY",
        "REDLINE_BITGET_DEMO_SECRET_KEY",
        "REDLINE_BITGET_DEMO_PASSPHRASE",
        "REDLINE_ATTESTATION_PRIVATE_KEY",
        "REDLINE_TRUST_PRIVATE_KEY",
    ):
        monkeypatch.delenv(secret_name, raising=False)

    verified = CliRunner().invoke(cli_app, ["verify-chain", str(release_dir_path), "--json"])

    assert verified.exit_code == 0, verified.stdout
    payload = json.loads(verified.stdout)
    assert payload["schema_version"] == "redline.chain.verify.v1"
    assert payload["ok"] is True
    assert payload["release_dir"] == str(release_dir_path)
    assert payload["bundle"]["ok"] is True
    assert payload["attestation"]["ok"] is True
    check_names = {item["name"] for item in payload["checks"] if item["ok"]}
    assert {"chain-receipt-link", "chain-approval-link", "chain-execution-link", "chain-checkpoint-link", "signature"}.issubset(check_names)
    combined = verified.stdout + json.dumps(payload)
    assert "demo-secret-do-not-leak" not in combined
    assert "passphrase" not in combined.lower()
    assert "access key" not in combined.lower()


def test_verify_chain_detects_each_tampered_link(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-verify-chain-tamper")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_verify_chain_tamper", version_id="strategy-verify-chain-tamper")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={}).json()["ok"] is True
    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    original = json.loads(bundle_path.read_text(encoding="utf-8"))

    def run_tampered(mutator, expected_check: str) -> None:
        tampered = json.loads(json.dumps(original))
        mutator(tampered)
        atomic_write_text(bundle_path, json.dumps(tampered, indent=2, sort_keys=True) + "\n")
        result = CliRunner().invoke(cli_app, ["verify-chain", str(bundle_path), "--json"])
        assert result.exit_code == 4, result.stdout
        payload = json.loads(result.stdout)
        checks = {item["name"]: item for item in payload["checks"]}
        assert payload["ok"] is False
        assert checks[expected_check]["ok"] is False

    run_tampered(lambda bundle: bundle["redline"].update({"receipt_hash": "sha256:" + "3" * 64}), "chain-receipt-link")
    run_tampered(lambda bundle: bundle["release_candidate"]["approval"].update({"reviewer_id": "forged-reviewer"}), "chain-approval-link")
    run_tampered(lambda bundle: bundle["execution_evidence"].update({"receipt_hash": "sha256:" + "4" * 64}), "chain-execution-link")

    def tamper_checkpoint(bundle: dict) -> None:
        checkpoint_artifact = next(item for item in bundle["redline"]["artifacts"] if item["artifact_id"] == "issuance-ledger-checkpoint")
        checkpoint_artifact["content"]["subject_receipt_hashes"] = []

    run_tampered(tamper_checkpoint, "chain-checkpoint-link")
    atomic_write_text(bundle_path, json.dumps(original, indent=2, sort_keys=True) + "\n")


def test_tamper_demo_script_detects_tampered_release_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-tamper-script")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_tamper_script", version_id="strategy-tamper-script")
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={}).json()["ok"] is True
    release_dir_path = tmp_path / "service" / "releases" / release["release_id"]
    for secret_name in (
        "REDLINE_BITGET_DEMO_ACCESS_KEY",
        "REDLINE_BITGET_DEMO_SECRET_KEY",
        "REDLINE_BITGET_DEMO_PASSPHRASE",
        "REDLINE_ATTESTATION_PRIVATE_KEY",
        "REDLINE_TRUST_PRIVATE_KEY",
    ):
        monkeypatch.delenv(secret_name, raising=False)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "tamper-demo.sh"), str(release_dir_path)],
        cwd=ROOT,
        env=os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode != 0
    assert "TAMPER_DETECTED" in completed.stdout
    assert "first_failed_check=" in completed.stdout
    assert "reason_code=" in completed.stdout
    assert "release-evidence-bundle.json" in completed.stdout
    assert "demo-secret-do-not-leak" not in completed.stdout
    assert "passphrase" not in completed.stdout.lower()
    assert "access key" not in completed.stdout.lower()


def test_verify_execution_evidence_cli_zero_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-verify-execution")
    run = _create_chained_service_run(client, tmp_path)
    executed = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    for secret_name in (
        "REDLINE_BITGET_DEMO_ACCESS_KEY",
        "REDLINE_BITGET_DEMO_SECRET_KEY",
        "REDLINE_BITGET_DEMO_PASSPHRASE",
    ):
        monkeypatch.delenv(secret_name, raising=False)

    evidence_path = Path(run["out_dir"]) / "execution-evidence.json"
    verified = CliRunner().invoke(cli_app, ["verify-execution-evidence", str(evidence_path), "--json"])

    assert verified.exit_code == 0, verified.stdout
    payload = json.loads(verified.stdout)
    assert payload["schema_version"] == "redline.execution_evidence.verify.v1"
    assert payload["ok"] is True
    assert payload["evidence_path"] == str(evidence_path)
    assert payload["ledger_path"] == str(Path(run["out_dir"]) / "execution-ledger.jsonl")
    assert payload["artifact_hash"] == executed.json()["evidence"]["artifact_hash"]
    check_names = {item["name"] for item in payload["checks"] if item["ok"]}
    assert {"execution-evidence", "execution-ledger-chain", "execution-ledger-entry-link"}.issubset(check_names)
    combined = verified.stdout + json.dumps(payload)
    assert "demo-secret-do-not-leak" not in combined
    assert "passphrase" not in combined.lower()
    assert "access key" not in combined.lower()


def test_verify_execution_evidence_cli_accepts_release_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(
        calls, order_id_factory=lambda _count: "demo-order-verify-execution-dir"
    )
    run, release = _create_release_ready_for_showcase_job(
        client,
        tmp_path,
        release_id="rel_verify_execution_dir",
        version_id="strategy-verify-execution-dir",
    )
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200
    release_dir = tmp_path / "service" / "releases" / release["release_id"]
    for secret_name in (
        "REDLINE_BITGET_DEMO_ACCESS_KEY",
        "REDLINE_BITGET_DEMO_SECRET_KEY",
        "REDLINE_BITGET_DEMO_PASSPHRASE",
    ):
        monkeypatch.delenv(secret_name, raising=False)

    verified = CliRunner().invoke(cli_app, ["verify-execution-evidence", str(release_dir), "--json"])

    assert verified.exit_code == 0, verified.stdout
    payload = json.loads(verified.stdout)
    assert payload["schema_version"] == "redline.execution_evidence.verify.v1"
    assert payload["ok"] is True
    assert payload["input_path"] == str(release_dir)
    assert payload["evidence_path"] == str(Path(run["out_dir"]) / "execution-evidence.json")
    assert payload["ledger_path"] == str(Path(run["out_dir"]) / "execution-ledger.jsonl")
    check_names = {item["name"] for item in payload["checks"] if item["ok"]}
    assert {"execution-evidence", "execution-ledger-chain", "execution-ledger-entry-link"}.issubset(check_names)
    combined = verified.stdout + json.dumps(payload)
    assert "demo-secret-do-not-leak" not in combined
    assert "passphrase" not in combined.lower()
    assert "access key" not in combined.lower()


def test_verify_execution_evidence_cli_detects_tampered_evidence_and_ledger(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-verify-execution-tamper")
    run = _create_chained_service_run(client, tmp_path)
    executed = client.post(f"/v1/runs/{run['run_id']}/execute", headers=_headers(), json={})
    assert executed.status_code == 200
    assert executed.json()["ok"] is True
    evidence_path = Path(run["out_dir"]) / "execution-evidence.json"
    ledger_path = Path(run["out_dir"]) / "execution-ledger.jsonl"
    original_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    original_ledger = ledger_path.read_text(encoding="utf-8")

    tampered_evidence = dict(original_evidence)
    tampered_evidence["bitget_order_id"] = "forged-order"
    atomic_write_text(evidence_path, json.dumps(tampered_evidence, indent=2, sort_keys=True) + "\n")
    evidence_result = CliRunner().invoke(cli_app, ["verify-execution-evidence", str(evidence_path), "--json"])

    assert evidence_result.exit_code == 4, evidence_result.stdout
    evidence_payload = json.loads(evidence_result.stdout)
    assert evidence_payload["ok"] is False
    assert {item["name"]: item for item in evidence_payload["checks"]}["execution-evidence"]["ok"] is False

    atomic_write_text(evidence_path, json.dumps(original_evidence, indent=2, sort_keys=True) + "\n")
    ledger_entry = json.loads(original_ledger.splitlines()[0])
    ledger_entry["bitget_order_id"] = "forged-ledger-order"
    atomic_write_text(ledger_path, json.dumps(ledger_entry, sort_keys=True) + "\n")
    ledger_result = CliRunner().invoke(cli_app, ["verify-execution-evidence", str(evidence_path), "--json"])

    assert ledger_result.exit_code == 4, ledger_result.stdout
    ledger_payload = json.loads(ledger_result.stdout)
    assert ledger_payload["ok"] is False
    assert {item["name"]: item for item in ledger_payload["checks"]}["execution-ledger-chain"]["ok"] is False
    atomic_write_text(ledger_path, original_ledger)


def test_hackathon_pack_cli_builds_offline_verifiable_submission_pack(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []

    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-pack")
    run = _create_chained_service_run(client, tmp_path)
    release = _create_release_for_run(client, run, release_id="rel_hackathon_pack", version_id="strategy-pack")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "pack approved"},
    ).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={}).json()["ok"] is True
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "pack showcase approval"},
    ).status_code == 200
    showcase = client.post(
        f"/v1/release-candidates/{release['release_id']}/demo-showcase-orders",
        headers={**_headers(), "Idempotency-Key": "pack-showcase"},
        json={"side": "buy", "size": "0.0001"},
    )
    assert showcase.status_code == 200
    assert showcase.json()["ok"] is True
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200

    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    pack_dir = tmp_path / "pack"
    manifest_path = tmp_path / "hackathon-submit-manifest.json"
    packed = CliRunner().invoke(
        cli_app,
        [
            "hackathon-pack",
            str(bundle_path),
            "--out",
            str(pack_dir),
            "--manifest",
            str(manifest_path),
            "--json",
        ],
    )

    assert packed.exit_code == 0, packed.stdout
    payload = json.loads(packed.stdout)
    pack_bundle = Path(payload["latest_release_bundle"])
    pack_attestation = Path(payload["latest_attestation"])
    assert pack_bundle == pack_dir / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    assert pack_attestation.exists()
    assert manifest_path.exists()
    assert (pack_dir / "README.md").exists()
    assert (pack_dir / "judge-demo-curl.sh").exists()
    assert (pack_dir / "verify-output.json").exists()
    assert (pack_dir / "showcase-index.json").exists()
    assert {item["kind"] for item in payload["latest_real_bitget_orders"]} == {"canonical", "showcase"}
    assert "demo-order-pack-1" in {item["bitget_order_id"] for item in payload["latest_real_bitget_orders"]}
    assert "demo-order-pack-2" in {item["bitget_order_id"] for item in payload["latest_real_bitget_orders"]}

    verify_bundle = CliRunner().invoke(cli_app, ["verify-release-bundle", str(pack_bundle), "--json"])
    verify_attestation = CliRunner().invoke(cli_app, ["verify-release-attestation", str(pack_attestation), "--bundle", str(pack_bundle), "--json"])

    assert verify_bundle.exit_code == 0, verify_bundle.stdout
    assert verify_attestation.exit_code == 0, verify_attestation.stdout
    generated_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            manifest_path,
            pack_dir / "hackathon-submit-manifest.json",
            pack_dir / "verify-output.json",
            pack_dir / "showcase-index.json",
            pack_dir / "README.md",
            pack_dir / "judge-demo-curl.sh",
        ]
    )
    assert "demo-secret-do-not-leak" not in generated_text
    assert "demo-passphrase" not in generated_text


def test_hackathon_pack_rejects_unsafe_release_id_from_self_consistent_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_prefix="demo-order-pack-safe")
    _, release = _create_release_ready_for_showcase_job(
        client,
        tmp_path,
        release_id="rel_hackathon_pack_safe",
        version_id="strategy-pack-safe",
    )
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200

    bundle_path = tmp_path / "service" / "releases" / release["release_id"] / "release-evidence-bundle.json"
    manifest_path = bundle_path.parent / "release-evidence-manifest.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["release_candidate"]["release_id"] = "../../pwned"
    atomic_write_text(bundle_path, json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        if item["path"] == "release-evidence-bundle.json":
            item["sha256"] = hash_file(bundle_path)
            item["bytes"] = bundle_path.stat().st_size
    atomic_write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    assert verify_release_evidence_bundle(bundle_path)["ok"] is True

    pack_dir = tmp_path / "pack"
    packed = CliRunner().invoke(
        cli_app,
        [
            "hackathon-pack",
            str(bundle_path),
            "--out",
            str(pack_dir),
            "--manifest",
            str(tmp_path / "hackathon-submit-manifest.json"),
            "--json",
        ],
    )

    assert packed.exit_code == 4, packed.stdout
    payload = json.loads(packed.stdout)
    assert payload["ok"] is False
    assert payload["reason_code"] == "RECEIPT_BINDING_FAILED"
    assert "release id is not a safe artifact id" in payload["message"]
    assert not (pack_dir / "pwned").exists()


def test_release_withheld_and_missing_simulation_evidence_cannot_approve(tmp_path: Path) -> None:
    client = _client(tmp_path)
    bad_run = _seed_service_run(client, tmp_path, run_id="run_release_bad", state=RunState.FAIL, reason_code="NEW_BLOCK_BREACH")
    bad_release = _create_release_for_run(client, bad_run, release_id="rel_bad", version_id="strategy-bad")
    client.app.state.redline_service.execution_transport = lambda method, url, headers, body: (_ for _ in ()).throw(AssertionError("must not call Bitget"))

    bound_bad = client.post(f"/v1/release-candidates/{bad_release['release_id']}/redline-run", headers=_headers(), json={"run_id": bad_run["run_id"]})
    approve_bad = client.post(
        f"/v1/release-candidates/{bad_release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    )
    execute_bad = client.post(f"/v1/release-candidates/{bad_release['release_id']}/execute-demo", headers=_headers(), json={})

    assert bound_bad.status_code == 200
    assert bound_bad.json()["ok"] is False
    assert bound_bad.json()["state"] == "blocked_withheld"
    assert approve_bad.status_code == 200
    assert approve_bad.json()["ok"] is False
    assert approve_bad.json()["reason_code"] == "BLOCKED_WITHHELD"
    assert execute_bad.status_code == 200
    assert execute_bad.json()["ok"] is False
    assert execute_bad.json()["state"] == "blocked_withheld"
    assert execute_bad.json()["reason_code"] == "BLOCKED_WITHHELD"

    good_run = _seed_service_run(client, tmp_path, run_id="run_release_missing_sim")
    good_release = _create_release_for_run(client, good_run, release_id="rel_missing_sim", version_id="strategy-missing-sim")
    assert client.post(f"/v1/release-candidates/{good_release['release_id']}/redline-run", headers=_headers(), json={"run_id": good_run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{good_release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200

    approve_missing_sim = client.post(
        f"/v1/release-candidates/{good_release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    )

    assert approve_missing_sim.status_code == 200
    assert approve_missing_sim.json()["ok"] is False
    assert approve_missing_sim.json()["reason_code"] == "SIMULATION_EVIDENCE_REQUIRED"


def test_require_demo_execution_enforced_before_release_evidence_bundle(tmp_path: Path) -> None:
    client = _client(tmp_path)
    run = _seed_service_run(client, tmp_path, run_id="run_require_demo")
    release = _create_release_for_run(client, run, release_id="rel_require_demo", version_id="strategy-require-demo")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload(require_demo_execution=True)).status_code == 200
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "approval alone is not final release evidence"},
    )

    evidence = client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers())
    attest = client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={})

    assert approval.status_code == 200
    assert approval.json()["ok"] is True
    assert evidence.status_code == 409
    assert evidence.json()["ok"] is False
    assert evidence.json()["state"] == ReleaseState.BLOCKED_MISSING_EVIDENCE
    assert evidence.json()["reason_code"] == "BLOCKED_MISSING_EVIDENCE"
    assert evidence.json()["evidence"]["missing"] == ["demo_execution"]
    assert attest.status_code == 200
    assert attest.json()["ok"] is False
    assert attest.json()["state"] == ReleaseState.BLOCKED_MISSING_EVIDENCE
    assert attest.json()["reason_code"] == "BLOCKED_MISSING_EVIDENCE"
    assert attest.json()["evidence"]["missing"] == ["demo_execution"]


def test_release_blocked_state_is_terminal(tmp_path: Path) -> None:
    client = _client(tmp_path)
    bad_run = _seed_service_run(client, tmp_path, run_id="run_terminal_bad", state=RunState.FAIL, reason_code="NEW_BLOCK_BREACH")
    bad_release = _create_release_for_run(client, bad_run, release_id="rel_terminal_bad", version_id="strategy-terminal-bad")

    bound = client.post(f"/v1/release-candidates/{bad_release['release_id']}/redline-run", headers=_headers(), json={"run_id": bad_run["run_id"]})
    simulation = client.post(f"/v1/release-candidates/{bad_release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload())

    assert bound.status_code == 200
    assert bound.json()["state"] == "blocked_withheld"
    assert simulation.status_code == 409
    assert "terminal" in simulation.json()["message"]


def test_approval_binds_package_hash_not_just_version_id(tmp_path: Path) -> None:
    client = _client(tmp_path)
    service = client.app.state.redline_service
    run = _seed_service_run(client, tmp_path, run_id="run_approval_package_bind")
    release = _create_release_for_run(client, run, release_id="rel_approval_package_bind", version_id="strategy-approval-package-bind")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer", "comment": "package-bound approval"},
    )
    assert approval.status_code == 200
    assert approval.json()["ok"] is True

    with sqlite3.connect(service.store.db_path) as conn:
        conn.execute(
            """
            UPDATE strategy_versions
            SET package_hash = ?, identity_lock_hash = ?
            WHERE version_id = ?
            """,
            ("sha256:" + "9" * 64, "sha256:" + "8" * 64, release["version_id"]),
        )

    executed = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})

    assert executed.status_code == 200
    assert executed.json()["ok"] is False
    assert executed.json()["state"] == ReleaseState.BLOCKED_APPROVAL
    assert executed.json()["reason_code"] == "APPROVAL_EVIDENCE_CHANGED"


def test_release_risk_breach_freezes_and_approval_invalidation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)

    def fake_execute(*, service, run, payload, approval_hash="sha256:unapproved"):
        _ = service, payload
        return ExecutionResponse(
            run_id=run.run_id,
            ok=True,
            state="placed",
            evidence={"bitget_order_id": "demo-order-freeze", "client_oid": "rl-freeze", "receipt_hash": run.receipt_hash},
        )

    monkeypatch.setattr(service_app, "_execute_bitget_demo_order", fake_execute)
    run = _seed_service_run(client, tmp_path, run_id="run_release_policy")
    release = _create_release_for_run(client, run, release_id="rel_policy", version_id="strategy-policy")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200

    risk_breach = client.post(
        f"/v1/release-candidates/{release['release_id']}/risk-policy",
        headers=_headers(),
        json=_risk_policy_payload(allowed_symbols=["ETHUSDT"]),
    )
    assert risk_breach.status_code == 200
    assert risk_breach.json()["ok"] is False
    assert risk_breach.json()["state"] == "blocked_risk_policy"

    release = _create_release_for_run(client, run, release_id="rel_freeze", version_id="strategy-freeze")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200

    monkeypatch.setenv("REDLINE_RELEASE_FREEZE", "1")
    frozen_approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    )
    assert frozen_approval.json()["reason_code"] == "REDLINE_RELEASE_FREEZE"
    monkeypatch.setenv("REDLINE_RELEASE_FREEZE", "0")
    approval = client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    )
    assert approval.json()["ok"] is True

    changed_simulation = _simulation_payload()
    changed_simulation["trade_count"] = 13
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=changed_simulation).status_code == 200
    execute_without_reapproval = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert execute_without_reapproval.json()["reason_code"] == "RELEASE_NOT_APPROVED"

    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    ).json()["ok"] is True
    monkeypatch.setenv("REDLINE_EXECUTION_FREEZE", "1")
    frozen_execute = client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={})
    assert frozen_execute.json()["reason_code"] == "REDLINE_EXECUTION_FREEZE"
    safety = client.get("/v1/release-safety", headers=_headers())
    assert safety.status_code == 200
    assert safety.json()["execution_freeze"] is True


def test_release_evidence_and_audit_tamper_are_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)

    def fake_execute(*, service, run, payload, approval_hash="sha256:unapproved"):
        _ = service, payload
        order = BitgetOrderPlacement(
            client_oid="rl-tamper",
            bitget_order_id="demo-order-tamper",
            response_hash="sha256:" + "5" * 64,
            placed_at="2026-06-24T00:00:00Z",
            status_code=200,
        )
        evidence = write_execution_evidence(
            run_id=run.run_id,
            out_dir=Path(run.out_dir),
            receipt_hash=run.receipt_hash or "sha256:" + "0" * 64,
            verdict=Status.PASS,
            intent=default_execution_intent(),
            order=order,
            issuance_ledger_entry_hash="sha256:genesis",
            issuance_checkpoint_hash="sha256:genesis",
            approval_hash=approval_hash,
        )
        return ExecutionResponse(
            run_id=run.run_id,
            ok=True,
            state="placed",
            evidence=evidence.model_dump(mode="json"),
        )

    monkeypatch.setattr(service_app, "_execute_bitget_demo_order", fake_execute)
    run = _seed_service_run(client, tmp_path, run_id="run_release_tamper")
    release = _create_release_for_run(client, run, release_id="rel_tamper", version_id="strategy-tamper")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/redline-run", headers=_headers(), json={"run_id": run["run_id"]}).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/simulation-evidence", headers=_headers(), json=_simulation_payload()).status_code == 200
    assert client.post(f"/v1/release-candidates/{release['release_id']}/risk-policy", headers=_headers(), json=_risk_policy_payload()).status_code == 200
    assert client.post(
        f"/v1/release-candidates/{release['release_id']}/approve",
        headers=_headers(),
        json={"reviewer_id": "release-reviewer"},
    ).json()["ok"] is True
    assert client.post(f"/v1/release-candidates/{release['release_id']}/execute-demo", headers=_headers(), json={}).json()["ok"] is True
    assert client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers()).status_code == 200

    service_root = tmp_path / "service"
    bundle_path = service_root / "releases" / release["release_id"] / "release-evidence-bundle.json"
    bundle_path.write_text(bundle_path.read_text(encoding="utf-8").replace("demo-order-tamper", "demo-order-forged"), encoding="utf-8")
    tampered_bundle = client.get(f"/v1/release-candidates/{release['release_id']}/evidence", headers=_headers())
    assert tampered_bundle.status_code == 400
    assert tampered_bundle.json()["error_code"] == "RECEIPT_MISMATCH"

    ledger_path = service_root / "releases" / release["release_id"] / "release-audit-ledger.jsonl"
    ledger_path.write_text(ledger_path.read_text(encoding="utf-8") + '{"bad": true}\n', encoding="utf-8")
    tampered_ledger = client.get(f"/v1/release-candidates/{release['release_id']}/audit-ledger", headers=_headers())
    assert tampered_ledger.status_code == 400
    assert tampered_ledger.json()["error_code"] == "RECEIPT_MISMATCH"


def test_service_openapi_exposes_frontend_contract(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/v1/runs" in paths
    assert "/v1/packages/upload" in paths
    assert "/v1/runs/{run_id}/artifacts/{artifact_id}" in paths
    assert "/v1/runs/{run_id}/execute" in paths
    assert "/v1/strategy-versions" in paths
    assert "/v1/release-candidates" in paths
    assert "/v1/release-candidates/{release_id}/execute-demo" in paths
    assert "/v1/release-safety" in paths


@pytest.mark.skipif(not os.environ.get("REDLINE_TEST_POSTGRES_URL"), reason="REDLINE_TEST_POSTGRES_URL is not configured")
def test_postgres_store_claims_and_persists_runs(tmp_path: Path) -> None:
    database_url = os.environ["REDLINE_TEST_POSTGRES_URL"]
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS release_audit_entries")
            cur.execute("DROP TABLE IF EXISTS release_candidates")
            cur.execute("DROP TABLE IF EXISTS strategy_versions")
            cur.execute("DROP TABLE IF EXISTS runs")
            cur.execute("DROP TABLE IF EXISTS packages")
    store = PostgresServiceStore(database_url)
    package = PackageResponse(
        package_id="pkg_postgres",
        path=str(PACKAGE),
        identity_hash="sha256:" + "1" * 64,
        identity_lock_hash="sha256:" + "2" * 64,
        files=["baseline/strategy.py"],
        created_at="2026-06-14T00:00:00Z",
    )
    store.upsert_package(package)
    request = RunCreateRequest(package_id="pkg_postgres", candidate="candidate_good", suite_path=str(SUITE), spec_path=str(SPEC))
    store.create_run(run_id="run_postgres", request_id="req_pg", request=request, package_path=PACKAGE, out_dir=tmp_path / "run")

    work = store.claim_next_run(worker_id="worker_pg")
    assert work is not None
    assert work.request.package_id == "pkg_postgres"
    assert store.count_packages() == 1
    assert store.count_runs(states={RunState.RUNNING}) == 1

    store.mark_error(run_id="run_postgres", error_code="DATA_MISSING", message="failed closed")
    run = store.get_run("run_postgres")

    assert run is not None
    assert run.state == RunState.ERROR
    assert run.error_message == "failed closed"

    strategy_version = StrategyVersionResponse(
        version_id="strategy-postgres-v1",
        strategy_id="strategy-postgres",
        package_id="pkg_postgres",
        package_path=str(PACKAGE),
        package_hash=package.identity_hash,
        identity_lock_hash=package.identity_lock_hash,
        source_kind="fixture",
        metadata={"name": "Postgres strategy"},
        created_by="author",
        created_at="2026-06-23T00:00:00Z",
        updated_at="2026-06-23T00:00:00Z",
    )
    created_version = store.create_strategy_version(strategy_version)
    assert created_version.version_id == "strategy-postgres-v1"
    assert store.create_strategy_version(strategy_version).package_hash == package.identity_hash
    with pytest.raises(ValueError, match="different package hash"):
        store.create_strategy_version(strategy_version.model_copy(update={"package_hash": "sha256:" + "9" * 64}))

    release = ReleaseCandidateResponse(
        release_id="rel_postgres",
        strategy_id="strategy-postgres",
        version_id="strategy-postgres-v1",
        state=ReleaseState.DRAFT,
        created_by="author",
        created_at="2026-06-23T00:00:00Z",
        updated_at="2026-06-23T00:00:00Z",
    )
    created_release = store.create_release_candidate(release)
    updated_release = store.update_release_candidate(created_release.model_copy(update={"state": ReleaseState.REDLINE_PASSED, "run_id": "run_postgres"}))
    assert updated_release.state == ReleaseState.REDLINE_PASSED
    assert store.get_release_candidate("rel_postgres").run_id == "run_postgres"
    audit_entry = {
        "schema_version": "redline.release.audit.v1",
        "release_id": "rel_postgres",
        "event_type": "release_candidate_created",
        "actor": "author",
        "created_at": "2026-06-23T00:00:00Z",
        "payload": {},
        "previous_entry_hash": "sha256:genesis",
        "entry_hash": "sha256:" + "1" * 64,
    }
    store.append_release_audit_entry(release_id="rel_postgres", entry=audit_entry)
    assert store.list_release_audit_entries(release_id="rel_postgres") == [audit_entry]


def test_risk_policy_mainnet_veto_not_bypassed_by_notional_reduce():
    """Independent-review HIGH fix: a release whose risk policy forbids mainnet must
    BLOCK a confirm_mainnet_order request even when that order also trips the notional
    cap. Before the fix the notional branch returned a size-reduced ``reduce`` decision
    and short-circuited the mainnet veto, letting a mainnet-forbidden release place a
    mainnet order in a mainnet-enabled deployment."""
    from redline.service.release import risk_policy_breach
    from redline.service.models import ExecutionRequest

    policy = {
        "mainnet_enabled": False,
        "max_order_notional_usdt": "20",
        "expected_order_notional_usdt": "40",
        "allowed_symbols": ["BTCUSDT"],
        "allowed_product_types": ["USDT-FUTURES"],
    }
    mainnet_attempt = ExecutionRequest(
        symbol="BTCUSDT", product_type="USDT-FUTURES", confirm_mainnet_order=True, size="1.0"
    )
    decision = risk_policy_breach(policy, mainnet_attempt)
    assert decision.decision == "block"
    assert "mainnet" in decision.reason.lower()

    # Control: the same oversized order WITHOUT mainnet confirmation still reduces size
    # (the notional-cap path is preserved; only the mainnet veto now takes precedence).
    demo_attempt = ExecutionRequest(
        symbol="BTCUSDT", product_type="USDT-FUTURES", confirm_mainnet_order=False, size="1.0"
    )
    demo_decision = risk_policy_breach(policy, demo_attempt)
    assert demo_decision.decision == "reduce"


def test_verify_chain_trusted_key_pin_rejects_foreign_signer(tmp_path: Path, monkeypatch) -> None:
    """Independent-review MED hardening: offline attestation verify is integrity-only by
    default (the embedded key self-signs), but with --trusted-public-key pinned it must
    reject any attestation not signed by that exact key — closing the self-signed-forgery
    gap in the zero-secret judge path."""
    monkeypatch.setenv("REDLINE_BITGET_DEMO_ACCESS_KEY", "demo-key")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_SECRET_KEY", "demo-secret-do-not-leak")
    monkeypatch.setenv("REDLINE_BITGET_DEMO_PASSPHRASE", "demo-passphrase")
    client = _client(tmp_path)
    calls: list[dict[str, object]] = []
    client.app.state.redline_service.execution_transport = _bitget_demo_transport(calls, order_id_factory=lambda _count: "demo-order-pin")
    _run, release = _create_release_ready_for_showcase_job(client, tmp_path, release_id="rel_pin", version_id="strategy-pin")
    assert client.post(f"/v1/release-candidates/{release['release_id']}/attest", headers=_headers(), json={}).json()["ok"] is True
    release_dir_path = tmp_path / "service" / "releases" / release["release_id"]
    attestation = json.loads((release_dir_path / "release-attestation.json").read_text(encoding="utf-8"))
    real_key = attestation["public_key"]
    for secret_name in (
        "REDLINE_BITGET_DEMO_ACCESS_KEY",
        "REDLINE_BITGET_DEMO_SECRET_KEY",
        "REDLINE_BITGET_DEMO_PASSPHRASE",
        "REDLINE_ATTESTATION_PRIVATE_KEY",
        "REDLINE_TRUST_PRIVATE_KEY",
    ):
        monkeypatch.delenv(secret_name, raising=False)

    # Pinned to the genuine signer -> passes and records the pin check.
    pinned_ok = CliRunner().invoke(cli_app, ["verify-chain", str(release_dir_path), "--trusted-public-key", real_key, "--json"])
    assert pinned_ok.exit_code == 0, pinned_ok.stdout
    ok_payload = json.loads(pinned_ok.stdout)
    assert ok_payload["ok"] is True
    assert any(item["name"] == "trusted-key-pin" and item["ok"] for item in ok_payload["checks"])

    # Pinned to a foreign key -> fails (this is where a self-signed forgery would land).
    foreign_key = "ed25519-public:" + "0" * 64
    pinned_bad = CliRunner().invoke(cli_app, ["verify-chain", str(release_dir_path), "--trusted-public-key", foreign_key, "--json"])
    assert pinned_bad.exit_code != 0
    bad_payload = json.loads(pinned_bad.stdout)
    assert bad_payload["ok"] is False
    assert not any(item["name"] == "trusted-key-pin" and item["ok"] for item in bad_payload["checks"])
