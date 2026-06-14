from __future__ import annotations

import io
import json
import os
import sqlite3
import tarfile
import time
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from redline.service.cleanup import cleanup_expired_runs
from redline.service.app import create_app
from redline.service.config import ServiceConfig
from redline.service.storage import LocalArtifactStore, create_artifact_store, create_metadata_store
from redline.service.postgres_store import PostgresServiceStore
from redline.service.models import PackageResponse, RunCreateRequest, RunState
from redline.service.store import ServiceStore

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
SUITE = ROOT / "fixtures/suites/demo_suite.json"
SPEC = ROOT / "fixtures/specs/redline_spec.json"


def _client(tmp_path: Path, *, max_upload_bytes: int = 50 * 1024 * 1024) -> TestClient:
    app = create_app(ServiceConfig(root=tmp_path / "service", token="test-token", workers=2, max_upload_bytes=max_upload_bytes))
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"X-Redline-Token": "test-token"}


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


def test_service_config_rejects_production_default_token(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.delenv("REDLINE_SERVICE_TOKEN", raising=False)

    with pytest.raises(ValueError, match="production service requires"):
        ServiceConfig.from_env()


def test_service_config_rejects_wildcard_production_cors(monkeypatch) -> None:
    monkeypatch.setenv("REDLINE_SERVICE_ENV", "production")
    monkeypatch.setenv("REDLINE_SERVICE_TOKEN", "x" * 32)
    monkeypatch.setenv("REDLINE_SERVICE_CORS_ORIGINS", "*")

    with pytest.raises(ValueError, match="CORS origins"):
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
    receipt_path.write_text(receipt_path.read_text(encoding="utf-8").replace("redline.receipt.v3.2", "redline.receipt.v3.x"), encoding="utf-8")

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


def test_service_openapi_exposes_frontend_contract(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/v1/runs" in paths
    assert "/v1/packages/upload" in paths
    assert "/v1/runs/{run_id}/artifacts/{artifact_id}" in paths


@pytest.mark.skipif(not os.environ.get("REDLINE_TEST_POSTGRES_URL"), reason="REDLINE_TEST_POSTGRES_URL is not configured")
def test_postgres_store_claims_and_persists_runs(tmp_path: Path) -> None:
    database_url = os.environ["REDLINE_TEST_POSTGRES_URL"]
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
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
