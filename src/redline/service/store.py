from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redline.io_safety import ensure_safe_output_dir, reject_unsafe_output_file
from redline.service.models import ArtifactManifest, PackageResponse, RunCreateRequest, RunResponse, RunState


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ServiceStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        ensure_safe_output_dir(db_path.parent)
        reject_unsafe_output_file(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS packages (
                    package_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    identity_hash TEXT NOT NULL,
                    identity_lock_hash TEXT NOT NULL,
                    files_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    package_id TEXT,
                    package_path TEXT NOT NULL,
                    baseline TEXT NOT NULL,
                    candidate TEXT NOT NULL,
                    suite_path TEXT NOT NULL,
                    spec_path TEXT NOT NULL,
                    baseline_receipt_path TEXT,
                    baseline_trust_policy_path TEXT,
                    baseline_version_id TEXT,
                    candidate_version_id TEXT,
                    out_dir TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    reason_code TEXT,
                    envelope_status TEXT,
                    package_hash TEXT,
                    receipt_hash TEXT,
                    report_hash TEXT,
                    artifact_manifest_json TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                )
                """
            )

    def upsert_package(self, package: PackageResponse) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO packages
                (package_id, path, identity_hash, identity_lock_hash, files_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    package.package_id,
                    package.path,
                    package.identity_hash,
                    package.identity_lock_hash,
                    json.dumps(package.files, sort_keys=True),
                    package.created_at,
                ),
            )

    def get_package(self, package_id: str) -> PackageResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM packages WHERE package_id = ?", (package_id,)).fetchone()
        if row is None:
            return None
        return PackageResponse(
            package_id=row["package_id"],
            path=row["path"],
            identity_hash=row["identity_hash"],
            identity_lock_hash=row["identity_lock_hash"],
            files=json.loads(row["files_json"]),
            created_at=row["created_at"],
        )

    def create_run(
        self,
        *,
        run_id: str,
        request_id: str,
        request: RunCreateRequest,
        package_path: Path,
        out_dir: Path,
    ) -> RunResponse:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, state, request_id, package_id, package_path, baseline, candidate,
                    suite_path, spec_path, baseline_receipt_path, baseline_trust_policy_path,
                    baseline_version_id, candidate_version_id, out_dir, request_json,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    RunState.QUEUED.value,
                    request_id,
                    request.package_id,
                    str(package_path),
                    request.baseline,
                    request.candidate,
                    request.suite_path,
                    request.spec_path,
                    request.baseline_receipt_path,
                    request.baseline_trust_policy_path,
                    request.baseline_version_id,
                    request.candidate_version_id,
                    str(out_dir),
                    request.model_dump_json(),
                    now,
                    now,
                ),
            )
        run = self.get_run(run_id)
        if run is None:
            raise RuntimeError("run insert failed")
        return run

    def mark_running(self, run_id: str) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE runs SET state = ?, started_at = ?, updated_at = ? WHERE run_id = ?",
                (RunState.RUNNING.value, now, now, run_id),
            )

    def mark_completed(
        self,
        *,
        run_id: str,
        state: RunState,
        reason_code: str,
        envelope_status: str,
        package_hash: str | None,
        receipt_hash: str | None,
        report_hash: str | None,
        artifact_manifest: ArtifactManifest,
    ) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET state = ?, reason_code = ?, envelope_status = ?, package_hash = ?,
                    receipt_hash = ?, report_hash = ?, artifact_manifest_json = ?,
                    completed_at = ?, updated_at = ?, error_code = NULL, error_message = NULL
                WHERE run_id = ?
                """,
                (
                    state.value,
                    reason_code,
                    envelope_status,
                    package_hash,
                    receipt_hash,
                    report_hash,
                    artifact_manifest.model_dump_json(),
                    now,
                    now,
                    run_id,
                ),
            )

    def mark_error(self, *, run_id: str, error_code: str, message: str) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET state = ?, error_code = ?, error_message = ?, completed_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (RunState.ERROR.value, error_code, message, now, now, run_id),
            )

    def get_run(self, run_id: str) -> RunResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return _row_to_run(row) if row is not None else None

    def list_runs(self, *, limit: int = 50) -> list[RunResponse]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_run(row) for row in rows]


def _row_to_run(row: sqlite3.Row) -> RunResponse:
    artifact_manifest = None
    if row["artifact_manifest_json"]:
        artifact_manifest = ArtifactManifest.model_validate(json.loads(row["artifact_manifest_json"]))
    return RunResponse(
        run_id=row["run_id"],
        state=RunState(row["state"]),
        request_id=row["request_id"],
        package_id=row["package_id"],
        package_path=row["package_path"],
        baseline=row["baseline"],
        candidate=row["candidate"],
        suite_path=row["suite_path"],
        spec_path=row["spec_path"],
        out_dir=row["out_dir"],
        reason_code=row["reason_code"],
        envelope_status=row["envelope_status"],
        package_hash=row["package_hash"],
        receipt_hash=row["receipt_hash"],
        report_hash=row["report_hash"],
        artifact_manifest=artifact_manifest,
        error_code=row["error_code"],
        error_message=row["error_message"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
    )


def model_to_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))
