from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from redline.canonical import CanonicalizationError, hash_obj
from redline.io_safety import ensure_safe_output_dir, reject_unsafe_output_file
from redline.models import ReasonCode
from redline.service.migrations import SERVICE_MIGRATIONS
from redline.service.models import (
    ArtifactManifest,
    PackageResponse,
    ReleaseCandidateResponse,
    ReleaseJobEventResponse,
    ReleaseJobResponse,
    ReleaseJobStatus,
    ReleaseJobType,
    ReleaseJobWorkItem,
    ReleaseState,
    ReleaseTier,
    RunCreateRequest,
    RunResponse,
    RunState,
    RunWorkItem,
    StrategyVersionResponse,
)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ServiceStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        ensure_safe_output_dir(db_path.parent)
        reject_unsafe_output_file(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_state_created ON runs (state, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_updated_at ON runs (updated_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS strategy_versions (
                    version_id TEXT PRIMARY KEY,
                    strategy_id TEXT NOT NULL,
                    package_id TEXT,
                    package_path TEXT,
                    package_hash TEXT NOT NULL,
                    identity_lock_hash TEXT,
                    source_kind TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_strategy_versions_strategy ON strategy_versions (strategy_id, created_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS release_candidates (
                    release_id TEXT PRIMARY KEY,
                    strategy_id TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    release_tier TEXT NOT NULL DEFAULT 'L0',
                    created_by TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    run_id TEXT,
                    redline_reason_code TEXT,
                    redline_receipt_hash TEXT,
                    redline_report_hash TEXT,
                    simulation_evidence_json TEXT,
                    simulation_evidence_hash TEXT,
                    risk_policy_json TEXT,
                    risk_policy_hash TEXT,
                    approval_json TEXT,
                    approval_nonce TEXT,
                    approval_expires_at TEXT,
                    approval_consumed_at TEXT,
                    execution_run_id TEXT,
                    execution_evidence_json TEXT,
                    evidence_manifest_json TEXT,
                    evidence_manifest_hash TEXT,
                    reject_reason TEXT,
                    killed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(version_id) REFERENCES strategy_versions(version_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_release_candidates_version ON release_candidates (version_id, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_release_candidates_state ON release_candidates (state, created_at)")
            self._ensure_columns(
                conn,
                "release_candidates",
                {
                    "release_tier": "TEXT NOT NULL DEFAULT 'L0'",
                    "approval_nonce": "TEXT",
                    "approval_expires_at": "TEXT",
                    "approval_consumed_at": "TEXT",
                },
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS release_audit_entries (
                    release_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    entry_json TEXT NOT NULL,
                    previous_entry_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (release_id, sequence)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (scope, key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS release_jobs (
                    job_id TEXT PRIMARY KEY,
                    release_id TEXT NOT NULL,
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    idempotency_key TEXT,
                    requested_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    result_json TEXT,
                    error_code TEXT,
                    error_message TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_release_jobs_release ON release_jobs (release_id, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_release_jobs_status ON release_jobs (status, created_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS release_job_events (
                    job_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    release_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_event_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    PRIMARY KEY (job_id, sequence)
                )
                """
            )
            for migration in SERVICE_MIGRATIONS:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (migration.version, migration.name, utc_now()),
                )

    def list_schema_migrations(self) -> list[dict[str, str]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version").fetchall()
        return [dict(row) for row in rows]

    def _ensure_columns(self, conn: sqlite3.Connection, table: str, columns: Mapping[str, str]) -> None:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for column, definition in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def get_idempotency_record(self, *, scope: str, key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM idempotency_keys WHERE scope = ? AND key = ?", (scope, key)).fetchone()
        return dict(row) if row is not None else None

    def put_idempotency_record(self, *, scope: str, key: str, request_hash: str, response: Mapping[str, Any], status_code: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO idempotency_keys
                (scope, key, request_hash, response_json, status_code, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scope, key, request_hash, model_to_json(response), status_code, utc_now()),
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

    def create_strategy_version(self, version: StrategyVersionResponse) -> StrategyVersionResponse:
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM strategy_versions WHERE version_id = ?", (version.version_id,)).fetchone()
            if existing is not None:
                current = _row_to_strategy_version(existing)
                if current.package_hash != version.package_hash:
                    raise ValueError("strategy version already exists with a different package hash")
                return current
            conn.execute(
                """
                INSERT INTO strategy_versions (
                    version_id, strategy_id, package_id, package_path, package_hash,
                    identity_lock_hash, source_kind, metadata_json, created_by, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.version_id,
                    version.strategy_id,
                    version.package_id,
                    version.package_path,
                    version.package_hash,
                    version.identity_lock_hash,
                    version.source_kind.value,
                    model_to_json(version.metadata),
                    version.created_by,
                    version.created_at or now,
                    version.updated_at or now,
                ),
            )
        created = self.get_strategy_version(version.version_id)
        if created is None:
            raise RuntimeError("strategy version insert failed")
        return created

    def get_strategy_version(self, version_id: str) -> StrategyVersionResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM strategy_versions WHERE version_id = ?", (version_id,)).fetchone()
        return _row_to_strategy_version(row) if row is not None else None

    def list_strategy_versions(self, *, limit: int = 50) -> list[StrategyVersionResponse]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM strategy_versions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_strategy_version(row) for row in rows]

    def create_release_candidate(self, release: ReleaseCandidateResponse) -> ReleaseCandidateResponse:
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM release_candidates WHERE release_id = ?", (release.release_id,)).fetchone()
            if existing is not None:
                current = _row_to_release_candidate(existing)
                if current.version_id != release.version_id or current.strategy_id != release.strategy_id:
                    raise ValueError("release candidate already exists with a different strategy version")
                return current
            conn.execute(
                """
                INSERT INTO release_candidates (
                    release_id, strategy_id, version_id, state, release_tier, created_by, metadata_json,
                    run_id, redline_reason_code, redline_receipt_hash, redline_report_hash,
                    simulation_evidence_json, simulation_evidence_hash, risk_policy_json,
                    risk_policy_hash, approval_json, approval_nonce, approval_expires_at,
                    approval_consumed_at, execution_run_id, execution_evidence_json,
                    evidence_manifest_json, evidence_manifest_hash, reject_reason, killed_at,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _release_candidate_values(release, created_at=release.created_at or now, updated_at=release.updated_at or now),
            )
        created = self.get_release_candidate(release.release_id)
        if created is None:
            raise RuntimeError("release candidate insert failed")
        return created

    def update_release_candidate(self, release: ReleaseCandidateResponse) -> ReleaseCandidateResponse:
        updated = release.model_copy(update={"updated_at": utc_now()})
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE release_candidates
                SET strategy_id = ?, version_id = ?, state = ?, release_tier = ?, created_by = ?, metadata_json = ?,
                    run_id = ?, redline_reason_code = ?, redline_receipt_hash = ?, redline_report_hash = ?,
                    simulation_evidence_json = ?, simulation_evidence_hash = ?, risk_policy_json = ?,
                    risk_policy_hash = ?, approval_json = ?, approval_nonce = ?, approval_expires_at = ?,
                    approval_consumed_at = ?, execution_run_id = ?, execution_evidence_json = ?,
                    evidence_manifest_json = ?, evidence_manifest_hash = ?, reject_reason = ?, killed_at = ?,
                    created_at = ?, updated_at = ?
                WHERE release_id = ?
                """,
                (*_release_candidate_values(updated, created_at=updated.created_at, updated_at=updated.updated_at)[1:], updated.release_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"release candidate not found: {updated.release_id}")
        saved = self.get_release_candidate(updated.release_id)
        if saved is None:
            raise RuntimeError("release candidate update failed")
        return saved

    def consume_release_approval(self, *, release_id: str, nonce: str, consumed_at: str) -> ReleaseCandidateResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM release_candidates WHERE release_id = ?", (release_id,)).fetchone()
            if row is None:
                return None
            release = _row_to_release_candidate(row)
            approval = release.approval
            if not isinstance(approval, dict) or approval.get("nonce") != nonce or approval.get("consumed_at") is not None:
                return None
            consumed_approval = {**approval, "consumed_at": consumed_at}
            cursor = conn.execute(
                """
                UPDATE release_candidates
                SET approval_json = ?, approval_consumed_at = ?, updated_at = ?
                WHERE release_id = ? AND approval_nonce = ? AND approval_consumed_at IS NULL
                """,
                (model_to_json(consumed_approval), consumed_at, consumed_at, release_id, nonce),
            )
            if cursor.rowcount != 1:
                return None
        return self.get_release_candidate(release_id)

    def consume_release_showcase_approval(self, *, release_id: str, nonce: str, consumed_at: str) -> ReleaseCandidateResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM release_candidates WHERE release_id = ?", (release_id,)).fetchone()
            if row is None:
                return None
            release = _row_to_release_candidate(row)
            metadata = dict(release.metadata)
            approval = metadata.get("showcase_approval")
            if not isinstance(approval, dict) or approval.get("nonce") != nonce or approval.get("consumed_at") is not None:
                return None
            metadata["showcase_approval"] = {**approval, "consumed_at": consumed_at}
            cursor = conn.execute(
                """
                UPDATE release_candidates
                SET metadata_json = ?, updated_at = ?
                WHERE release_id = ? AND metadata_json = ?
                """,
                (model_to_json(metadata), consumed_at, release_id, row["metadata_json"]),
            )
            if cursor.rowcount != 1:
                return None
        return self.get_release_candidate(release_id)

    def get_release_candidate(self, release_id: str) -> ReleaseCandidateResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM release_candidates WHERE release_id = ?", (release_id,)).fetchone()
        return _row_to_release_candidate(row) if row is not None else None

    def list_release_candidates(self, *, limit: int = 50) -> list[ReleaseCandidateResponse]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM release_candidates ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_release_candidate(row) for row in rows]

    def append_release_audit_entry(self, *, release_id: str, entry: dict[str, Any]) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence), -1) + 1 AS next_sequence FROM release_audit_entries WHERE release_id = ?",
                (release_id,),
            ).fetchone()
            sequence = int(row["next_sequence"])
            conn.execute(
                """
                INSERT INTO release_audit_entries (
                    release_id, sequence, event_type, entry_json, previous_entry_hash, entry_hash, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release_id,
                    sequence,
                    str(entry["event_type"]),
                    model_to_json(entry),
                    str(entry["previous_entry_hash"]),
                    str(entry["entry_hash"]),
                    str(entry["created_at"]),
                ),
            )

    def list_release_audit_entries(self, *, release_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT entry_json FROM release_audit_entries WHERE release_id = ? ORDER BY sequence ASC",
                (release_id,),
            ).fetchall()
        return [json.loads(row["entry_json"]) for row in rows]

    def create_release_job(
        self,
        *,
        job_id: str,
        release_id: str,
        job_type: ReleaseJobType,
        request_hash: str,
        request: dict[str, Any],
        idempotency_key: str | None,
        requested_by: str,
    ) -> ReleaseJobResponse:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO release_jobs (
                    job_id, release_id, job_type, status, request_hash, request_json,
                    idempotency_key, requested_by, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    release_id,
                    job_type.value,
                    ReleaseJobStatus.QUEUED.value,
                    request_hash,
                    model_to_json(request),
                    idempotency_key,
                    requested_by,
                    now,
                ),
            )
        job = self.get_release_job(release_id=release_id, job_id=job_id)
        if job is None:
            raise RuntimeError("release job insert failed")
        return job

    def get_release_job(self, *, release_id: str, job_id: str) -> ReleaseJobResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM release_jobs WHERE release_id = ? AND job_id = ?", (release_id, job_id)).fetchone()
        return _row_to_release_job(row) if row is not None else None

    def list_release_jobs(self, *, release_id: str, limit: int = 50) -> list[ReleaseJobResponse]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM release_jobs WHERE release_id = ? ORDER BY created_at DESC LIMIT ?",
                (release_id, limit),
            ).fetchall()
        return [_row_to_release_job(row) for row in rows]

    def claim_next_release_job(self, *, worker_id: str) -> ReleaseJobWorkItem | None:
        _ = worker_id
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT * FROM release_jobs
                WHERE status = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (ReleaseJobStatus.QUEUED.value,),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                """
                UPDATE release_jobs
                SET status = ?, started_at = COALESCE(started_at, ?)
                WHERE job_id = ? AND status = ?
                """,
                (ReleaseJobStatus.RUNNING.value, now, row["job_id"], ReleaseJobStatus.QUEUED.value),
            )
            conn.commit()
        return _row_to_release_job_work_item(row)

    def recover_interrupted_release_jobs(self) -> list[ReleaseJobResponse]:
        now = utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM release_jobs WHERE status = ? ORDER BY created_at ASC",
                (ReleaseJobStatus.RUNNING.value,),
            ).fetchall()
            job_ids = [str(row["job_id"]) for row in rows]
            for job_id in job_ids:
                conn.execute(
                    """
                    UPDATE release_jobs
                    SET status = ?, finished_at = COALESCE(finished_at, ?),
                        error_code = ?, error_message = ?
                    WHERE job_id = ? AND status = ?
                    """,
                    (
                        ReleaseJobStatus.FAILED.value,
                        now,
                        "JOB_RECOVERY_REQUIRED",
                        "release job was interrupted before completion",
                        job_id,
                        ReleaseJobStatus.RUNNING.value,
                    ),
                )
            recovered = [
                conn.execute("SELECT * FROM release_jobs WHERE job_id = ?", (job_id,)).fetchone()
                for job_id in job_ids
            ]
        return [_row_to_release_job(row) for row in recovered if row is not None]

    def cancel_release_job(self, *, release_id: str, job_id: str) -> ReleaseJobResponse | None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE release_jobs
                SET status = ?, finished_at = COALESCE(finished_at, ?),
                    error_code = ?, error_message = ?
                WHERE release_id = ? AND job_id = ? AND status = ?
                """,
                (
                    ReleaseJobStatus.CANCELLED.value,
                    now,
                    "JOB_CANCELLED",
                    "release job cancelled before execution",
                    release_id,
                    job_id,
                    ReleaseJobStatus.QUEUED.value,
                ),
            )
            row = conn.execute("SELECT * FROM release_jobs WHERE release_id = ? AND job_id = ?", (release_id, job_id)).fetchone()
        return _row_to_release_job(row) if row is not None else None

    def mark_release_job_status(
        self,
        *,
        job_id: str,
        status: ReleaseJobStatus,
        result: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        now = utc_now()
        started_at_expr = "COALESCE(started_at, ?)" if status == ReleaseJobStatus.RUNNING else "started_at"
        finished_at = now if status in {ReleaseJobStatus.SUCCEEDED, ReleaseJobStatus.FAILED, ReleaseJobStatus.CANCELLED} else None
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE release_jobs
                SET status = ?, started_at = {started_at_expr}, finished_at = COALESCE(?, finished_at),
                    result_json = ?, error_code = ?, error_message = ?
                WHERE job_id = ?
                """,
                (
                    status.value,
                    now,
                    finished_at,
                    model_to_json(result) if result is not None else None,
                    error_code,
                    error_message,
                    job_id,
                )
                if status == ReleaseJobStatus.RUNNING
                else (
                    status.value,
                    finished_at,
                    model_to_json(result) if result is not None else None,
                    error_code,
                    error_message,
                    job_id,
                ),
            )

    def append_release_job_event(self, *, release_id: str, job_id: str, event_type: str, payload: dict[str, Any] | None = None) -> ReleaseJobEventResponse:
        created_at = utc_now()
        payload = payload or {}
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence, event_hash FROM release_job_events WHERE job_id = ? ORDER BY sequence DESC LIMIT 1",
                (job_id,),
            ).fetchone()
            sequence = int(row["sequence"]) + 1 if row is not None else 0
            previous_event_hash = str(row["event_hash"]) if row is not None else "sha256:genesis"
            event_id = f"evt_{hash_obj({'job_id': job_id, 'sequence': sequence, 'created_at': created_at}).removeprefix('sha256:')[:24]}"
            entry = {
                "event_id": event_id,
                "job_id": job_id,
                "release_id": release_id,
                "sequence": sequence,
                "event_type": event_type,
                "payload": payload,
                "created_at": created_at,
                "previous_event_hash": previous_event_hash,
            }
            event_hash = hash_obj(entry)
            conn.execute(
                """
                INSERT INTO release_job_events (
                    job_id, sequence, event_id, release_id, event_type, payload_json,
                    created_at, previous_event_hash, event_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (job_id, sequence, event_id, release_id, event_type, model_to_json(payload), created_at, previous_event_hash, event_hash),
            )
            conn.commit()
        return ReleaseJobEventResponse(**entry, event_hash=event_hash)

    def list_release_job_events(self, *, release_id: str, job_id: str) -> list[ReleaseJobEventResponse]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM release_job_events WHERE release_id = ? AND job_id = ? ORDER BY sequence ASC",
                (release_id, job_id),
            ).fetchall()
        events = [_row_to_release_job_event(row) for row in rows]
        _validate_release_job_event_chain(events)
        return events

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

    def update_artifact_manifest(self, *, run_id: str, artifact_manifest: ArtifactManifest) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE runs SET artifact_manifest_json = ?, updated_at = ? WHERE run_id = ?",
                (artifact_manifest.model_dump_json(), now, run_id),
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

    def claim_next_run(self, *, worker_id: str) -> RunWorkItem | None:
        _ = worker_id
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM runs WHERE state = ? ORDER BY created_at ASC LIMIT 1",
                (RunState.QUEUED.value,),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                """
                UPDATE runs
                SET state = ?, started_at = COALESCE(started_at, ?), updated_at = ?
                WHERE run_id = ?
                """,
                (RunState.RUNNING.value, now, now, row["run_id"]),
            )
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (row["run_id"],)).fetchone()
            conn.commit()
        if row is None:
            return None
        return _row_to_work_item(row)

    def requeue_interrupted_runs(self) -> int:
        now = utc_now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs
                SET state = ?, updated_at = ?
                WHERE state = ?
                """,
                (RunState.QUEUED.value, now, RunState.RUNNING.value),
            )
            return cursor.rowcount

    def get_run(self, run_id: str) -> RunResponse | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return _row_to_run(row) if row is not None else None

    def list_runs(self, *, limit: int = 50) -> list[RunResponse]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_run(row) for row in rows]

    def count_packages(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM packages").fetchone()
        return int(row["count"])

    def count_runs(self, *, states: set[RunState] | None = None) -> int:
        with self._connect() as conn:
            if states is None:
                row = conn.execute("SELECT COUNT(*) AS count FROM runs").fetchone()
            else:
                values = [state.value for state in sorted(states, key=lambda item: item.value)]
                if not values:
                    return 0
                placeholders = ",".join("?" for _ in values)
                row = conn.execute(f"SELECT COUNT(*) AS count FROM runs WHERE state IN ({placeholders})", values).fetchone()
        return int(row["count"])

    def prune_runs_before(self, cutoff_iso: str) -> list[Path]:
        terminal = [RunState.PASS.value, RunState.FAIL.value, RunState.AMBER.value, RunState.ERROR.value]
        placeholders = ",".join("?" for _ in terminal)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT run_id, out_dir FROM runs WHERE state IN ({placeholders}) AND updated_at < ?",
                (*terminal, cutoff_iso),
            ).fetchall()
            run_ids = [row["run_id"] for row in rows]
            if run_ids:
                id_placeholders = ",".join("?" for _ in run_ids)
                conn.execute(f"DELETE FROM runs WHERE run_id IN ({id_placeholders})", run_ids)
        return [Path(row["out_dir"]) for row in rows]


def _row_to_run(row: Mapping[str, Any]) -> RunResponse:
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
        baseline_receipt_path=row["baseline_receipt_path"],
        baseline_trust_policy_path=row["baseline_trust_policy_path"],
        baseline_version_id=row["baseline_version_id"],
        candidate_version_id=row["candidate_version_id"],
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


def _row_to_strategy_version(row: Mapping[str, Any]) -> StrategyVersionResponse:
    return StrategyVersionResponse(
        version_id=row["version_id"],
        strategy_id=row["strategy_id"],
        package_id=row["package_id"],
        package_path=row["package_path"],
        package_hash=row["package_hash"],
        identity_lock_hash=row["identity_lock_hash"],
        source_kind=row["source_kind"],
        metadata=json.loads(row["metadata_json"]),
        created_by=row["created_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_release_candidate(row: Mapping[str, Any]) -> ReleaseCandidateResponse:
    return ReleaseCandidateResponse(
        release_id=row["release_id"],
        strategy_id=row["strategy_id"],
        version_id=row["version_id"],
        state=ReleaseState(row["state"]),
        release_tier=ReleaseTier(row["release_tier"] or ReleaseTier.L0.value),
        created_by=row["created_by"],
        metadata=json.loads(row["metadata_json"]),
        run_id=row["run_id"],
        redline_reason_code=row["redline_reason_code"],
        redline_receipt_hash=row["redline_receipt_hash"],
        redline_report_hash=row["redline_report_hash"],
        simulation_evidence=_json_or_none(row["simulation_evidence_json"]),
        simulation_evidence_hash=row["simulation_evidence_hash"],
        risk_policy=_json_or_none(row["risk_policy_json"]),
        risk_policy_hash=row["risk_policy_hash"],
        approval=_json_or_none(row["approval_json"]),
        execution_run_id=row["execution_run_id"],
        execution_evidence=_json_or_none(row["execution_evidence_json"]),
        evidence_manifest=_json_or_none(row["evidence_manifest_json"]),
        evidence_manifest_hash=row["evidence_manifest_hash"],
        reject_reason=row["reject_reason"],
        killed_at=row["killed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_release_job(row: Mapping[str, Any]) -> ReleaseJobResponse:
    return ReleaseJobResponse(
        job_id=row["job_id"],
        release_id=row["release_id"],
        job_type=ReleaseJobType(row["job_type"]),
        status=ReleaseJobStatus(row["status"]),
        requested_by=row["requested_by"],
        request_hash=row["request_hash"],
        idempotency_key=row["idempotency_key"],
        events_url=f"/v1/release-candidates/{row['release_id']}/jobs/{row['job_id']}/events",
        result=_json_or_none(row["result_json"]),
        error_code=row["error_code"],
        error_message=row["error_message"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
    )


def _row_to_release_job_work_item(row: Mapping[str, Any]) -> ReleaseJobWorkItem:
    return ReleaseJobWorkItem(
        job_id=row["job_id"],
        release_id=row["release_id"],
        job_type=ReleaseJobType(row["job_type"]),
        request=json.loads(row["request_json"]),
        requested_by=row["requested_by"],
    )


def _row_to_release_job_event(row: Mapping[str, Any]) -> ReleaseJobEventResponse:
    return ReleaseJobEventResponse(
        event_id=row["event_id"],
        job_id=row["job_id"],
        release_id=row["release_id"],
        sequence=int(row["sequence"]),
        event_type=row["event_type"],
        payload=json.loads(row["payload_json"]),
        created_at=row["created_at"],
        previous_event_hash=row["previous_event_hash"],
        event_hash=row["event_hash"],
    )


def _validate_release_job_event_chain(events: list[ReleaseJobEventResponse]) -> None:
    previous_hash = "sha256:genesis"
    for expected_sequence, event in enumerate(events):
        if event.sequence != expected_sequence or event.previous_event_hash != previous_hash:
            raise CanonicalizationError("release job event hash chain mismatch", ReasonCode.RECEIPT_MISMATCH)
        entry = {
            "event_id": event.event_id,
            "job_id": event.job_id,
            "release_id": event.release_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "payload": event.payload,
            "created_at": event.created_at,
            "previous_event_hash": event.previous_event_hash,
        }
        expected_hash = hash_obj(entry)
        if event.event_hash != expected_hash:
            raise CanonicalizationError("release job event entry hash mismatch", ReasonCode.RECEIPT_MISMATCH)
        previous_hash = event.event_hash


def _release_candidate_values(release: ReleaseCandidateResponse, *, created_at: str, updated_at: str) -> tuple[Any, ...]:
    approval_nonce, approval_expires_at, approval_consumed_at = _approval_lifecycle_values(release.approval)
    return (
        release.release_id,
        release.strategy_id,
        release.version_id,
        release.state.value,
        release.release_tier.value,
        release.created_by,
        model_to_json(release.metadata),
        release.run_id,
        release.redline_reason_code,
        release.redline_receipt_hash,
        release.redline_report_hash,
        model_to_json(release.simulation_evidence) if release.simulation_evidence is not None else None,
        release.simulation_evidence_hash,
        model_to_json(release.risk_policy) if release.risk_policy is not None else None,
        release.risk_policy_hash,
        model_to_json(release.approval) if release.approval is not None else None,
        approval_nonce,
        approval_expires_at,
        approval_consumed_at,
        release.execution_run_id,
        model_to_json(release.execution_evidence) if release.execution_evidence is not None else None,
        model_to_json(release.evidence_manifest) if release.evidence_manifest is not None else None,
        release.evidence_manifest_hash,
        release.reject_reason,
        release.killed_at,
        created_at,
        updated_at,
    )


def _approval_lifecycle_values(approval: Mapping[str, Any] | None) -> tuple[str | None, str | None, str | None]:
    if approval is None:
        return None, None, None
    return (
        str(approval.get("nonce")) if approval.get("nonce") is not None else None,
        str(approval.get("expires_at")) if approval.get("expires_at") is not None else None,
        str(approval.get("consumed_at")) if approval.get("consumed_at") is not None else None,
    )


def _row_to_work_item(row: Mapping[str, Any]) -> RunWorkItem:
    return RunWorkItem(
        run_id=row["run_id"],
        request_id=row["request_id"],
        request=RunCreateRequest.model_validate(json.loads(row["request_json"])),
        package_path=Path(row["package_path"]),
        out_dir=Path(row["out_dir"]),
    )


def model_to_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _json_or_none(raw: str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    return json.loads(raw)
