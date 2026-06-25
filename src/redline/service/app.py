from __future__ import annotations

import logging
import csv
import io
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated

import uvicorn
from fastapi import APIRouter, Body, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from redline.attestation import (
    RELEASE_ATTESTATION_NAME,
    attest_release_bundle,
    load_release_attestation,
    render_attestation_status_html,
    verify_release_attestation,
    write_release_attestation,
)
from redline.canonical import CanonicalizationError, hash_file, hash_obj
from redline.io_safety import ensure_safe_output_dir
from redline.judge_console import render_judge_console_html, render_judge_release_html
from redline.models import ExecutionEvidence, ExecutionIntent, ReasonCode
from redline.models import Status as RedlineStatus
from redline.models import VerificationLevel, VerificationStatus
from redline.service.auth import (
    SESSION_COOKIE_NAME,
    AuthPrincipal,
    EXECUTE_DEMO,
    READ_ONLY,
    RELEASE_WRITE,
    dev_principal,
    make_session_cookie,
    principal_from_auth_users,
    principal_from_session_cookie,
)
from redline.service.artifacts import extract_package_archive, save_upload_stream
from redline.service.artifacts import build_artifact_manifest
from redline.service.config import ServiceConfig
from redline.service.models import (
    ArtifactInfo,
    ApprovalRequest,
    ErrorEnvelope,
    ExecutionRequest,
    ExecutionResponse,
    HealthResponse,
    PackageImportRequest,
    PackageResponse,
    RedlineRunBindRequest,
    RejectRequest,
    ReleaseActionResponse,
    ReleaseCandidateCreateRequest,
    ReleaseCandidateListResponse,
    ReleaseCandidateResponse,
    ReleaseJobEventListResponse,
    ReleaseJobListResponse,
    ReleaseJobResponse,
    ReleaseJobStatus,
    ReleaseJobType,
    ReleaseJobWorkItem,
    ReleaseSafetyResponse,
    ReleaseState,
    RiskPolicyRequest,
    RunCreateRequest,
    RunListResponse,
    RunResponse,
    RunState,
    SimulationEvidenceRequest,
    SimulationEvidenceSource,
    SponsorRequest,
    SponsorResponse,
    StrategyVersionCreateRequest,
    StrategyVersionListResponse,
    StrategyVersionResponse,
)
from redline.service.release import (
    AUDIT_LEDGER_NAME,
    BUNDLE_NAME,
    MANIFEST_NAME,
    RISK_POLICY_NAME,
    SIMULATION_NAME,
    append_release_audit_event,
    approval_record_hash,
    compute_release_tier,
    evidence_fingerprint,
    generate_release_evidence_bundle,
    load_release_audit_ledger,
    policy_hash,
    release_dir,
    risk_policy_breach,
    RiskPolicyDecision,
    simulation_evidence_hash,
    verify_release_evidence_bundle,
    verify_release_file,
    write_release_json,
)
from redline.service.storage import ArtifactStore, RunMetadataStore, create_artifact_store, create_metadata_store
from redline.service.store import utc_now
from redline.service.transitions import ReleaseTransitionError, ReleaseTransitionMissingEvidenceError, is_terminal_release_state, transition_release
from redline.service.worker import execute_run
from redline.sponsor.bitget import BitgetCredentials
from redline.sponsor.bitget_execution import (
    DEFAULT_BASE_URL,
    DEFAULT_DEMO_SYMBOL,
    DEFAULT_PRODUCT_TYPE,
    BitgetDemoExecutionAdapter,
    BitgetExchangePreflightEvidence,
    ExecutionBlocked,
    BitgetOrderStatusEvidence,
    UNAPPROVED_APPROVAL_HASH,
    default_execution_intent,
    execution_ledger_has_order,
    load_order_status_evidence,
    load_execution_evidence,
    load_execution_ledger,
    make_client_oid,
    make_showcase_client_oid,
    write_execution_evidence_artifacts,
    write_exchange_preflight_evidence,
    write_order_status_evidence,
)
from redline.surfaces import execute_sponsor_readback, import_package, publish_preflight
from redline.verifier import verify


LOGGER = logging.getLogger("redline.service")
GITHUB_STATE_COOKIE_NAME = "redline_github_oauth_state"
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
SHOWCASE_ORDERS_DIR = "demo-showcase-orders"
SHOWCASE_LEDGER_NAME = "demo-showcase-execution-ledger.jsonl"
SHOWCASE_APPROVAL_METADATA_KEY = "showcase_approval"
APPROVAL_ROLES = frozenset({"reviewer", "release_manager"})


@dataclass(frozen=True)
class VerifiedDemoExecution:
    intent: ExecutionIntent
    receipt_hash: str
    chain_status: str
    strength_summary: str


class RedlineService:
    def __init__(self, config: ServiceConfig) -> None:
        self.config = config
        _configure_logging(config)
        ensure_safe_output_dir(config.root)
        self.artifacts: ArtifactStore = create_artifact_store(config)
        ensure_safe_output_dir(self.artifacts.packages_dir)
        ensure_safe_output_dir(self.artifacts.runs_dir)
        self.store: RunMetadataStore = create_metadata_store(config)
        requeued = self.store.requeue_interrupted_runs()
        self.executor = ThreadPoolExecutor(max_workers=config.workers, thread_name_prefix="redline-run")
        self.execution_lock = threading.Lock()
        self.execution_transport = None
        self.closing = False
        self.rate_limiter = SlidingWindowRateLimiter(limit=config.request_rate_limit_per_minute, window_seconds=60)
        LOGGER.info(
            "redline service configured",
            extra={
                "environment": config.environment,
                "metadata_store": config.metadata_store,
                "artifact_store": config.artifact_store,
                "workers": config.workers,
                "requeued_runs": requeued,
            },
        )
        if requeued:
            self.kick_queue()

    def close(self) -> None:
        self.closing = True
        self.executor.shutdown(wait=True, cancel_futures=False)

    def import_local_package(self, request: PackageImportRequest) -> PackageResponse:
        self._assert_package_quota()
        result = import_package(Path(request.package_path), write_lock=request.write_lock)
        package_id = _package_id(result.identity_hash)
        response = PackageResponse(
            package_id=package_id,
            path=result.path,
            identity_hash=result.identity_hash,
            identity_lock_hash=result.identity_lock_hash,
            files=result.files,
            created_at=utc_now(),
        )
        self.store.upsert_package(response)
        return response

    def create_run(self, *, request_id: str, request: RunCreateRequest) -> RunResponse:
        self._assert_run_quota()
        package_path = self._resolve_package_path(request)
        run_id = _run_id(request.model_dump(mode="json"))
        out_dir = self.artifacts.run_dir(run_id)
        run = self.store.create_run(
            run_id=run_id,
            request_id=request_id,
            request=request,
            package_path=package_path,
            out_dir=out_dir,
        )
        LOGGER.info("run queued", extra={"request_id": request_id, "run_id": run_id})
        self.kick_queue()
        return run

    def kick_queue(self) -> None:
        for _ in range(self.config.workers):
            self.executor.submit(self._drain_queue, worker_id=f"worker_{uuid.uuid4().hex[:8]}")

    def _drain_queue(self, *, worker_id: str) -> None:
        while True:
            work = self.store.claim_next_run(worker_id=worker_id)
            if work is None:
                return
            LOGGER.info("run claimed", extra={"request_id": work.request_id, "run_id": work.run_id, "worker_id": worker_id})
            execute_run(
                store=self.store,
                run_id=work.run_id,
                request=work.request,
                package_path=work.package_path,
                out_dir=work.out_dir,
                expose_error_details=self.config.expose_error_details,
                mark_running=False,
            )

    def check_rate_limit(self, key: str) -> None:
        if not self.rate_limiter.allow(key):
            raise HTTPException(status_code=429, detail="Redline service request quota exceeded")

    def _assert_package_quota(self) -> None:
        if self.config.max_packages and self.store.count_packages() >= self.config.max_packages:
            raise HTTPException(status_code=429, detail="Redline service package quota exceeded")

    def _assert_run_quota(self) -> None:
        if self.config.max_runs_total and self.store.count_runs() >= self.config.max_runs_total:
            raise HTTPException(status_code=429, detail="Redline service run quota exceeded")
        active = self.store.count_runs(states={RunState.QUEUED, RunState.RUNNING})
        if self.config.max_active_runs and active >= self.config.max_active_runs:
            raise HTTPException(status_code=429, detail="Redline service active run quota exceeded")

    def _resolve_package_path(self, request: RunCreateRequest) -> Path:
        if request.package_id is not None:
            package = self.store.get_package(request.package_id)
            if package is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"package not found: {request.package_id}")
            return Path(package.path)
        assert request.package_path is not None
        return Path(request.package_path).resolve()


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    service = RedlineService(config or ServiceConfig.from_env())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _ = app
        yield
        service.close()

    app = FastAPI(
        title="Playbook Redline Service",
        version="0.1.0",
        summary="Production-style HTTP boundary for Redline proof runs and artifacts.",
        lifespan=lifespan,
    )
    if service.config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(service.config.cors_origins),
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Redline-Token", "X-Request-Id"],
            expose_headers=["x-request-id"],
        )
    app.state.redline_service = service

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or f"req_{uuid.uuid4().hex}"
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        LOGGER.info(
            "request complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": elapsed_ms,
            },
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return _error_response(request, status_code=exc.status_code, error_code=str(exc.status_code), message=detail)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return _error_response(request, status_code=422, error_code=ReasonCode.SCHEMA_INVALID.value, message=str(exc))

    @app.exception_handler(CanonicalizationError)
    async def canonicalization_exception_handler(request: Request, exc: CanonicalizationError):
        return _error_response(request, status_code=400, error_code=exc.reason_code.value, message=str(exc))

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        LOGGER.exception("unhandled service exception", extra={"request_id": getattr(request.state, "request_id", "req_unknown")})
        message = str(exc) if service.config.expose_error_details else "internal server error"
        return _error_response(request, status_code=500, error_code=ReasonCode.DATA_MISSING.value, message=message)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            ok=True,
            environment=service.config.environment,
            metadata_store=service.config.metadata_store,
            artifact_store=service.config.artifact_store,
        )

    @app.post("/v1/auth/dev-login", tags=["auth"])
    def dev_login_endpoint(payload: Annotated[dict[str, object] | None, Body()] = None):
        if not service.config.dev_auth_enabled and not service.config.dev_auth_user:
            raise HTTPException(status_code=403, detail="dev auth is disabled")
        requested_login = str((payload or {}).get("login") or "") or None
        principal = dev_principal(
            raw_users=service.config.auth_users,
            configured_user=service.config.dev_auth_user,
            requested_login=requested_login,
        )
        response = JSONResponse({"ok": True, "principal": principal.public_dict()})
        response.set_cookie(
            SESSION_COOKIE_NAME,
            make_session_cookie(principal, secret=_auth_session_secret(service)),
            httponly=True,
            samesite="lax",
            secure=service.config.environment == "production",
            max_age=8 * 60 * 60,
        )
        return response

    @app.get("/v1/auth/login/github", tags=["auth"])
    def github_login_endpoint():
        if not service.config.github_oauth_client_id:
            raise HTTPException(status_code=501, detail="GitHub OAuth is not configured; set REDLINE_GITHUB_OAUTH_CLIENT_ID")
        state_value = secrets.token_urlsafe(32)
        query = {
            "client_id": service.config.github_oauth_client_id,
            "state": state_value,
            "scope": "read:user",
            "allow_signup": "false",
        }
        if service.config.github_oauth_redirect_uri:
            query["redirect_uri"] = service.config.github_oauth_redirect_uri
        response = RedirectResponse(GITHUB_AUTHORIZE_URL + "?" + urllib.parse.urlencode(query), status_code=302)
        response.set_cookie(
            GITHUB_STATE_COOKIE_NAME,
            state_value,
            httponly=True,
            samesite="lax",
            secure=service.config.environment == "production",
            max_age=10 * 60,
        )
        return response

    @app.get("/v1/auth/callback/github", tags=["auth"])
    def github_callback_endpoint(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
        if error:
            raise HTTPException(status_code=400, detail="GitHub OAuth authorization failed")
        if not code or not state:
            raise HTTPException(status_code=400, detail="GitHub OAuth callback missing code or state")
        expected_state = request.cookies.get(GITHUB_STATE_COOKIE_NAME)
        if not expected_state or not secrets.compare_digest(expected_state, state):
            raise HTTPException(status_code=400, detail="GitHub OAuth state mismatch")
        token = _github_exchange_code(service.config, code=code)
        github_user = _github_fetch_user(token)
        principal = _github_principal_from_user(service.config, github_user)
        response = JSONResponse({"ok": True, "principal": principal.public_dict()})
        response.set_cookie(
            SESSION_COOKIE_NAME,
            make_session_cookie(principal, secret=_auth_session_secret(service)),
            httponly=True,
            samesite="lax",
            secure=service.config.environment == "production",
            max_age=8 * 60 * 60,
        )
        response.delete_cookie(GITHUB_STATE_COOKIE_NAME)
        return response

    @app.post("/v1/auth/logout", tags=["auth"])
    def logout_endpoint():
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    @app.get("/v1/auth/me", tags=["auth"], dependencies=[Depends(_require_token)])
    def auth_me_endpoint(request: Request):
        return {"ok": True, "principal": _current_principal(request).public_dict()}

    router = APIRouter(prefix="/v1", dependencies=[Depends(_require_token)], tags=["redline"])

    @router.post("/packages/import", response_model=PackageResponse, status_code=201, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def import_package_endpoint(payload: PackageImportRequest, request: Request) -> PackageResponse:
        _ = request
        return service.import_local_package(payload)

    @router.post("/packages/upload", response_model=PackageResponse, status_code=201, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    async def upload_package_endpoint(
        request: Request,
        archive: Annotated[UploadFile, File(description="Canonical playbook package archive as .tar.gz")],
    ) -> PackageResponse:
        service._assert_package_quota()
        if archive.content_type not in {"application/gzip", "application/x-gzip", "application/tar", "application/octet-stream"}:
            raise HTTPException(status_code=415, detail="package upload must be a tar archive")
        upload_id = f"pkg_{uuid.uuid4().hex}"
        upload_dir = service.artifacts.package_upload_dir(upload_id)
        ensure_safe_output_dir(upload_dir)
        archive_path = upload_dir / "package.tar.gz"
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await archive.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > service.config.max_upload_bytes:
                raise HTTPException(status_code=413, detail="package upload exceeds max size")
            chunks.append(chunk)
        save_upload_stream(chunks=chunks, out_path=archive_path, max_bytes=service.config.max_upload_bytes)
        package_root = extract_package_archive(archive_path=archive_path, out_dir=upload_dir, max_bytes=service.config.max_upload_bytes)
        result = import_package(package_root, write_lock=False)
        response = PackageResponse(
            package_id=upload_id,
            path=result.path,
            identity_hash=result.identity_hash,
            identity_lock_hash=result.identity_lock_hash,
            files=result.files,
            created_at=utc_now(),
        )
        service.store.upsert_package(response)
        request.state.package_id = upload_id
        return response

    @router.post("/strategy-versions", response_model=StrategyVersionResponse, status_code=201, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def create_strategy_version_endpoint(payload: StrategyVersionCreateRequest) -> StrategyVersionResponse:
        try:
            version = _build_strategy_version(service, payload)
            created = service.store.create_strategy_version(version)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return created

    @router.get("/strategy-versions", response_model=StrategyVersionListResponse)
    def list_strategy_versions_endpoint(limit: int = 50) -> StrategyVersionListResponse:
        return StrategyVersionListResponse(strategy_versions=service.store.list_strategy_versions(limit=max(1, min(limit, 100))))

    @router.get("/strategy-versions/{version_id}", response_model=StrategyVersionResponse)
    def get_strategy_version_endpoint(version_id: str) -> StrategyVersionResponse:
        version = service.store.get_strategy_version(version_id)
        if version is None:
            raise HTTPException(status_code=404, detail="strategy version not found")
        return version

    @router.post("/release-candidates", response_model=ReleaseCandidateResponse, status_code=201, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def create_release_candidate_endpoint(
        request: Request,
        payload: ReleaseCandidateCreateRequest,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ReleaseCandidateResponse:
        replayed = _idempotency_replay(service, scope="release-candidates:create", key=idempotency_key, payload=payload.model_dump(mode="json"))
        if replayed is not None:
            return ReleaseCandidateResponse.model_validate(replayed)
        version = service.store.get_strategy_version(payload.version_id)
        if version is None:
            raise HTTPException(status_code=404, detail="strategy version not found")
        if payload.strategy_id is not None and payload.strategy_id != version.strategy_id:
            raise HTTPException(status_code=409, detail="release candidate strategy_id does not match strategy version")
        release_id = payload.release_id or _release_id(payload.model_dump(mode="json"))
        principal = _current_principal(request)
        created_by = payload.created_by if _is_legacy_service_principal(principal) else principal.principal_id
        metadata = dict(payload.metadata)
        metadata.setdefault("claimed_created_by", payload.created_by)
        metadata["created_by_auth"] = _principal_audit_payload(principal)
        now = utc_now()
        release = ReleaseCandidateResponse(
            release_id=release_id,
            strategy_id=version.strategy_id,
            version_id=version.version_id,
            state=ReleaseState.DRAFT,
            created_by=created_by,
            metadata=metadata,
            created_at=now,
            updated_at=now,
        )
        existing = service.store.get_release_candidate(release_id)
        try:
            created = service.store.create_release_candidate(release)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        _idempotency_store(
            service,
            scope="release-candidates:create",
            key=idempotency_key,
            payload=payload.model_dump(mode="json"),
            response=created.model_dump(mode="json"),
            status_code=201,
        )
        if existing is None:
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=created.release_id,
                event_type="strategy_version_created",
                actor=created.created_by,
                payload={
                    "strategy_id": version.strategy_id,
                    "version_id": version.version_id,
                    "package_hash": version.package_hash,
                    "actor_auth": _principal_audit_payload(principal),
                },
            )
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=created.release_id,
                event_type="release_candidate_created",
                actor=created.created_by,
                payload={"state": created.state.value, "actor_auth": _principal_audit_payload(principal)},
            )
        return created

    @router.get("/release-candidates", response_model=ReleaseCandidateListResponse)
    def list_release_candidates_endpoint(limit: int = 50) -> ReleaseCandidateListResponse:
        return ReleaseCandidateListResponse(release_candidates=service.store.list_release_candidates(limit=max(1, min(limit, 100))))

    @router.get("/release-candidates/{release_id}", response_model=ReleaseCandidateResponse)
    def get_release_candidate_endpoint(release_id: str) -> ReleaseCandidateResponse:
        return _get_release_or_404(service, release_id)

    @router.post("/release-candidates/{release_id}/redline-run", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def bind_redline_run_endpoint(release_id: str, payload: RedlineRunBindRequest, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        run = service.store.get_run(payload.run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        if release.state == ReleaseState.KILLED:
            return _release_blocked(release, "RELEASE_KILLED")
        state = _state_for_bound_run(run)
        updated = _transition_release_or_409(
            release,
            state,
            updates={
                "state": state,
                "run_id": run.run_id,
                "redline_reason_code": run.reason_code,
                "redline_receipt_hash": run.receipt_hash,
                "redline_report_hash": run.report_hash,
                "approval": None,
                "evidence_manifest": None,
                "evidence_manifest_hash": None,
            },
        )
        updated = service.store.update_release_candidate(updated)
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="redline_run_bound",
            actor=_audit_actor(request, release.created_by),
            payload={"run_id": run.run_id, "run_state": run.state.value, "reason_code": run.reason_code},
        )
        if state == ReleaseState.REDLINE_PASSED:
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=release_id,
                event_type="redline_verified",
                actor=_audit_actor(request, release.created_by),
                payload={"receipt_hash": run.receipt_hash, "report_hash": run.report_hash},
            )
        return ReleaseActionResponse(release_id=release_id, ok=state == ReleaseState.REDLINE_PASSED, state=updated.state, reason_code=run.reason_code)

    @router.post("/release-candidates/{release_id}/simulation-evidence", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def import_simulation_evidence_endpoint(release_id: str, payload: SimulationEvidenceRequest, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        _assert_release_not_terminal(release)
        evidence = {
            "schema_version": "redline.release.simulation_evidence.v1",
            **payload.model_dump(mode="json"),
            "release_id": release_id,
            "imported_at": utc_now(),
        }
        evidence_hash = simulation_evidence_hash(evidence)
        evidence = {**evidence, "evidence_hash": evidence_hash}
        write_release_json(service.config.root, release_id, SIMULATION_NAME, evidence)
        next_state = ReleaseState.REVIEW_REQUIRED if release.risk_policy and _release_has_redline_pass(release) else ReleaseState.EVIDENCE_COLLECTING
        updated = _transition_release_or_409(
            release,
            next_state,
            updates={
                "state": next_state,
                "simulation_evidence": evidence,
                "simulation_evidence_hash": evidence_hash,
                "approval": None,
                "evidence_manifest": None,
                "evidence_manifest_hash": None,
            },
        )
        updated = service.store.update_release_candidate(updated)
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="simulation_evidence_imported",
            actor=_audit_actor(request, release.created_by),
            payload={"evidence_hash": evidence_hash, "source": payload.source.value, "symbol": payload.symbol},
        )
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state, evidence={"simulation_evidence_hash": evidence_hash})

    @router.post("/release-candidates/{release_id}/simulation-evidence-file", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    async def import_simulation_evidence_file_endpoint(
        release_id: str,
        request: Request,
        source: Annotated[SimulationEvidenceSource, Form()],
        market: Annotated[str, Form(min_length=1, max_length=64)],
        symbol: Annotated[str, Form(min_length=1, max_length=64)],
        file: Annotated[UploadFile, File(description="GetAgent Studio or local backtest CSV/JSON export")],
    ) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        _assert_release_not_terminal(release)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > service.config.max_upload_bytes:
                raise HTTPException(status_code=413, detail="simulation evidence upload exceeds max size")
            chunks.append(chunk)
        raw = b"".join(chunks)
        release_artifact_dir = release_dir(service.config.root, release_id)
        suffix = ".json" if (file.filename or "").lower().endswith(".json") else ".csv"
        source_path = release_artifact_dir / f"release-simulation-source{suffix}"
        from redline.service.artifacts import atomic_write_bytes

        atomic_write_bytes(source_path, raw)
        normalized = _normalize_simulation_upload(raw=raw, filename=file.filename or source_path.name, source=source, market=market, symbol=symbol)
        evidence = {
            "schema_version": "redline.release.simulation_evidence.v1",
            **normalized,
            "release_id": release_id,
            "imported_at": utc_now(),
            "source_file_hash": hash_file(source_path),
            "metadata": {
                **normalized.get("metadata", {}),
                "source_filename": file.filename or "",
                "source_artifact": source_path.name,
            },
        }
        evidence_hash = simulation_evidence_hash(evidence)
        evidence = {**evidence, "evidence_hash": evidence_hash}
        write_release_json(service.config.root, release_id, SIMULATION_NAME, evidence)
        next_state = ReleaseState.REVIEW_REQUIRED if release.risk_policy and _release_has_redline_pass(release) else ReleaseState.EVIDENCE_COLLECTING
        updated = _transition_release_or_409(
            release,
            next_state,
            updates={
                "state": next_state,
                "simulation_evidence": evidence,
                "simulation_evidence_hash": evidence_hash,
                "approval": None,
                "evidence_manifest": None,
                "evidence_manifest_hash": None,
            },
        )
        updated = service.store.update_release_candidate(updated)
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="simulation_evidence_file_imported",
            actor=_audit_actor(request, release.created_by),
            payload={"evidence_hash": evidence_hash, "source_file_hash": evidence["source_file_hash"], "source": source.value, "symbol": symbol},
        )
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state, evidence={"simulation_evidence_hash": evidence_hash})

    @router.get("/release-candidates/{release_id}/simulation-evidence")
    def get_simulation_evidence_endpoint(release_id: str):
        release = _get_release_or_404(service, release_id)
        if release.simulation_evidence is None:
            raise HTTPException(status_code=404, detail="simulation evidence not found")
        return release.simulation_evidence

    @router.post("/release-candidates/{release_id}/risk-policy", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def bind_risk_policy_endpoint(release_id: str, payload: RiskPolicyRequest, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        _assert_release_not_terminal(release)
        policy = payload.model_dump(mode="json")
        risk_decision = risk_policy_breach(policy)
        risk_hash = policy_hash(policy)
        policy_record = {**policy, "schema_version": "redline.release.risk_policy.v1", "policy_hash": risk_hash, "bound_at": utc_now()}
        write_release_json(service.config.root, release_id, RISK_POLICY_NAME, policy_record)
        if risk_decision.blocked:
            next_state = ReleaseState.BLOCKED_RISK_POLICY
        elif _release_has_redline_pass(release) and release.simulation_evidence is not None:
            next_state = ReleaseState.REVIEW_REQUIRED
        else:
            next_state = ReleaseState.EVIDENCE_COLLECTING
        updated = _transition_release_or_409(
            release,
            next_state,
            updates={
                "state": next_state,
                "risk_policy": policy_record,
                "risk_policy_hash": risk_hash,
                "approval": None,
                "evidence_manifest": None,
                "evidence_manifest_hash": None,
            },
        )
        updated = service.store.update_release_candidate(updated)
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="risk_policy_bound",
            actor=_audit_actor(request, release.created_by),
            payload={"risk_policy_hash": risk_hash},
        )
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="risk_policy_checked",
            actor=_audit_actor(request, release.created_by),
            payload={"ok": risk_decision.ok, "breach": risk_decision.reason if risk_decision.blocked else None, "risk_policy_decision": risk_decision.model_dump()},
        )
        return ReleaseActionResponse(
            release_id=release_id,
            ok=risk_decision.ok,
            state=updated.state,
            reason_code="RISK_POLICY_BREACH" if risk_decision.blocked else None,
            evidence={
                "risk_policy_hash": risk_hash,
                "breach": risk_decision.reason if risk_decision.blocked else None,
                "risk_policy_decision": risk_decision.model_dump(),
            },
        )

    @router.post("/release-candidates/{release_id}/approve", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def approve_release_endpoint(release_id: str, payload: ApprovalRequest, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        principal = _current_principal(request)
        if _release_freeze_enabled():
            LOGGER.warning("release approval blocked by freeze", extra={"release_id": release_id, "principal_id": principal.principal_id})
            return _release_blocked(release, "REDLINE_RELEASE_FREEZE")
        if principal.role not in APPROVAL_ROLES and not _is_legacy_service_principal(principal):
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_APPROVAL, reason_code="APPROVAL_ROLE_DENIED")
        if principal.principal_id == release.created_by and not _is_legacy_service_principal(principal):
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_APPROVAL, reason_code="SELF_APPROVAL_FORBIDDEN")
        blocked = _approval_block_reason(service, release)
        if blocked:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_APPROVAL, reason_code=blocked)
        strategy_version = _get_strategy_version_for_release_or_404(service, release)
        fingerprint = evidence_fingerprint(release, strategy_version=strategy_version)
        approved_at = utc_now()
        approval = {
            "schema_version": "redline.release.approval.v1",
            "decision": "approve",
            "reviewer_id": principal.principal_id,
            "reviewer_role": principal.role,
            "auth_method": principal.auth_method,
            "auth_subject": principal.subject,
            "reviewer_display_name": principal.display_name,
            "reviewer_email": principal.email,
            "claimed_reviewer_id": payload.reviewer_id,
            "comment": payload.comment,
            "approved_at": approved_at,
            "nonce": _approval_nonce(),
            "expires_at": _approval_expires_at(),
            "consumed_at": None,
            "evidence_manifest_hash": fingerprint,
            "package_hash": strategy_version.package_hash,
            "identity_lock_hash": strategy_version.identity_lock_hash,
            "risk_policy_hash": release.risk_policy_hash,
            "demo_mode": payload.demo_mode,
        }
        if release.state == ReleaseState.RELEASE_READY:
            metadata = dict(release.metadata)
            metadata[SHOWCASE_APPROVAL_METADATA_KEY] = approval
            updated = service.store.update_release_candidate(release.model_copy(update={"metadata": metadata}))
        else:
            updated = service.store.update_release_candidate(_transition_release_or_409(release, ReleaseState.APPROVED, updates={"approval": approval}))
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="approval_granted",
            actor=principal.principal_id,
            payload={
                "evidence_manifest_hash": fingerprint,
                "package_hash": strategy_version.package_hash,
                "identity_lock_hash": strategy_version.identity_lock_hash,
                "risk_policy_hash": release.risk_policy_hash,
                "actor_auth": _principal_audit_payload(principal),
            },
        )
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state, evidence={"approval": approval})

    @router.post("/release-candidates/{release_id}/reject", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def reject_release_endpoint(release_id: str, payload: RejectRequest, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        principal = _current_principal(request)
        approval = {
            "schema_version": "redline.release.approval.v1",
            "decision": "reject",
            "reviewer_id": principal.principal_id,
            "reviewer_role": principal.role,
            "auth_method": principal.auth_method,
            "auth_subject": principal.subject,
            "reviewer_display_name": principal.display_name,
            "reviewer_email": principal.email,
            "claimed_reviewer_id": payload.reviewer_id,
            "comment": payload.comment,
            "rejected_at": utc_now(),
            "evidence_manifest_hash": evidence_fingerprint(release, strategy_version=_get_strategy_version_for_release_or_404(service, release)),
            "risk_policy_hash": release.risk_policy_hash,
        }
        updated = service.store.update_release_candidate(
            _transition_release_or_409(release, ReleaseState.REJECTED, updates={"approval": approval, "reject_reason": payload.comment})
        )
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="approval_rejected",
            actor=principal.principal_id,
            payload={"comment": payload.comment, "actor_auth": _principal_audit_payload(principal)},
        )
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state, evidence={"approval": approval})

    @router.post("/release-candidates/{release_id}/execute-demo", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def execute_release_demo_endpoint(
        release_id: str,
        request: Request,
        payload: Annotated[ExecutionRequest | None, Body()] = None,
    ) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        execution_request = payload or ExecutionRequest()
        if _execution_freeze_enabled():
            LOGGER.warning("release execution blocked by freeze", extra={"release_id": release_id})
            return _release_blocked(release, "REDLINE_EXECUTION_FREEZE")
        if release.execution_evidence is not None:
            return ReleaseActionResponse(release_id=release_id, ok=True, state=release.state, evidence=release.execution_evidence)
        if release.state in {
            ReleaseState.BLOCKED_WITHHELD,
            ReleaseState.BLOCKED_UNVERIFIED,
            ReleaseState.BLOCKED_MISSING_EVIDENCE,
            ReleaseState.BLOCKED_RISK_POLICY,
            ReleaseState.BLOCKED_APPROVAL,
            ReleaseState.BLOCKED_EXCHANGE_ERROR,
        }:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code=release.state.value.upper())
        if release.state != ReleaseState.APPROVED:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RELEASE_NOT_APPROVED")
        strategy_version = _get_strategy_version_for_release_or_404(service, release)
        approval_block = _approval_block_reason_for_execution(release, strategy_version=strategy_version)
        if approval_block is not None:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_APPROVAL, reason_code=approval_block)
        consumed_release = _consume_current_approval(service, release)
        if consumed_release is None:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_APPROVAL, reason_code=ReasonCode.APPROVAL_CONSUMED.value)
        release = consumed_release
        if release.risk_policy is None:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_RISK_POLICY, reason_code="RISK_POLICY_REQUIRED")
        risk_decision = risk_policy_breach(release.risk_policy, execution_request)
        if risk_decision.blocked:
            updated = service.store.update_release_candidate(_transition_release_or_409(release, ReleaseState.BLOCKED_RISK_POLICY))
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=release_id,
                event_type="risk_policy_checked",
                actor=_audit_actor(request, release.created_by),
                payload={"ok": False, "breach": risk_decision.reason, "risk_policy_decision": risk_decision.model_dump()},
            )
            return ReleaseActionResponse(
                release_id=release_id,
                ok=False,
                state=updated.state,
                reason_code="RISK_POLICY_BREACH",
                evidence={"breach": risk_decision.reason, "risk_policy_decision": risk_decision.model_dump()},
            )
        execution_request = _apply_risk_policy_decision(execution_request, risk_decision)
        if release.run_id is None:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_UNVERIFIED, reason_code="RUN_REQUIRED")
        run = service.store.get_run(release.run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="demo_order_requested",
            actor=_audit_actor(request, release.created_by),
            payload={"run_id": run.run_id, "risk_policy_decision": risk_decision.model_dump()},
        )
        execution = _execute_bitget_demo_order(service=service, run=run, payload=execution_request, approval_hash=approval_record_hash(release.approval))
        if not execution.ok:
            updated = service.store.update_release_candidate(_transition_release_or_409(release, ReleaseState.BLOCKED_EXCHANGE_ERROR))
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=release_id,
                event_type="demo_order_blocked",
                actor=_audit_actor(request, release.created_by),
                payload={"reason_code": execution.reason_code, "state": execution.state},
            )
            return ReleaseActionResponse(release_id=release_id, ok=False, state=updated.state, reason_code=execution.reason_code, evidence=execution.evidence)
        evidence = execution.evidence
        try:
            canonical_evidence = load_execution_evidence(Path(run.out_dir) / "execution-evidence.json").model_dump(mode="json")
        except ExecutionBlocked as exc:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=ReleaseState.BLOCKED_EXCHANGE_ERROR, reason_code=exc.reason_code, evidence={"detail": exc.message})
        updated = service.store.update_release_candidate(
            _transition_release_or_409(
                release,
                ReleaseState.RELEASE_READY,
                updates={
                    "state": ReleaseState.RELEASE_READY,
                    "execution_run_id": run.run_id,
                    "execution_evidence": canonical_evidence,
                    "evidence_manifest": None,
                    "evidence_manifest_hash": None,
                },
            )
        )
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="demo_order_placed",
            actor=_audit_actor(request, release.created_by),
            payload={
                "run_id": run.run_id,
                "client_oid": evidence.get("client_oid"),
                "bitget_order_id": _mask_identifier(str(evidence.get("bitget_order_id", ""))),
                "risk_policy_decision": risk_decision.model_dump(),
            },
        )
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="release_ready",
            actor=_audit_actor(request, release.created_by),
            payload={"state": updated.state.value},
        )
        evidence["risk_policy_decision"] = risk_decision.model_dump()
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state, evidence=evidence)

    @router.post("/release-candidates/{release_id}/demo-showcase-orders", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def create_release_demo_showcase_order_endpoint(
        release_id: str,
        request: Request,
        payload: Annotated[ExecutionRequest | None, Body()] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        execution_request = payload or ExecutionRequest()
        replayed = _idempotency_replay(
            service,
            scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
            key=idempotency_key,
            payload=execution_request.model_dump(mode="json"),
        )
        if replayed is not None:
            return ReleaseActionResponse.model_validate(replayed)
        if _execution_freeze_enabled():
            LOGGER.warning("release showcase execution blocked by freeze", extra={"release_id": release_id})
            response = _release_blocked(release, "REDLINE_EXECUTION_FREEZE")
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        if release.state != ReleaseState.RELEASE_READY or release.execution_evidence is None:
            response = ReleaseActionResponse(
                release_id=release_id,
                ok=False,
                state=release.state,
                reason_code="RELEASE_DEMO_EXECUTION_REQUIRED",
                evidence={"detail": "canonical execute-demo evidence is required before showcase orders"},
            )
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        strategy_version = _get_strategy_version_for_release_or_404(service, release)
        approval, approval_kind = _current_showcase_approval(release)
        approval_block = _approval_block_reason_for_execution(release, strategy_version=strategy_version, approval=approval)
        if approval_block is not None:
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code=approval_block)
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        consumed_release = _consume_current_approval(service, release, approval_kind=approval_kind)
        if consumed_release is None:
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code=ReasonCode.APPROVAL_CONSUMED.value)
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        release = consumed_release
        approval, _approval_kind = _current_showcase_approval(release)
        if release.risk_policy is None:
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RISK_POLICY_REQUIRED")
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        risk_decision = risk_policy_breach(release.risk_policy, execution_request)
        if risk_decision.blocked:
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=release_id,
                event_type="showcase_risk_policy_checked",
                actor=_audit_actor(request, release.created_by),
                payload={"ok": False, "breach": risk_decision.reason, "risk_policy_decision": risk_decision.model_dump()},
            )
            response = ReleaseActionResponse(
                release_id=release_id,
                ok=False,
                state=release.state,
                reason_code="RISK_POLICY_BREACH",
                evidence={"breach": risk_decision.reason, "risk_policy_decision": risk_decision.model_dump()},
            )
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        execution_request = _apply_risk_policy_decision(execution_request, risk_decision)
        run_id = release.execution_run_id or release.run_id
        if run_id is None:
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RUN_REQUIRED")
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        try:
            canonical_evidence = load_execution_evidence(Path(run.out_dir) / "execution-evidence.json")
        except ExecutionBlocked as exc:
            response = ReleaseActionResponse(
                release_id=release_id,
                ok=False,
                state=release.state,
                reason_code="RELEASE_EVIDENCE_CHANGED",
                evidence={"detail": exc.reason_code},
            )
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        if canonical_evidence.model_dump(mode="json") != release.execution_evidence:
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RELEASE_EVIDENCE_CHANGED")
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="showcase_demo_order_requested",
            actor=_audit_actor(request, release.created_by),
            payload={"run_id": run.run_id, "risk_policy_decision": risk_decision.model_dump()},
        )
        execution = _execute_bitget_demo_showcase_order(
            service=service,
            release_id=release_id,
            run=run,
            payload=execution_request,
            approval_hash=approval_record_hash(approval or {}),
        )
        if not execution.ok:
            append_release_audit_event(
                root=service.config.root,
                store=service.store,
                release_id=release_id,
                event_type="showcase_demo_order_blocked",
                actor=_audit_actor(request, release.created_by),
                payload={"reason_code": execution.reason_code, "state": execution.state},
            )
            response = ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code=execution.reason_code, evidence=execution.evidence)
            _idempotency_store(
                service,
                scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
                key=idempotency_key,
                payload=execution_request.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                status_code=200,
            )
            return response
        evidence = execution.evidence
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="showcase_demo_order_placed",
            actor=_audit_actor(request, release.created_by),
            payload={
                "run_id": run.run_id,
                "attempt_id": evidence.get("attempt_id"),
                "client_oid": evidence.get("client_oid"),
                "bitget_order_id": _mask_identifier(str(evidence.get("bitget_order_id", ""))),
                "risk_policy_decision": risk_decision.model_dump(),
            },
        )
        evidence["risk_policy_decision"] = risk_decision.model_dump()
        response = ReleaseActionResponse(release_id=release_id, ok=True, state=release.state, evidence=evidence)
        _idempotency_store(
            service,
            scope=f"release-candidates:{release_id}:demo-showcase-orders:create",
            key=idempotency_key,
            payload=execution_request.model_dump(mode="json"),
            response=response.model_dump(mode="json"),
            status_code=200,
        )
        return response

    @router.get("/release-candidates/{release_id}/demo-showcase-orders")
    def list_release_demo_showcase_orders_endpoint(release_id: str):
        _get_release_or_404(service, release_id)
        attempts = _list_showcase_order_summaries(service=service, release_id=release_id)
        return {"release_id": release_id, "count": len(attempts), "orders": attempts}

    @router.get("/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html", response_class=HTMLResponse)
    def release_demo_showcase_evidence_html_endpoint(release_id: str, attempt_id: str) -> HTMLResponse:
        from redline.render import load_evidence_panel, render_execution_evidence_html

        _get_release_or_404(service, release_id)
        title = f"Release {release_id} · showcase {attempt_id}"
        try:
            evidence = _load_showcase_execution_evidence(service=service, release_id=release_id, attempt_id=attempt_id)
        except ExecutionBlocked as exc:
            return HTMLResponse(
                render_execution_evidence_html(
                    evidence=None,
                    verdict="INVALID",
                    reason_code=exc.reason_code,
                    chain_status="invalid",
                    strength_summary="showcase execution evidence failed verification",
                    invalid_reason_code=exc.reason_code,
                    title=title,
                )
            )
        run = service.store.get_run(evidence.run_id)
        panel = load_evidence_panel(Path(run.out_dir), title=title) if run is not None else None
        return HTMLResponse(
            render_execution_evidence_html(
                evidence=evidence,
                verdict="PASS",
                reason_code=panel.reason_code if panel is not None else ReasonCode.PASS.value,
                chain_status=panel.chain_status if panel is not None else "chained",
                strength_summary=panel.strength_summary if panel is not None else "Redline receipt verified for showcase execution",
                receipt_hash=evidence.receipt_hash,
                title=title,
            )
        )

    def _run_showcase_order_job(
        *,
        job_id: str,
        release_id: str,
        principal: AuthPrincipal,
        execution_request: ExecutionRequest,
        already_claimed: bool = False,
    ) -> None:
        try:
            if not already_claimed:
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.RUNNING)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_started", payload={"job_type": ReleaseJobType.SHOWCASE_ORDER.value})
            if _release_job_cancel_requested(release_id=release_id, job_id=job_id):
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.CANCELLED, error_code="JOB_CANCELLED", error_message="release job cancelled before Bitget request")
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_cancelled", payload={"stage": "before_bitget_request"})
                return
            release = service.store.get_release_candidate(release_id)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="redline_verification_started", payload={"release_id": release_id})
            if release is not None and release.redline_reason_code == ReasonCode.PASS.value:
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="redline_verification_passed",
                    payload={"receipt_hash": release.redline_receipt_hash},
                )
            service.store.append_release_job_event(
                release_id=release_id,
                job_id=job_id,
                event_type="risk_policy_checked",
                payload={"risk_policy_hash": release.risk_policy_hash if release is not None else None},
            )
            service.store.append_release_job_event(
                release_id=release_id,
                job_id=job_id,
                event_type="canonical_evidence_checked",
                payload={"execution_run_id": release.execution_run_id if release is not None else None},
            )
            fake_request = SimpleNamespace(state=SimpleNamespace(auth_principal=principal))
            response = create_release_demo_showcase_order_endpoint(
                release_id=release_id,
                request=fake_request,
                payload=execution_request,
                idempotency_key=f"release-job:{job_id}",
            )
            response_payload = response.model_dump(mode="json")
            if response.ok:
                if response.evidence.get("preflight_hash"):
                    service.store.append_release_job_event(
                        release_id=release_id,
                        job_id=job_id,
                        event_type="exchange_preflight_passed",
                        payload={"preflight_hash": response.evidence.get("preflight_hash")},
                    )
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="bitget_order_requested", payload={"mode": "demo", "paptrading": "1"})
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="bitget_order_placed",
                    payload={
                        "bitget_order_id": response.evidence.get("bitget_order_id"),
                        "client_oid": response.evidence.get("client_oid"),
                        "attempt_id": response.evidence.get("attempt_id"),
                    },
                )
                if response.evidence.get("order_status_hash"):
                    service.store.append_release_job_event(
                        release_id=release_id,
                        job_id=job_id,
                        event_type="bitget_reconciliation_succeeded",
                        payload={"order_status_hash": response.evidence.get("order_status_hash"), "order_status": response.evidence.get("order_status")},
                    )
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="evidence_written",
                    payload={
                        "attempt_id": response.evidence.get("attempt_id"),
                        "evidence_hash": response.evidence.get("evidence_hash"),
                        "response_hash": response.evidence.get("response_hash"),
                    },
                )
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.SUCCEEDED, result=response_payload)
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_succeeded", payload={"ok": True})
            else:
                reason_code = response.reason_code or "JOB_FAILED"
                if reason_code == "EXCHANGE_PREFLIGHT_FAILED":
                    service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="exchange_preflight_failed", payload={"reason_code": reason_code})
                if reason_code == "EXCHANGE_RECONCILIATION_REQUIRED":
                    service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="bitget_reconciliation_required", payload={"reason_code": reason_code})
                if reason_code.startswith("BITGET_"):
                    service.store.append_release_job_event(
                        release_id=release_id,
                        job_id=job_id,
                        event_type="bitget_order_requested",
                        payload={"mode": "demo", "paptrading": "1", "reason_code": reason_code},
                    )
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.FAILED, result=response_payload, error_code=reason_code, error_message=reason_code)
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_failed", payload={"reason_code": reason_code})
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            error_code = type(exc).__name__
            service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.FAILED, error_code=error_code, error_message=error_code)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_failed", payload={"reason_code": error_code})

    def _release_job_cancel_requested(*, release_id: str, job_id: str) -> bool:
        return any(event.event_type == "job_cancel_requested" for event in service.store.list_release_job_events(release_id=release_id, job_id=job_id))

    def _run_canonical_execute_demo_job(
        *,
        job_id: str,
        release_id: str,
        principal: AuthPrincipal,
        execution_request: ExecutionRequest,
        already_claimed: bool = False,
    ) -> None:
        try:
            if not already_claimed:
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.RUNNING)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_started", payload={"job_type": ReleaseJobType.CANONICAL_EXECUTE_DEMO.value})
            if _release_job_cancel_requested(release_id=release_id, job_id=job_id):
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.CANCELLED, error_code="JOB_CANCELLED", error_message="release job cancelled before Bitget request")
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_cancelled", payload={"stage": "before_bitget_request"})
                return
            release = service.store.get_release_candidate(release_id)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="redline_verification_started", payload={"release_id": release_id})
            if release is not None and release.redline_reason_code == ReasonCode.PASS.value:
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="redline_verification_passed",
                    payload={"receipt_hash": release.redline_receipt_hash},
                )
            service.store.append_release_job_event(
                release_id=release_id,
                job_id=job_id,
                event_type="risk_policy_checked",
                payload={"risk_policy_hash": release.risk_policy_hash if release is not None else None},
            )
            fake_request = SimpleNamespace(state=SimpleNamespace(auth_principal=principal))
            response = execute_release_demo_endpoint(
                release_id=release_id,
                request=fake_request,
                payload=execution_request,
            )
            response_payload = response.model_dump(mode="json")
            if response.ok:
                if response.evidence.get("preflight_hash"):
                    service.store.append_release_job_event(
                        release_id=release_id,
                        job_id=job_id,
                        event_type="exchange_preflight_passed",
                        payload={"preflight_hash": response.evidence.get("preflight_hash")},
                    )
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="bitget_order_requested", payload={"mode": "demo", "paptrading": "1"})
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="bitget_order_placed",
                    payload={
                        "bitget_order_id": response.evidence.get("bitget_order_id"),
                        "client_oid": response.evidence.get("client_oid"),
                    },
                )
                if response.evidence.get("order_status_hash"):
                    service.store.append_release_job_event(
                        release_id=release_id,
                        job_id=job_id,
                        event_type="bitget_reconciliation_succeeded",
                        payload={"order_status_hash": response.evidence.get("order_status_hash"), "order_status": response.evidence.get("order_status")},
                    )
                service.store.append_release_job_event(
                    release_id=release_id,
                    job_id=job_id,
                    event_type="evidence_written",
                    payload={"run_id": response.evidence.get("run_id"), "response_hash": response.evidence.get("response_hash")},
                )
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.SUCCEEDED, result=response_payload)
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_succeeded", payload={"ok": True})
            else:
                reason_code = response.reason_code or "JOB_FAILED"
                if reason_code == "EXCHANGE_PREFLIGHT_FAILED":
                    service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="exchange_preflight_failed", payload={"reason_code": reason_code})
                if reason_code == "EXCHANGE_RECONCILIATION_REQUIRED":
                    service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="bitget_reconciliation_required", payload={"reason_code": reason_code})
                service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.FAILED, result=response_payload, error_code=reason_code, error_message=reason_code)
                service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_failed", payload={"reason_code": reason_code})
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            error_code = type(exc).__name__
            service.store.mark_release_job_status(job_id=job_id, status=ReleaseJobStatus.FAILED, error_code=error_code, error_message=error_code)
            service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_failed", payload={"reason_code": error_code})

    def _principal_for_release_job(work: ReleaseJobWorkItem) -> AuthPrincipal:
        return AuthPrincipal(
            principal_id=work.requested_by,
            role="release_manager",
            scopes=frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO}),
            token_label="release-job",
            auth_method="service_token",
            subject=work.requested_by,
            display_name=work.requested_by,
        )

    def _drain_release_jobs(*, worker_id: str) -> None:
        while not service.closing:
            work = service.store.claim_next_release_job(worker_id=worker_id)
            if work is None:
                return
            if work.job_type == ReleaseJobType.SHOWCASE_ORDER:
                _run_showcase_order_job(
                    job_id=work.job_id,
                    release_id=work.release_id,
                    principal=_principal_for_release_job(work),
                    execution_request=ExecutionRequest.model_validate(work.request),
                    already_claimed=True,
                )
                continue
            if work.job_type == ReleaseJobType.CANONICAL_EXECUTE_DEMO:
                _run_canonical_execute_demo_job(
                    job_id=work.job_id,
                    release_id=work.release_id,
                    principal=_principal_for_release_job(work),
                    execution_request=ExecutionRequest.model_validate(work.request),
                    already_claimed=True,
                )
                continue
            service.store.mark_release_job_status(job_id=work.job_id, status=ReleaseJobStatus.FAILED, error_code="JOB_TYPE_UNSUPPORTED", error_message=work.job_type.value)
            service.store.append_release_job_event(release_id=work.release_id, job_id=work.job_id, event_type="job_failed", payload={"reason_code": "JOB_TYPE_UNSUPPORTED"})

    def _kick_release_jobs() -> None:
        for _ in range(service.config.workers):
            service.executor.submit(_drain_release_jobs, worker_id=f"release_job_{uuid.uuid4().hex[:8]}")

    @router.post("/release-candidates/{release_id}/jobs/showcase-order", response_model=ReleaseJobResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def create_release_showcase_order_job_endpoint(
        release_id: str,
        request: Request,
        payload: Annotated[ExecutionRequest | None, Body()] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ReleaseJobResponse:
        _get_release_or_404(service, release_id)
        execution_request = payload or ExecutionRequest()
        request_payload = execution_request.model_dump(mode="json")
        replayed = _idempotency_replay(
            service,
            scope=f"release-candidates:{release_id}:jobs:showcase-order:create",
            key=idempotency_key,
            payload=request_payload,
        )
        if replayed is not None:
            replayed_job_id = str(replayed.get("job_id") or "")
            current = service.store.get_release_job(release_id=release_id, job_id=replayed_job_id)
            return current or ReleaseJobResponse.model_validate(replayed)
        principal = _current_principal(request)
        request_hash = hash_obj(request_payload)
        job_id = _job_id({"release_id": release_id, "job_type": ReleaseJobType.SHOWCASE_ORDER.value, "request_hash": request_hash})
        job = service.store.create_release_job(
            job_id=job_id,
            release_id=release_id,
            job_type=ReleaseJobType.SHOWCASE_ORDER,
            request_hash=request_hash,
            request=request_payload,
            idempotency_key=idempotency_key,
            requested_by=principal.principal_id,
        )
        service.store.append_release_job_event(release_id=release_id, job_id=job_id, event_type="job_queued", payload={"job_type": job.job_type.value})
        _idempotency_store(
            service,
            scope=f"release-candidates:{release_id}:jobs:showcase-order:create",
            key=idempotency_key,
            payload=request_payload,
            response=job.model_dump(mode="json"),
            status_code=202,
        )
        _kick_release_jobs()
        return job

    @router.post("/release-candidates/{release_id}/jobs/execute-demo", response_model=ReleaseJobResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def create_release_execute_demo_job_endpoint(
        release_id: str,
        request: Request,
        payload: Annotated[ExecutionRequest | None, Body()] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ReleaseJobResponse:
        _get_release_or_404(service, release_id)
        execution_request = payload or ExecutionRequest()
        request_payload = execution_request.model_dump(mode="json")
        replayed = _idempotency_replay(
            service,
            scope=f"release-candidates:{release_id}:jobs:execute-demo:create",
            key=idempotency_key,
            payload=request_payload,
        )
        if replayed is not None:
            replayed_job_id = str(replayed.get("job_id") or "")
            current = service.store.get_release_job(release_id=release_id, job_id=replayed_job_id)
            return current or ReleaseJobResponse.model_validate(replayed)
        principal = _current_principal(request)
        request_hash = hash_obj(request_payload)
        job_id = _job_id({"release_id": release_id, "job_type": ReleaseJobType.CANONICAL_EXECUTE_DEMO.value, "request_hash": request_hash})
        job = service.store.create_release_job(
            job_id=job_id,
            release_id=release_id,
            job_type=ReleaseJobType.CANONICAL_EXECUTE_DEMO,
            request=request_payload,
            requested_by=principal.principal_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        service.store.append_release_job_event(
            release_id=release_id,
            job_id=job_id,
            event_type="job_queued",
            payload={"requested_by": principal.principal_id, "job_type": ReleaseJobType.CANONICAL_EXECUTE_DEMO.value},
        )
        _idempotency_store(
            service,
            scope=f"release-candidates:{release_id}:jobs:execute-demo:create",
            key=idempotency_key,
            payload=request_payload,
            response=job.model_dump(mode="json"),
            status_code=200,
        )
        _kick_release_jobs()
        return job

    @router.post("/release-candidates/{release_id}/jobs/{job_id}/cancel", response_model=ReleaseJobResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def cancel_release_job_endpoint(release_id: str, job_id: str, request: Request) -> ReleaseJobResponse:
        _get_release_or_404(service, release_id)
        principal = _current_principal(request)
        job = service.store.get_release_job(release_id=release_id, job_id=job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="release job not found")
        if job.status == ReleaseJobStatus.QUEUED:
            cancelled = service.store.cancel_release_job(release_id=release_id, job_id=job_id)
            if cancelled is None:
                raise HTTPException(status_code=404, detail="release job not found")
            service.store.append_release_job_event(
                release_id=release_id,
                job_id=job_id,
                event_type="job_cancelled",
                payload={"actor": principal.principal_id, "stage": "queued"},
            )
            return cancelled
        if job.status == ReleaseJobStatus.RUNNING:
            service.store.append_release_job_event(
                release_id=release_id,
                job_id=job_id,
                event_type="job_cancel_requested",
                payload={"actor": principal.principal_id, "detail": "Bitget request may already be in flight"},
            )
            current = service.store.get_release_job(release_id=release_id, job_id=job_id)
            return current or job
        return job

    @router.get("/release-candidates/{release_id}/jobs", response_model=ReleaseJobListResponse)
    def list_release_jobs_endpoint(release_id: str) -> ReleaseJobListResponse:
        _get_release_or_404(service, release_id)
        return ReleaseJobListResponse(jobs=service.store.list_release_jobs(release_id=release_id))

    @router.get("/release-candidates/{release_id}/jobs/{job_id}", response_model=ReleaseJobResponse)
    def get_release_job_endpoint(release_id: str, job_id: str) -> ReleaseJobResponse:
        _get_release_or_404(service, release_id)
        job = service.store.get_release_job(release_id=release_id, job_id=job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="release job not found")
        return job

    @router.get("/release-candidates/{release_id}/jobs/{job_id}/events", response_model=ReleaseJobEventListResponse)
    def list_release_job_events_endpoint(release_id: str, job_id: str) -> ReleaseJobEventListResponse:
        _get_release_or_404(service, release_id)
        if service.store.get_release_job(release_id=release_id, job_id=job_id) is None:
            raise HTTPException(status_code=404, detail="release job not found")
        return ReleaseJobEventListResponse(events=service.store.list_release_job_events(release_id=release_id, job_id=job_id))

    @router.get("/release-candidates/{release_id}/jobs/{job_id}/events.ndjson", response_class=PlainTextResponse)
    def list_release_job_events_ndjson_endpoint(release_id: str, job_id: str) -> PlainTextResponse:
        events = list_release_job_events_endpoint(release_id, job_id).events
        body = "".join(json.dumps(event.model_dump(mode="json"), sort_keys=True) + "\n" for event in events)
        return PlainTextResponse(body, media_type="application/x-ndjson")

    @router.post("/release-candidates/{release_id}/kill", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def kill_release_endpoint(release_id: str, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        updated = service.store.update_release_candidate(_transition_release_or_409(release, ReleaseState.KILLED, updates={"killed_at": utc_now()}))
        append_release_audit_event(
            root=service.config.root,
            store=service.store,
            release_id=release_id,
            event_type="release_killed",
            actor=_audit_actor(request, release.created_by),
            payload={"state": updated.state.value},
        )
        return ReleaseActionResponse(release_id=release_id, ok=True, state=updated.state)

    @router.get("/release-candidates/{release_id}/evidence")
    def download_release_evidence_endpoint(release_id: str):
        release = _get_release_or_404(service, release_id)
        missing = _required_release_evidence_missing(release)
        if missing:
            response = _missing_release_evidence_response(release, missing)
            return JSONResponse(status_code=409, content=response.model_dump(mode="json"))
        _release, bundle_path, _manifest_path, _manifest_hash, _manifest = _ensure_release_evidence_bundle(service=service, release=release)
        return FileResponse(bundle_path, filename=bundle_path.name, media_type="application/json")

    @router.post("/release-candidates/{release_id}/attest", response_model=ReleaseActionResponse, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def attest_release_endpoint(release_id: str, request: Request) -> ReleaseActionResponse:
        release = _get_release_or_404(service, release_id)
        missing = _required_release_evidence_missing(release)
        if missing:
            return _missing_release_evidence_response(release, missing)
        if release.state != ReleaseState.RELEASE_READY:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RELEASE_NOT_READY")
        release, bundle_path, _manifest_path, _manifest_hash, _manifest = _ensure_release_evidence_bundle(service=service, release=release)
        key_text = os.environ.get("REDLINE_ATTESTATION_PRIVATE_KEY") or os.environ.get("REDLINE_TRUST_PRIVATE_KEY")
        principal = _current_principal(request)
        try:
            attestation = attest_release_bundle(
                bundle_path=bundle_path,
                private_key_text=key_text,
                attester_principal=principal.principal_id,
                key_id=os.environ.get("REDLINE_ATTESTATION_KEY_ID", "service-local"),
                issuer=os.environ.get("REDLINE_ATTESTATION_ISSUER", "redline-service"),
            )
            attestation_path = release_dir(service.config.root, release_id) / RELEASE_ATTESTATION_NAME
            write_release_attestation(attestation_path, attestation)
            verification = verify_release_attestation(attestation_path=attestation_path, bundle_path=bundle_path)
        except ValueError as exc:
            return ReleaseActionResponse(release_id=release_id, ok=False, state=release.state, reason_code="RELEASE_ATTESTATION_FAILED", evidence={"detail": str(exc)})
        return ReleaseActionResponse(
            release_id=release_id,
            ok=bool(verification["ok"]),
            state=release.state,
            reason_code=None if verification["ok"] else "RELEASE_ATTESTATION_INVALID",
            evidence={**attestation.model_dump(mode="json"), "attestation_path": str(attestation_path), "verification": verification},
        )

    @router.get("/release-candidates/{release_id}/attestation")
    def get_release_attestation_endpoint(release_id: str):
        release = _get_release_or_404(service, release_id)
        _release, bundle_path, _manifest_path, _manifest_hash, _manifest = _ensure_release_evidence_bundle(service=service, release=release)
        attestation_path = release_dir(service.config.root, release_id) / RELEASE_ATTESTATION_NAME
        if not attestation_path.exists():
            raise HTTPException(status_code=404, detail="release attestation not found")
        attestation = load_release_attestation(attestation_path)
        verification = verify_release_attestation(attestation_path=attestation_path, bundle_path=bundle_path)
        return {**attestation.model_dump(mode="json"), "attestation_path": str(attestation_path), "verification": verification}

    @router.get("/release-candidates/{release_id}/attestation.html", response_class=HTMLResponse)
    def release_attestation_html_endpoint(release_id: str) -> HTMLResponse:
        release = _get_release_or_404(service, release_id)
        _release, bundle_path, _manifest_path, _manifest_hash, _manifest = _ensure_release_evidence_bundle(service=service, release=release)
        attestation_path = release_dir(service.config.root, release_id) / RELEASE_ATTESTATION_NAME
        if not attestation_path.exists():
            verification = {
                "ok": False,
                "attestation_path": str(attestation_path),
                "bundle_path": str(bundle_path),
                "checks": [{"name": "attestation-json", "ok": False, "detail": "missing"}],
            }
        else:
            verification = verify_release_attestation(attestation_path=attestation_path, bundle_path=bundle_path)
        import html as _html

        from redline.render import _I18N_SCRIPT, _inline_css, _lang_toggle, randomart_svg, t

        seed = str(verification.get("attestation_hash") or verification.get("bundle_hash") or "")
        seal = ""
        if seed:
            tone = "rl-seal--pass" if verification.get("ok") else "rl-seal--void"
            stamp = "VERIFIED" if verification.get("ok") else "VOID"
            short = _html.escape(seed[:26] + "…" if len(seed) > 26 else seed)
            seal = (
                f'<div class="rl-seal {tone}"><span class="rl-seal__art">{randomart_svg(seed)}</span>'
                f'<span class="rl-seal__body"><span class="rl-seal__stamp">{stamp}</span>'
                f'<span class="rl-seal__algo">SSH randomart &middot; attestation fingerprint</span>'
                f'<span class="rl-seal__hash">{short}</span></span></div>'
            )
        doc = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>Release Attestation</title><style>{_inline_css()}</style></head>'
            f'<body><main class="rl-main">{_lang_toggle()}<h1 class="rl-macro rl-caret">{t("Attestation", "认证")}</h1>'
            f'<p class="rl-label">{_html.escape(str(release_id))}</p>{seal}'
            f'{render_attestation_status_html(verification=verification)}</main>{_I18N_SCRIPT}</body></html>'
        )
        return HTMLResponse(doc)

    @router.get("/release-candidates/{release_id}/evidence.html", response_class=HTMLResponse)
    def release_evidence_html_endpoint(release_id: str) -> HTMLResponse:
        from redline.render import load_evidence_panel, render_evidence_panel_html

        release = _get_release_or_404(service, release_id)
        release_panel = load_evidence_panel(release_dir(service.config.root, release_id), title=f"Release {release_id}")
        if release_panel.invalid_reason_code is not None:
            return HTMLResponse(render_evidence_panel_html(release_panel))
        run = service.store.get_run(release.execution_run_id or release.run_id) if (release.execution_run_id or release.run_id) else None
        if run is not None:
            panel = load_evidence_panel(Path(run.out_dir), title=f"Release {release_id}")
        else:
            panel = release_panel
        html_doc = render_evidence_panel_html(panel)
        attestation_path = release_dir(service.config.root, release_id) / RELEASE_ATTESTATION_NAME
        if attestation_path.exists():
            try:
                _release, bundle_path, _manifest_path, _manifest_hash, _manifest = _ensure_release_evidence_bundle(service=service, release=release)
                status_html = render_attestation_status_html(verification=verify_release_attestation(attestation_path=attestation_path, bundle_path=bundle_path))
                html_doc = html_doc.replace("</main>", status_html + "</main>", 1)
            except (CanonicalizationError, ValueError):
                status_html = render_attestation_status_html(verification={"ok": False, "checks": [{"name": "attestation", "ok": False, "detail": "invalid"}]})
                html_doc = html_doc.replace("</main>", status_html + "</main>", 1)
        return HTMLResponse(html_doc)

    @router.get("/release-candidates/{release_id}/audit-ledger")
    def download_release_audit_ledger_endpoint(release_id: str):
        _get_release_or_404(service, release_id)
        from redline.service.release import load_release_audit_ledger

        ledger_path = release_dir(service.config.root, release_id) / "release-audit-ledger.jsonl"
        load_release_audit_ledger(ledger_path)
        return FileResponse(ledger_path, filename=ledger_path.name, media_type="application/jsonl")

    @router.get("/release-safety", response_model=ReleaseSafetyResponse)
    def release_safety_endpoint() -> ReleaseSafetyResponse:
        return ReleaseSafetyResponse(
            release_freeze=_release_freeze_enabled(),
            execution_freeze=_execution_freeze_enabled(),
            mainnet_orders_enabled=os.environ.get("REDLINE_ALLOW_MAINNET_ORDER") == "1",
        )

    @router.get("/judge/console", response_class=HTMLResponse, dependencies=[Depends(_require_scope(READ_ONLY))])
    def judge_console_endpoint(request: Request) -> HTMLResponse:
        principal = _current_principal(request)
        releases = [_judge_release_summary(service, release) for release in service.store.list_release_candidates(limit=50)]
        return HTMLResponse(
            render_judge_console_html(
                principal=principal.principal_id,
                safety=release_safety_endpoint().model_dump(mode="json"),
                releases=releases,
            )
        )

    @router.get("/judge/releases/{release_id}", response_class=HTMLResponse, dependencies=[Depends(_require_scope(READ_ONLY))])
    def judge_release_detail_endpoint(release_id: str, request: Request) -> HTMLResponse:
        principal = _current_principal(request)
        release = _get_release_or_404(service, release_id)
        jobs = [job.model_dump(mode="json") for job in service.store.list_release_jobs(release_id=release_id, limit=20)]
        latest_events: list[dict[str, object]] = []
        if jobs:
            latest_events = [event.model_dump(mode="json") for event in service.store.list_release_job_events(release_id=release_id, job_id=str(jobs[0]["job_id"]))]
        return HTMLResponse(
            render_judge_release_html(
                principal=principal.principal_id,
                safety=release_safety_endpoint().model_dump(mode="json"),
                release=release.model_dump(mode="json"),
                showcase_orders=_list_showcase_order_summaries(service=service, release_id=release_id),
                jobs=jobs,
                latest_events=latest_events,
                audit_entries=_release_audit_summary(service=service, release_id=release_id),
                bundle_status=_release_bundle_status(service=service, release_id=release_id),
                attestation_status=_release_attestation_status(service=service, release_id=release_id),
            )
        )

    @router.get("/verify", response_class=HTMLResponse)
    def verify_endpoint() -> HTMLResponse:
        # public, zero-secret, self-contained: offline tamper demo (no auth required)
        from redline.render import render_verify_html

        return HTMLResponse(render_verify_html())

    @router.post("/runs", response_model=RunResponse, status_code=202, dependencies=[Depends(_require_scope(RELEASE_WRITE))])
    def create_run_endpoint(payload: RunCreateRequest, request: Request) -> RunResponse:
        return service.create_run(request_id=request.state.request_id, request=payload)

    @router.get("/runs", response_model=RunListResponse)
    def list_runs_endpoint(limit: int = 50) -> RunListResponse:
        return RunListResponse(runs=service.store.list_runs(limit=max(1, min(limit, 100))))

    @router.get("/runs/{run_id}", response_model=RunResponse)
    def get_run_endpoint(run_id: str) -> RunResponse:
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return run

    @router.get("/runs/{run_id}/artifacts")
    def list_artifacts_endpoint(run_id: str):
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        if run.artifact_manifest is None:
            raise HTTPException(status_code=409, detail="run artifacts are not ready")
        return run.artifact_manifest

    @router.get("/runs/{run_id}/artifacts/{artifact_id:path}")
    def download_artifact_endpoint(run_id: str, artifact_id: str):
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        artifact = _artifact_manifest_entry(run, artifact_id)
        path = service.artifacts.resolve_download_path(run, artifact)
        if hash_file(path) != artifact.sha256:
            raise CanonicalizationError("artifact hash mismatch", ReasonCode.RECEIPT_MISMATCH)
        return FileResponse(path, filename=path.name)

    @router.post("/runs/{run_id}/sponsor-readback", response_model=SponsorResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def sponsor_readback_endpoint(run_id: str, payload: SponsorRequest) -> SponsorResponse:
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        if run.state.value not in {"pass", "amber"}:
            raise HTTPException(status_code=409, detail="run is not locally passable")
        receipt_path = Path(run.out_dir) / "receipt.json"
        preflight = publish_preflight(
            receipt_path=receipt_path,
            package=Path(run.package_path),
            suite_path=Path(run.suite_path),
            spec_path=Path(run.spec_path),
            out_dir=Path(run.out_dir) / "publish",
            allow_demo_baseline_genesis=payload.allow_demo_baseline_genesis,
        )
        if payload.mode.value == "preflight":
            manifest = run.artifact_manifest
            return SponsorResponse(
                run_id=run_id,
                ok=preflight.ok,
                state=preflight.state,
                reason_code=preflight.reason_code.value if preflight.reason_code else None,
                evidence=preflight.model_dump(mode="json"),
            )
        access_key = os.environ.get("REDLINE_BITGET_ACCESS_KEY") or os.environ.get("BITGET_ACCESS_KEY")
        secret_key = os.environ.get("REDLINE_BITGET_SECRET_KEY") or os.environ.get("BITGET_SECRET_KEY")
        passphrase = os.environ.get("REDLINE_BITGET_PASSPHRASE") or os.environ.get("BITGET_PASSPHRASE")
        if not preflight.ok:
            return SponsorResponse(
                run_id=run_id,
                ok=False,
                state=preflight.state,
                reason_code=preflight.reason_code.value if preflight.reason_code else ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
                evidence=preflight.model_dump(mode="json"),
            )
        if access_key is None or secret_key is None or passphrase is None:
            return SponsorResponse(
                run_id=run_id,
                ok=False,
                state="BITGET_CREDENTIALS_REQUIRED",
                reason_code=ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
                evidence={},
            )
        result = execute_sponsor_readback(
            receipt_path=receipt_path,
            package=Path(run.package_path),
            out_dir=Path(run.out_dir) / "publish",
            access_key=access_key,
            secret_key=secret_key,
            passphrase=passphrase,
            final_publish=payload.final_publish,
            suite_path=Path(run.suite_path),
            spec_path=Path(run.spec_path),
        )
        return SponsorResponse(
            run_id=run_id,
            ok=result.ok,
            state=result.state.value,
            reason_code=(result.reason_code or ReasonCode.PASS).value,
            evidence=result.evidence,
        )

    @router.post("/runs/{run_id}/execute", response_model=ExecutionResponse, dependencies=[Depends(_require_scope(EXECUTE_DEMO))])
    def execute_endpoint(run_id: str, payload: Annotated[ExecutionRequest | None, Body()] = None) -> ExecutionResponse:
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return _execute_bitget_demo_order(service=service, run=run, payload=payload or ExecutionRequest())

    for recovered_job in service.store.recover_interrupted_release_jobs():
        service.store.append_release_job_event(
            release_id=recovered_job.release_id,
            job_id=recovered_job.job_id,
            event_type="job_failed",
            payload={"reason_code": "JOB_RECOVERY_REQUIRED", "detail": "job was running when service started"},
        )
    _kick_release_jobs()

    app.include_router(router)
    return app


class SlidingWindowRateLimiter:
    def __init__(self, *, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


def main() -> None:
    config = ServiceConfig.from_env()
    uvicorn.run(create_app(config), host=config.host, port=config.port, reload=False, log_level=config.log_level.lower())


async def _require_token(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_redline_token: Annotated[str | None, Header(alias="X-Redline-Token")] = None,
) -> AuthPrincipal:
    service = request.app.state.redline_service
    supplied = x_redline_token
    if supplied is None and authorization and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    principal = _principal_for_token(service.config.service_tokens, supplied)
    if principal is None and supplied is None:
        principal = _principal_for_session_cookie(service, request.cookies.get(SESSION_COOKIE_NAME))
    if principal is None or not principal.has_scope(READ_ONLY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing or invalid Redline service token")
    service.check_rate_limit(supplied or f"session:{principal.principal_id}")
    request.state.auth_principal = principal
    return principal


def _require_scope(required_scope: str):
    def dependency(request: Request) -> AuthPrincipal:
        principal = _current_principal(request)
        if not principal.has_scope(required_scope):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Redline token lacks required scope: {required_scope}")
        return principal

    return dependency


def _principal_for_token(service_tokens, supplied: str | None) -> AuthPrincipal | None:
    if not supplied:
        return None
    for item in service_tokens:
        if secrets.compare_digest(supplied, item.token):
            return item.principal
    return None


def _principal_for_session_cookie(service: RedlineService, cookie: str | None) -> AuthPrincipal | None:
    if not cookie:
        return None
    return principal_from_session_cookie(cookie, secret=_auth_session_secret(service))


def _github_exchange_code(config: ServiceConfig, *, code: str) -> str:
    if not config.github_oauth_client_id or not config.github_oauth_client_secret:
        raise HTTPException(status_code=501, detail="GitHub OAuth client id/secret are not configured")
    payload: dict[str, str] = {
        "client_id": config.github_oauth_client_id,
        "client_secret": config.github_oauth_client_secret,
        "code": code,
    }
    if config.github_oauth_redirect_uri:
        payload["redirect_uri"] = config.github_oauth_redirect_uri
    request = urllib.request.Request(
        GITHUB_TOKEN_URL,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "redline-service"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            token_payload = json.loads(response.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=502, detail="GitHub OAuth token exchange failed") from exc
    if not isinstance(token_payload, dict) or not token_payload.get("access_token"):
        raise HTTPException(status_code=502, detail="GitHub OAuth token exchange returned no access token")
    return str(token_payload["access_token"])


def _github_fetch_user(access_token: str) -> dict[str, object]:
    request = urllib.request.Request(
        GITHUB_USER_URL,
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {access_token}", "User-Agent": "redline-service"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=502, detail="GitHub user lookup failed") from exc
    if not isinstance(payload, dict) or not payload.get("login"):
        raise HTTPException(status_code=502, detail="GitHub user lookup returned no login")
    return payload


def _github_principal_from_user(config: ServiceConfig, github_user: dict[str, object]) -> AuthPrincipal:
    login = str(github_user.get("login") or "")
    if not login:
        raise HTTPException(status_code=502, detail="GitHub user lookup returned no login")
    mapped = principal_from_auth_users(config.auth_users, login=login, auth_method="github_oauth")
    if mapped is not None:
        return mapped
    allowed = {item.strip() for item in config.github_oauth_allowed_logins if item.strip()}
    if allowed and login not in allowed:
        raise HTTPException(status_code=403, detail="GitHub login is not allowed for Redline")
    if not allowed:
        raise HTTPException(status_code=403, detail="GitHub login is not configured for Redline")
    return AuthPrincipal(
        principal_id=f"github:{login}",
        role="reviewer",
        scopes=frozenset({READ_ONLY, RELEASE_WRITE}),
        token_label="session",
        auth_method="github_oauth",
        subject=login,
        display_name=str(github_user.get("name") or login),
        email=str(github_user["email"]) if github_user.get("email") else None,
    )


def _auth_session_secret(service: RedlineService) -> str:
    return service.config.auth_session_secret or "redline-dev-session"


def _current_principal(request: Request) -> AuthPrincipal:
    principal = getattr(request.state, "auth_principal", None)
    if not isinstance(principal, AuthPrincipal):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing Redline principal")
    return principal


def _audit_actor(request: Request, fallback: str) -> str:
    try:
        return _current_principal(request).principal_id
    except HTTPException:
        return fallback


def _is_legacy_service_principal(principal: AuthPrincipal) -> bool:
    return (
        principal.auth_method == "service_token"
        and principal.token_label == "primary"
        and principal.principal_id == "service-token"
        and principal.role == "admin"
    )


def _principal_audit_payload(principal: AuthPrincipal) -> dict[str, object]:
    return {
        "principal_id": principal.principal_id,
        "actor": principal.principal_id,
        "auth_method": principal.auth_method,
        "auth_subject": principal.subject,
        "actor_display_name": principal.display_name,
        "actor_role": principal.role,
        "actor_scopes": sorted(principal.scopes),
    }


def _idempotency_replay(service: RedlineService, *, scope: str, key: str | None, payload: dict[str, object]) -> dict[str, object] | None:
    if not key:
        return None
    record = service.store.get_idempotency_record(scope=scope, key=key)
    if record is None:
        return None
    request_hash = hash_obj(payload)
    if record["request_hash"] != request_hash:
        raise HTTPException(status_code=409, detail="Idempotency-Key was reused with a different request body")
    return json.loads(record["response_json"])


def _idempotency_store(
    service: RedlineService,
    *,
    scope: str,
    key: str | None,
    payload: dict[str, object],
    response: dict[str, object],
    status_code: int,
) -> None:
    if not key:
        return
    service.store.put_idempotency_record(scope=scope, key=key, request_hash=hash_obj(payload), response=response, status_code=status_code)


def _error_response(request: Request, *, status_code: int, error_code: str, message: str) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "req_unknown")
    payload = ErrorEnvelope(request_id=request_id, error_code=error_code, message=message)
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"), headers={"x-request-id": request_id})


def _package_id(identity_hash: str) -> str:
    return "pkg_" + identity_hash.removeprefix("sha256:")[:24]


def _run_id(payload: object) -> str:
    return "run_" + hash_obj({"payload": payload, "nonce": uuid.uuid4().hex}).removeprefix("sha256:")[:24]


def _job_id(payload: object) -> str:
    return "job_" + hash_obj({"payload": payload, "nonce": uuid.uuid4().hex}).removeprefix("sha256:")[:24]


def _release_id(payload: object) -> str:
    return "rel_" + hash_obj({"payload": payload, "nonce": uuid.uuid4().hex}).removeprefix("sha256:")[:24]


def _approval_nonce() -> str:
    return "appr_" + hash_obj({"nonce": uuid.uuid4().hex}).removeprefix("sha256:")[:24]


def _approval_expires_at() -> str:
    raw_ttl_seconds = os.environ.get("REDLINE_APPROVAL_TTL_SECONDS", "900")
    try:
        ttl_seconds = max(1, int(raw_ttl_seconds))
    except ValueError:
        ttl_seconds = 900
    expires = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=ttl_seconds)
    return expires.isoformat().replace("+00:00", "Z")


def _approval_block_reason_for_execution(
    release: ReleaseCandidateResponse,
    *,
    strategy_version: StrategyVersionResponse,
    approval: dict[str, object] | None = None,
) -> str | None:
    approval = approval if approval is not None else release.approval
    if not isinstance(approval, dict) or approval.get("evidence_manifest_hash") != evidence_fingerprint(release, strategy_version=strategy_version):
        return "APPROVAL_EVIDENCE_CHANGED"
    if approval.get("consumed_at") is not None:
        return ReasonCode.APPROVAL_CONSUMED.value
    expires_at = approval.get("expires_at")
    if not isinstance(expires_at, str) or _is_expired_utc(expires_at):
        return ReasonCode.APPROVAL_EXPIRED.value
    if not isinstance(approval.get("nonce"), str) or not approval["nonce"]:
        return "APPROVAL_EVIDENCE_CHANGED"
    return None


def _current_showcase_approval(release: ReleaseCandidateResponse) -> tuple[dict[str, object] | None, str]:
    metadata_approval = release.metadata.get(SHOWCASE_APPROVAL_METADATA_KEY)
    if isinstance(metadata_approval, dict):
        return metadata_approval, "showcase"
    return release.approval, "release"


def _consume_current_approval(service: RedlineService, release: ReleaseCandidateResponse, *, approval_kind: str = "release") -> ReleaseCandidateResponse | None:
    approval = _current_showcase_approval(release)[0] if approval_kind == "showcase" else release.approval
    if not isinstance(approval, dict) or not isinstance(approval.get("nonce"), str):
        return None
    if approval_kind == "showcase":
        return service.store.consume_release_showcase_approval(release_id=release.release_id, nonce=approval["nonce"], consumed_at=utc_now())
    return service.store.consume_release_approval(release_id=release.release_id, nonce=approval["nonce"], consumed_at=utc_now())


def _is_expired_utc(value: str) -> bool:
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires <= datetime.now(UTC)


def _build_strategy_version(service: RedlineService, payload: StrategyVersionCreateRequest) -> StrategyVersionResponse:
    now = utc_now()
    package_id = payload.package_id
    package_path = payload.package_path
    package_hash = payload.package_hash
    identity_lock_hash = payload.identity_lock_hash
    if package_id is not None:
        package = service.store.get_package(package_id)
        if package is None:
            raise HTTPException(status_code=404, detail="package not found")
        package_path = package.path
        package_hash = package.identity_hash
        identity_lock_hash = package.identity_lock_hash
    elif package_path is not None:
        imported = import_package(Path(package_path), write_lock=False)
        if package_hash is not None and package_hash != imported.identity_hash:
            raise HTTPException(status_code=409, detail="strategy version package_hash does not match canonical package identity")
        package_path = str(imported.path)
        package_hash = imported.identity_hash
        identity_lock_hash = imported.identity_lock_hash
    if not package_hash:
        raise HTTPException(status_code=422, detail="strategy version requires package_id, package_path, or package_hash")
    return StrategyVersionResponse(
        version_id=payload.version_id,
        strategy_id=payload.strategy_id,
        package_id=package_id,
        package_path=package_path,
        package_hash=package_hash,
        identity_lock_hash=identity_lock_hash,
        source_kind=payload.source_kind,
        metadata=payload.metadata,
        created_by=payload.created_by,
        created_at=now,
        updated_at=now,
    )


def _get_release_or_404(service: RedlineService, release_id: str) -> ReleaseCandidateResponse:
    release = service.store.get_release_candidate(release_id)
    if release is None:
        raise HTTPException(status_code=404, detail="release candidate not found")
    return release


def _get_strategy_version_for_release_or_404(service: RedlineService, release: ReleaseCandidateResponse) -> StrategyVersionResponse:
    version = service.store.get_strategy_version(release.version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="strategy version not found")
    return version


def _state_for_bound_run(run: RunResponse) -> ReleaseState:
    if run.state in {RunState.QUEUED, RunState.RUNNING}:
        return ReleaseState.REDLINE_RUNNING
    if run.state == RunState.PASS and run.reason_code == ReasonCode.PASS.value and run.receipt_hash:
        return ReleaseState.REDLINE_PASSED
    if run.state in {RunState.FAIL, RunState.AMBER}:
        return ReleaseState.BLOCKED_WITHHELD
    return ReleaseState.BLOCKED_UNVERIFIED


def _release_has_redline_pass(release: ReleaseCandidateResponse) -> bool:
    return bool(release.run_id and release.redline_reason_code == ReasonCode.PASS.value and release.redline_receipt_hash)


def _normalize_simulation_upload(
    *,
    raw: bytes,
    filename: str,
    source: SimulationEvidenceSource,
    market: str,
    symbol: str,
) -> dict[str, object]:
    text = raw.decode("utf-8-sig")
    if filename.lower().endswith(".json"):
        payload = json.loads(text)
        return _normalize_simulation_json(payload, source=source, market=market, symbol=symbol)
    reader = csv.DictReader(io.StringIO(text))
    rows = [dict(row) for row in reader]
    return _normalize_trade_rows(rows, source=source, market=market, symbol=symbol, source_format="csv")


def _normalize_simulation_json(payload: object, *, source: SimulationEvidenceSource, market: str, symbol: str) -> dict[str, object]:
    if isinstance(payload, dict):
        if {"period_start", "period_end", "trade_count", "pnl", "max_drawdown", "win_rate"}.issubset(payload):
            return {
                "source": source.value,
                "period_start": str(payload["period_start"]),
                "period_end": str(payload["period_end"]),
                "market": str(payload.get("market") or market),
                "symbol": str(payload.get("symbol") or symbol),
                "trade_count": int(payload["trade_count"]),
                "pnl": str(payload["pnl"]),
                "max_drawdown": str(payload["max_drawdown"]),
                "win_rate": str(payload["win_rate"]),
                "sharpe_or_sortino": str(payload["sharpe_or_sortino"]) if payload.get("sharpe_or_sortino") is not None else None,
                "metadata": {"source_format": "json_summary"},
            }
        trades = payload.get("trades") or payload.get("orders") or payload.get("fills")
        if isinstance(trades, list):
            return _normalize_trade_rows([item for item in trades if isinstance(item, dict)], source=source, market=market, symbol=symbol, source_format="json_trades")
    if isinstance(payload, list):
        return _normalize_trade_rows([item for item in payload if isinstance(item, dict)], source=source, market=market, symbol=symbol, source_format="json_rows")
    raise HTTPException(status_code=422, detail="simulation JSON must be a summary object or trade rows")


def _normalize_trade_rows(
    rows: list[dict],
    *,
    source: SimulationEvidenceSource,
    market: str,
    symbol: str,
    source_format: str,
) -> dict[str, object]:
    if not rows:
        raise HTTPException(status_code=422, detail="simulation evidence file contains no rows")
    pnl_values = [_decimal_from_row(row, ("pnl", "profit", "realized_pnl", "net_pnl")) for row in rows]
    pnl_total = sum((value for value in pnl_values if value is not None), Decimal("0"))
    pnl_count = sum(1 for value in pnl_values if value is not None)
    wins = sum(1 for value in pnl_values if value is not None and value > 0)
    drawdowns = [_decimal_from_row(row, ("max_drawdown", "drawdown", "dd")) for row in rows]
    max_drawdown = max((abs(value) for value in drawdowns if value is not None), default=Decimal("0"))
    timestamps = sorted(value for row in rows for value in [_first_text(row, ("timestamp", "time", "date", "created_at"))] if value)
    inferred_symbol = _first_text(rows[0], ("symbol", "pair", "instrument")) or symbol
    trade_count = pnl_count if pnl_count else len(rows)
    win_rate = Decimal(wins) / Decimal(trade_count) if trade_count else Decimal("0")
    return {
        "source": source.value,
        "period_start": timestamps[0] if timestamps else "uploaded-file",
        "period_end": timestamps[-1] if timestamps else "uploaded-file",
        "market": market,
        "symbol": inferred_symbol,
        "trade_count": trade_count,
        "pnl": _decimal_str(pnl_total),
        "max_drawdown": _decimal_str(max_drawdown),
        "win_rate": _decimal_str(win_rate),
        "metadata": {"source_format": source_format, "row_count": len(rows)},
    }


def _decimal_from_row(row: dict, keys: tuple[str, ...]) -> Decimal | None:
    raw = _first_text(row, keys)
    if raw is None:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    return value if value.is_finite() else None


def _first_text(row: dict, keys: tuple[str, ...]) -> str | None:
    lowered = {str(key).strip().lower(): value for key, value in row.items()}
    for key in keys:
        value = lowered.get(key)
        if value not in {None, ""}:
            return str(value)
    return None


def _decimal_str(value: Decimal) -> str:
    normalized = value.quantize(Decimal("0.00000001")).normalize()
    return format(normalized, "f")


def _assert_release_not_terminal(release: ReleaseCandidateResponse) -> None:
    if is_terminal_release_state(release.state):
        raise HTTPException(status_code=409, detail=f"release candidate is terminal: {release.state.value}")


def _transition_release_or_409(release: ReleaseCandidateResponse, to_state: ReleaseState, *, updates: dict[str, object] | None = None) -> ReleaseCandidateResponse:
    try:
        return _with_computed_release_tier(transition_release(release, to_state, updates=updates))
    except ReleaseTransitionMissingEvidenceError as exc:
        blocked_updates = {
            **(updates or {}),
            "state": ReleaseState.BLOCKED_MISSING_EVIDENCE,
            "metadata": {**release.metadata, "missing_evidence": list(exc.missing)},
        }
        return _with_computed_release_tier(release.model_copy(update=blocked_updates))
    except ReleaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _with_computed_release_tier(release: ReleaseCandidateResponse) -> ReleaseCandidateResponse:
    decision = compute_release_tier(release)
    return release.model_copy(update={"release_tier": decision.tier})


def _required_release_evidence_missing(release: ReleaseCandidateResponse) -> list[str]:
    if release.risk_policy is None:
        return []
    missing: list[str] = []
    if bool(release.risk_policy.get("require_human_approval", True)) and release.approval is None:
        missing.append("human_approval")
    if bool(release.risk_policy.get("require_demo_execution", True)) and (release.execution_evidence is None or release.execution_run_id is None):
        missing.append("demo_execution")
    return missing


def _missing_release_evidence_response(release: ReleaseCandidateResponse, missing: list[str]) -> ReleaseActionResponse:
    return ReleaseActionResponse(
        release_id=release.release_id,
        ok=False,
        state=ReleaseState.BLOCKED_MISSING_EVIDENCE,
        reason_code="BLOCKED_MISSING_EVIDENCE",
        evidence={"missing": missing},
    )


def _approval_block_reason(service: RedlineService, release: ReleaseCandidateResponse) -> str | None:
    if release.state in {
        ReleaseState.KILLED,
        ReleaseState.REJECTED,
        ReleaseState.BLOCKED_WITHHELD,
        ReleaseState.BLOCKED_UNVERIFIED,
        ReleaseState.BLOCKED_RISK_POLICY,
        ReleaseState.BLOCKED_EXCHANGE_ERROR,
    }:
        return release.state.value.upper()
    if release.run_id is None:
        return "RUN_REQUIRED"
    run = service.store.get_run(release.run_id)
    if run is None:
        return "RUN_NOT_FOUND"
    if _state_for_bound_run(run) != ReleaseState.REDLINE_PASSED:
        return "REDLINE_VERIFIED_PASS_REQUIRED"
    if release.redline_receipt_hash != run.receipt_hash or not release.redline_receipt_hash:
        return "REDLINE_RECEIPT_REQUIRED"
    if release.risk_policy is None or release.risk_policy_hash is None:
        return "RISK_POLICY_REQUIRED"
    risk_decision = risk_policy_breach(release.risk_policy)
    if risk_decision.blocked:
        return "RISK_POLICY_BREACH"
    if release.risk_policy.get("require_simulation_evidence", True) and release.simulation_evidence is None:
        return "SIMULATION_EVIDENCE_REQUIRED"
    return None


def _release_blocked(release: ReleaseCandidateResponse, reason_code: str) -> ReleaseActionResponse:
    return ReleaseActionResponse(release_id=release.release_id, ok=False, state=release.state, reason_code=reason_code)


def _apply_risk_policy_decision(execution_request: ExecutionRequest, decision: RiskPolicyDecision) -> ExecutionRequest:
    if not decision.reduced or decision.adjusted_size is None:
        return execution_request
    return execution_request.model_copy(update={"size": decision.adjusted_size})


def _list_showcase_order_summaries(*, service: RedlineService, release_id: str) -> list[dict[str, object]]:
    attempts_root = release_dir(service.config.root, release_id) / SHOWCASE_ORDERS_DIR
    attempts: list[dict[str, object]] = []
    if attempts_root.exists():
        for attempt_dir in sorted(item for item in attempts_root.iterdir() if item.is_dir()):
            attempt_id = attempt_dir.name
            try:
                evidence = _load_showcase_execution_evidence(service=service, release_id=release_id, attempt_id=attempt_id)
                attempts.append(
                    {
                        "attempt_id": attempt_id,
                        "ok": True,
                        "bitget_order_id": evidence.bitget_order_id,
                        "client_oid": evidence.client_oid,
                        "placed_at": evidence.placed_at,
                        "symbol": evidence.symbol,
                        "product_type": evidence.product_type,
                        "order_mode": evidence.order_mode,
                        "paptrading": evidence.paptrading,
                        "artifact_hash": evidence.artifact_hash,
                        "evidence_html_url": f"/v1/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html",
                    }
                )
            except ExecutionBlocked as exc:
                attempts.append({"attempt_id": attempt_id, "ok": False, "reason_code": exc.reason_code})
    return attempts


def _judge_release_summary(service: RedlineService, release: ReleaseCandidateResponse) -> dict[str, object]:
    jobs = service.store.list_release_jobs(release_id=release.release_id, limit=1)
    execution = release.execution_evidence or {}
    return {
        "release_id": release.release_id,
        "state": release.state.value,
        "canonical_order_id": execution.get("bitget_order_id") if isinstance(execution, dict) else None,
        "showcase_count": len(_list_showcase_order_summaries(service=service, release_id=release.release_id)),
        "attestation_status": _release_attestation_status(service=service, release_id=release.release_id)["status"],
        "latest_job_status": jobs[0].status.value if jobs else None,
    }


def _release_bundle_status(*, service: RedlineService, release_id: str) -> dict[str, object]:
    bundle_path = release_dir(service.config.root, release_id) / BUNDLE_NAME
    if not bundle_path.exists():
        return {"ok": False, "status": "missing", "detail": "bundle missing"}
    try:
        verification = verify_release_evidence_bundle(bundle_path)
    except (CanonicalizationError, ValueError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "status": "invalid", "detail": str(exc)}
    return {
        "ok": bool(verification.get("ok")),
        "status": "verified" if verification.get("ok") else "invalid",
        "hash": str(verification.get("bundle_hash") or ""),
        "detail": str(verification.get("bundle_hash") or ""),
    }


def _release_attestation_status(*, service: RedlineService, release_id: str) -> dict[str, object]:
    out_dir = release_dir(service.config.root, release_id)
    attestation_path = out_dir / RELEASE_ATTESTATION_NAME
    bundle_path = out_dir / BUNDLE_NAME
    if not attestation_path.exists():
        return {"ok": False, "status": "missing", "detail": "attestation missing"}
    if not bundle_path.exists():
        return {"ok": False, "status": "invalid", "detail": "bundle missing"}
    try:
        verification = verify_release_attestation(attestation_path=attestation_path, bundle_path=bundle_path)
    except (CanonicalizationError, ValueError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "status": "invalid", "detail": str(exc)}
    return {
        "ok": bool(verification.get("ok")),
        "status": "ATTESTED" if verification.get("ok") else "invalid",
        "hash": str(verification.get("attestation_hash") or ""),
        "detail": str(verification.get("attestation_hash") or verification.get("bundle_hash") or ""),
    }


def _release_audit_summary(*, service: RedlineService, release_id: str) -> list[dict[str, object]]:
    try:
        return load_release_audit_ledger(release_dir(service.config.root, release_id) / AUDIT_LEDGER_NAME)
    except (CanonicalizationError, ValueError, OSError, json.JSONDecodeError) as exc:
        return [{"event_type": "audit_invalid", "created_at": utc_now(), "payload": {"reason_code": str(exc)}}]


def _ensure_release_evidence_bundle(
    *,
    service: RedlineService,
    release: ReleaseCandidateResponse,
) -> tuple[ReleaseCandidateResponse, Path, Path, str, dict[str, object]]:
    version = service.store.get_strategy_version(release.version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="strategy version not found")
    tier_decision = compute_release_tier(release, strategy_version=version)
    if release.release_tier != tier_decision.tier:
        release = service.store.update_release_candidate(release.model_copy(update={"release_tier": tier_decision.tier}))
    run = service.store.get_run(release.run_id) if release.run_id else None
    out_dir = release_dir(service.config.root, release.release_id)
    bundle_path = out_dir / BUNDLE_NAME
    manifest_path = out_dir / MANIFEST_NAME
    if release.evidence_manifest_hash and bundle_path.exists() and manifest_path.exists():
        verify_release_file(manifest_path, release.evidence_manifest_hash)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        bundle_hash = _manifest_file_hash(manifest, BUNDLE_NAME)
        verify_release_file(bundle_path, bundle_hash)
        return release, bundle_path, manifest_path, release.evidence_manifest_hash, manifest
    bundle_path, manifest_path, manifest_hash, manifest = generate_release_evidence_bundle(
        root=service.config.root,
        release=release,
        strategy_version=version,
        run=run,
    )
    updated = service.store.update_release_candidate(release.model_copy(update={"evidence_manifest": manifest, "evidence_manifest_hash": manifest_hash}))
    verify_release_file(bundle_path, _manifest_file_hash(manifest, BUNDLE_NAME))
    return updated, bundle_path, manifest_path, manifest_hash, manifest


def _release_freeze_enabled() -> bool:
    return os.environ.get("REDLINE_RELEASE_FREEZE") == "1"


def _execution_freeze_enabled() -> bool:
    return os.environ.get("REDLINE_EXECUTION_FREEZE") == "1"


def _manifest_file_hash(manifest: dict[str, object], rel_path: str) -> str:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise CanonicalizationError("release evidence manifest is invalid", ReasonCode.SCHEMA_INVALID)
    for item in files:
        if isinstance(item, dict) and item.get("path") == rel_path and isinstance(item.get("sha256"), str):
            return str(item["sha256"])
    raise CanonicalizationError("release evidence manifest is missing file hash", ReasonCode.DATA_MISSING)


def _mask_identifier(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


def _artifact_manifest_entry(run: RunResponse, artifact_id: str) -> ArtifactInfo:
    if run.artifact_manifest is None:
        raise HTTPException(status_code=409, detail="run artifacts are not ready")
    for artifact in run.artifact_manifest.artifacts:
        if artifact.artifact_id == artifact_id:
            return artifact
    raise HTTPException(status_code=404, detail="artifact not found")


def _configure_logging(config: ServiceConfig) -> None:
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _verified_demo_execution_context(*, run: RunResponse, payload: ExecutionRequest) -> VerifiedDemoExecution | ExecutionResponse:
    if run.state != RunState.PASS:
        return _execution_blocked(run.run_id, run.reason_code or "RUN_NOT_PASS", {"run_state": run.state.value})
    receipt_path = Path(run.out_dir) / "receipt.json"
    trust_policy_raw = payload.trust_policy_path or run.baseline_trust_policy_path or os.environ.get("REDLINE_TRUST_POLICY")
    if not trust_policy_raw:
        return _execution_blocked(run.run_id, ReasonCode.BASELINE_UNCHAINED.value, {"detail": "trust policy is required"})
    trust_policy_path = Path(trust_policy_raw)
    result = verify(
        receipt_path=receipt_path,
        package=Path(run.package_path),
        level=VerificationLevel.REPLAYED,
        suite_path=Path(run.suite_path),
        spec_path=Path(run.spec_path),
        trust_policy_path=trust_policy_path,
        baseline_receipt_path=Path(run.baseline_receipt_path) if run.baseline_receipt_path else None,
    )
    if result.status != VerificationStatus.VERIFIED or result.reason_code != ReasonCode.PASS:
        return _execution_blocked(
            run.run_id,
            result.reason_code.value,
            {"verification_status": result.status.value, "verification_level": result.verification_level.value},
        )
    if result.chain_status.value != "chained":
        return _execution_blocked(run.run_id, ReasonCode.BASELINE_UNCHAINED.value, {"chain_status": result.chain_status.value})
    if run.receipt_hash is None or result.receipt_hash != run.receipt_hash:
        return _execution_blocked(run.run_id, ReasonCode.RECEIPT_MISMATCH.value, {"receipt_hash": result.receipt_hash or ""})

    symbol = payload.symbol or os.environ.get("REDLINE_BITGET_DEMO_SYMBOL", DEFAULT_DEMO_SYMBOL)
    product_type = payload.product_type or os.environ.get("REDLINE_BITGET_PRODUCT_TYPE", DEFAULT_PRODUCT_TYPE)
    try:
        intent = default_execution_intent(
            symbol=symbol,
            product_type=product_type,
            margin_coin=payload.margin_coin,
            size=payload.size,
            side=payload.side,
            trade_side=payload.trade_side,
            order_type=payload.order_type,
            force=payload.force,
            price=payload.price,
            confirm_mainnet_order=payload.confirm_mainnet_order,
        )
    except ValueError as exc:
        return _execution_blocked(run.run_id, ReasonCode.SCHEMA_INVALID.value, {"detail": str(exc)})
    return VerifiedDemoExecution(
        intent=intent,
        receipt_hash=run.receipt_hash,
        chain_status=result.chain_status.value,
        strength_summary=result.strength_summary,
    )


def _place_verified_bitget_demo_order(
    *,
    service: RedlineService,
    run: RunResponse,
    context: VerifiedDemoExecution,
    client_oid: str,
    out_dir: Path,
    evidence_path: Path,
    ledger_path: Path,
    approval_hash: str = UNAPPROVED_APPROVAL_HASH,
) -> tuple[ExecutionEvidence, BitgetExchangePreflightEvidence, BitgetOrderStatusEvidence]:
    credentials = _demo_execution_credentials()
    if credentials is None:
        raise ExecutionBlocked("BITGET_DEMO_CREDENTIALS_REQUIRED", "Bitget demo credentials are required")
    paptrading = os.environ.get("REDLINE_BITGET_PAPTRADING", "1")
    base_url = os.environ.get("REDLINE_BITGET_BASE_URL", DEFAULT_BASE_URL)
    allow_mainnet = os.environ.get("REDLINE_ALLOW_MAINNET_ORDER") == "1"
    adapter = BitgetDemoExecutionAdapter(
        credentials=credentials,
        base_url=base_url,
        paptrading=paptrading,
        transport=service.execution_transport,
        allow_mainnet_order=allow_mainnet,
    )
    preflight = adapter.preflight_exchange(run_id=run.run_id, receipt_hash=context.receipt_hash, intent=context.intent, client_oid=client_oid)
    write_exchange_preflight_evidence(out_dir / "exchange-preflight-evidence.json", preflight)
    if not preflight.ok:
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_FAILED", "Bitget exchange preflight failed")
    order = adapter.place_order(intent=context.intent, receipt_hash=context.receipt_hash, client_oid=client_oid, cancelled=lambda: service.closing)
    evidence = write_execution_evidence_artifacts(
        run_id=run.run_id,
        evidence_path=evidence_path,
        ledger_path=ledger_path,
        receipt_hash=context.receipt_hash,
        verdict=RedlineStatus.PASS,
        intent=context.intent,
        order=order,
        order_mode="mainnet" if paptrading != "1" else "demo",
        paptrading=paptrading if paptrading == "1" else None,
        issuance_artifact_dir=Path(run.out_dir),
        approval_hash=approval_hash,
    )
    order_status = adapter.query_order_status(
        run_id=run.run_id,
        receipt_hash=context.receipt_hash,
        intent=context.intent,
        client_oid=client_oid,
        bitget_order_id=order.bitget_order_id,
    )
    write_order_status_evidence(out_dir / "order-status-evidence.json", order_status)
    if order_status.status == "unknown_reconciliation_required":
        raise ExecutionBlocked("EXCHANGE_RECONCILIATION_REQUIRED", "Bitget order status could not be reconciled")
    return evidence, preflight, order_status


def _execute_bitget_demo_order(
    *,
    service: RedlineService,
    run: RunResponse,
    payload: ExecutionRequest,
    approval_hash: str = UNAPPROVED_APPROVAL_HASH,
) -> ExecutionResponse:
    context = _verified_demo_execution_context(run=run, payload=payload)
    if isinstance(context, ExecutionResponse):
        return context
    client_oid = make_client_oid(receipt_hash=context.receipt_hash, intent=context.intent)
    out_dir = Path(run.out_dir)
    with service.execution_lock:
        evidence_path = out_dir / "execution-evidence.json"
        if evidence_path.exists():
            try:
                evidence = load_execution_evidence(evidence_path)
            except ExecutionBlocked as exc:
                return _execution_blocked(run.run_id, exc.reason_code, {"detail": exc.message})
            if evidence.receipt_hash != context.receipt_hash or evidence.client_oid != client_oid:
                return _execution_blocked(run.run_id, "EXECUTION_EVIDENCE_MISMATCH", {"detail": "run already has different execution evidence"})
            if approval_hash != UNAPPROVED_APPROVAL_HASH and evidence.approval_hash != approval_hash:
                return _execution_blocked(run.run_id, "EXECUTION_EVIDENCE_MISMATCH", {"detail": "execution evidence is not bound to current approval"})
            status_path = out_dir / "order-status-evidence.json"
            if status_path.exists():
                try:
                    order_status = load_order_status_evidence(status_path)
                except ExecutionBlocked as exc:
                    return _execution_blocked(run.run_id, exc.reason_code, {"detail": exc.message})
                if order_status.status == "unknown_reconciliation_required":
                    return _execution_blocked(run.run_id, "EXCHANGE_RECONCILIATION_REQUIRED", {"order_status_hash": order_status.evidence_hash})
            manifest = build_artifact_manifest(run.run_id, out_dir)
            service.store.update_artifact_manifest(run_id=run.run_id, artifact_manifest=manifest)
            return ExecutionResponse(run_id=run.run_id, ok=True, state="already_placed", evidence=evidence.model_dump(mode="json"))
        try:
            if execution_ledger_has_order(path=out_dir / "execution-ledger.jsonl", receipt_hash=context.receipt_hash, client_oid=client_oid):
                return _execution_blocked(run.run_id, "EXECUTION_EVIDENCE_MISSING", {"detail": "execution ledger exists without evidence artifact"})
        except ExecutionBlocked as exc:
            return _execution_blocked(run.run_id, exc.reason_code, {"detail": exc.message})

        try:
            evidence, preflight, order_status = _place_verified_bitget_demo_order(
                service=service,
                run=run,
                context=context,
                client_oid=client_oid,
                out_dir=out_dir,
                evidence_path=out_dir / "execution-evidence.json",
                ledger_path=out_dir / "execution-ledger.jsonl",
                approval_hash=approval_hash,
            )
        except ExecutionBlocked as exc:
            return _execution_blocked(run.run_id, exc.reason_code, {"detail": exc.message})
        manifest = build_artifact_manifest(run.run_id, out_dir)
        service.store.update_artifact_manifest(run_id=run.run_id, artifact_manifest=manifest)
        payload_json = evidence.model_dump(mode="json")
        payload_json.update({"preflight_hash": preflight.preflight_hash, "order_status_hash": order_status.evidence_hash, "order_status": order_status.status})
        return ExecutionResponse(run_id=run.run_id, ok=True, state="placed", evidence=payload_json)


def _execute_bitget_demo_showcase_order(
    *,
    service: RedlineService,
    release_id: str,
    run: RunResponse,
    payload: ExecutionRequest,
    approval_hash: str = UNAPPROVED_APPROVAL_HASH,
) -> ExecutionResponse:
    context = _verified_demo_execution_context(run=run, payload=payload)
    if isinstance(context, ExecutionResponse):
        return context
    attempt_id = _showcase_attempt_id(release_id=release_id, run_id=run.run_id)
    client_oid = make_showcase_client_oid(receipt_hash=context.receipt_hash, intent=context.intent, attempt_id=attempt_id)
    out_dir = release_dir(service.config.root, release_id) / SHOWCASE_ORDERS_DIR / attempt_id
    evidence_path = out_dir / "execution-evidence.json"
    ledger_path = release_dir(service.config.root, release_id) / SHOWCASE_LEDGER_NAME
    html_path = out_dir / "evidence.html"

    with service.execution_lock:
        try:
            evidence, preflight, order_status = _place_verified_bitget_demo_order(
                service=service,
                run=run,
                context=context,
                client_oid=client_oid,
                out_dir=out_dir,
                evidence_path=evidence_path,
                ledger_path=ledger_path,
                approval_hash=approval_hash,
            )
            from redline.render import render_execution_evidence_html, write_evidence_html

            write_evidence_html(
                html_path,
                render_execution_evidence_html(
                    evidence=evidence,
                    verdict="PASS",
                    reason_code=ReasonCode.PASS.value,
                    chain_status=context.chain_status,
                    strength_summary=context.strength_summary,
                    receipt_hash=context.receipt_hash,
                    title=f"Release {release_id} · showcase {attempt_id}",
                ),
            )
        except ExecutionBlocked as exc:
            return _execution_blocked(run.run_id, exc.reason_code, {"detail": exc.message})

    payload_json = evidence.model_dump(mode="json")
    payload_json.update(
        {
            "attempt_id": attempt_id,
            "evidence_path": str(evidence_path),
            "evidence_html_path": str(html_path),
            "evidence_html_url": f"/v1/release-candidates/{release_id}/demo-showcase-orders/{attempt_id}/evidence.html",
            "preflight_hash": preflight.preflight_hash,
            "preflight_evidence_path": str(out_dir / "exchange-preflight-evidence.json"),
            "order_status": order_status.status,
            "order_status_hash": order_status.evidence_hash,
            "order_status_evidence_path": str(out_dir / "order-status-evidence.json"),
            "showcase": True,
        }
    )
    return ExecutionResponse(run_id=run.run_id, ok=True, state="showcase_placed", evidence=payload_json)


def _showcase_attempt_id(*, release_id: str, run_id: str) -> str:
    digest = hash_obj({"release_id": release_id, "run_id": run_id, "nonce": uuid.uuid4().hex}).removeprefix("sha256:")
    return "show_" + digest[:24]


def _showcase_attempt_dir(*, service: RedlineService, release_id: str, attempt_id: str) -> Path:
    if not attempt_id or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-." for char in attempt_id.lower()) or "/" in attempt_id or "\\" in attempt_id:
        raise ExecutionBlocked("SHOWCASE_ATTEMPT_INVALID", "showcase attempt id is invalid")
    return release_dir(service.config.root, release_id) / SHOWCASE_ORDERS_DIR / attempt_id


def _load_showcase_execution_evidence(*, service: RedlineService, release_id: str, attempt_id: str):
    attempt_dir = _showcase_attempt_dir(service=service, release_id=release_id, attempt_id=attempt_id)
    evidence_path = attempt_dir / "execution-evidence.json"
    if not evidence_path.exists():
        raise ExecutionBlocked("SHOWCASE_EVIDENCE_MISSING", "showcase execution evidence is missing")
    evidence = load_execution_evidence(evidence_path)
    ledger_entries = load_execution_ledger(release_dir(service.config.root, release_id) / SHOWCASE_LEDGER_NAME)
    match = next((entry for entry in ledger_entries if entry.entry_hash == evidence.execution_ledger_entry_hash), None)
    if match is None:
        raise ExecutionBlocked("EXECUTION_LEDGER_MISMATCH", "showcase execution ledger entry not found")
    if (
        match.run_id != evidence.run_id
        or match.receipt_hash != evidence.receipt_hash
        or match.client_oid != evidence.client_oid
        or match.bitget_order_id != evidence.bitget_order_id
        or match.response_hash != evidence.response_hash
    ):
        raise ExecutionBlocked("EXECUTION_EVIDENCE_MISMATCH", "showcase execution evidence does not match ledger")
    return evidence


def _demo_execution_credentials() -> BitgetCredentials | None:
    access_key = os.environ.get("REDLINE_BITGET_DEMO_ACCESS_KEY")
    secret_key = os.environ.get("REDLINE_BITGET_DEMO_SECRET_KEY")
    passphrase = os.environ.get("REDLINE_BITGET_DEMO_PASSPHRASE")
    if not access_key or not secret_key or not passphrase:
        return None
    return BitgetCredentials(access_key=access_key, secret_key=secret_key, passphrase=passphrase)


def _execution_blocked(run_id: str, reason_code: str, evidence: dict[str, str]) -> ExecutionResponse:
    return ExecutionResponse(run_id=run_id, ok=False, state="blocked", reason_code=reason_code, evidence=evidence)
