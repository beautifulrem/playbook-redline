from __future__ import annotations

import logging
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, File, Header, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from redline.canonical import CanonicalizationError, hash_file, hash_obj
from redline.io_safety import ensure_safe_output_dir
from redline.models import ReasonCode
from redline.service.artifacts import extract_package_archive, save_upload_stream
from redline.service.config import ServiceConfig
from redline.service.models import (
    ArtifactInfo,
    ErrorEnvelope,
    HealthResponse,
    PackageImportRequest,
    PackageResponse,
    RunCreateRequest,
    RunListResponse,
    RunResponse,
    SponsorRequest,
    SponsorResponse,
)
from redline.service.storage import ArtifactStore, RunMetadataStore, create_artifact_store, create_metadata_store
from redline.service.store import utc_now
from redline.service.worker import execute_run
from redline.surfaces import execute_sponsor_readback, import_package, publish_preflight


LOGGER = logging.getLogger("redline.service")


class RedlineService:
    def __init__(self, config: ServiceConfig) -> None:
        self.config = config
        _configure_logging(config)
        ensure_safe_output_dir(config.root)
        self.artifacts: ArtifactStore = create_artifact_store(config)
        ensure_safe_output_dir(self.artifacts.packages_dir)
        ensure_safe_output_dir(self.artifacts.runs_dir)
        self.store: RunMetadataStore = create_metadata_store(config)
        self.executor = ThreadPoolExecutor(max_workers=config.workers, thread_name_prefix="redline-run")
        LOGGER.info(
            "redline service configured",
            extra={
                "environment": config.environment,
                "metadata_store": config.metadata_store,
                "artifact_store": config.artifact_store,
                "workers": config.workers,
            },
        )

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=False)

    def import_local_package(self, request: PackageImportRequest) -> PackageResponse:
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
        self.executor.submit(
            execute_run,
            store=self.store,
            run_id=run_id,
            request=request,
            package_path=package_path,
            out_dir=out_dir,
            expose_error_details=self.config.expose_error_details,
        )
        return run

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

    router = APIRouter(prefix="/v1", dependencies=[Depends(_require_token)], tags=["redline"])

    @router.post("/packages/import", response_model=PackageResponse, status_code=201)
    def import_package_endpoint(payload: PackageImportRequest, request: Request) -> PackageResponse:
        _ = request
        return service.import_local_package(payload)

    @router.post("/packages/upload", response_model=PackageResponse, status_code=201)
    async def upload_package_endpoint(
        request: Request,
        archive: Annotated[UploadFile, File(description="Canonical playbook package archive as .tar.gz")],
    ) -> PackageResponse:
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

    @router.post("/runs", response_model=RunResponse, status_code=202)
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

    @router.post("/runs/{run_id}/sponsor-readback", response_model=SponsorResponse)
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

    app.include_router(router)
    return app


def main() -> None:
    config = ServiceConfig.from_env()
    uvicorn.run(create_app(config), host=config.host, port=config.port, reload=False, log_level=config.log_level.lower())


async def _require_token(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_redline_token: Annotated[str | None, Header(alias="X-Redline-Token")] = None,
) -> None:
    expected = request.app.state.redline_service.config.token
    supplied = x_redline_token
    if supplied is None and authorization and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if not expected or not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing or invalid Redline service token")


def _error_response(request: Request, *, status_code: int, error_code: str, message: str) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "req_unknown")
    payload = ErrorEnvelope(request_id=request_id, error_code=error_code, message=message)
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"), headers={"x-request-id": request_id})


def _package_id(identity_hash: str) -> str:
    return "pkg_" + identity_hash.removeprefix("sha256:")[:24]


def _run_id(payload: object) -> str:
    return "run_" + hash_obj({"payload": payload, "nonce": uuid.uuid4().hex}).removeprefix("sha256:")[:24]


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
