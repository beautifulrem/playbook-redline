from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


ServiceEnvironment = Literal["local", "ci", "production"]
MetadataStoreKind = Literal["sqlite", "postgres"]
ArtifactStoreKind = Literal["local"]


@dataclass(frozen=True)
class ServiceConfig:
    root: Path = Path("artifacts/service")
    token: str = "redline-demo"
    max_upload_bytes: int = 50 * 1024 * 1024
    workers: int = 2
    environment: ServiceEnvironment = "local"
    host: str = "127.0.0.1"
    port: int = 8080
    cors_origins: tuple[str, ...] = ()
    log_level: str = "INFO"
    metadata_store: MetadataStoreKind = "sqlite"
    artifact_store: ArtifactStoreKind = "local"
    database_url: str | None = None
    expose_error_details: bool = True
    request_rate_limit_per_minute: int = 120
    max_packages: int = 100
    max_active_runs: int = 8
    max_runs_total: int = 500
    run_retention_seconds: int = 7 * 24 * 60 * 60

    def __post_init__(self) -> None:
        if self.environment not in {"local", "ci", "production"}:
            raise ValueError("REDLINE_SERVICE_ENV must be one of local, ci, production")
        if self.max_upload_bytes <= 0:
            raise ValueError("REDLINE_SERVICE_MAX_UPLOAD_BYTES must be positive")
        if self.workers <= 0:
            raise ValueError("REDLINE_SERVICE_WORKERS must be positive")
        if not (1 <= self.port <= 65535):
            raise ValueError("REDLINE_SERVICE_PORT must be between 1 and 65535")
        if self.metadata_store not in {"sqlite", "postgres"}:
            raise ValueError("REDLINE_SERVICE_METADATA_STORE must be sqlite or postgres")
        if self.metadata_store == "postgres" and not self.database_url:
            raise ValueError("REDLINE_DATABASE_URL or DATABASE_URL is required when REDLINE_SERVICE_METADATA_STORE=postgres")
        if self.artifact_store != "local":
            raise ValueError("only local artifact store is implemented")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("REDLINE_SERVICE_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        for name, value in {
            "REDLINE_SERVICE_RATE_LIMIT_PER_MINUTE": self.request_rate_limit_per_minute,
            "REDLINE_SERVICE_MAX_PACKAGES": self.max_packages,
            "REDLINE_SERVICE_MAX_ACTIVE_RUNS": self.max_active_runs,
            "REDLINE_SERVICE_MAX_RUNS_TOTAL": self.max_runs_total,
            "REDLINE_SERVICE_RUN_RETENTION_SECONDS": self.run_retention_seconds,
        }.items():
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.environment == "production":
            if self.token in {"", "redline-demo", "redline-smoke", "test-token"} or len(self.token) < 32:
                raise ValueError("production service requires a non-default REDLINE_SERVICE_TOKEN with at least 32 characters")
            if "*" in self.cors_origins:
                raise ValueError("production CORS origins must be explicit")

    @classmethod
    def from_env(cls) -> ServiceConfig:
        environment = os.environ.get("REDLINE_SERVICE_ENV", "local").strip().lower()
        expose_default = "false" if environment == "production" else "true"
        return cls(
            root=Path(os.environ.get("REDLINE_SERVICE_ROOT", "artifacts/service")),
            token=os.environ.get("REDLINE_SERVICE_TOKEN", "redline-demo"),
            max_upload_bytes=_parse_positive_int("REDLINE_SERVICE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024),
            workers=_parse_positive_int("REDLINE_SERVICE_WORKERS", 2),
            environment=environment,  # type: ignore[arg-type]
            host=os.environ.get("REDLINE_SERVICE_HOST", "127.0.0.1"),
            port=_parse_port("REDLINE_SERVICE_PORT", 8080),
            cors_origins=_parse_csv("REDLINE_SERVICE_CORS_ORIGINS"),
            log_level=os.environ.get("REDLINE_SERVICE_LOG_LEVEL", "INFO").upper(),
            metadata_store=os.environ.get("REDLINE_SERVICE_METADATA_STORE", "sqlite"),  # type: ignore[arg-type]
            artifact_store=os.environ.get("REDLINE_SERVICE_ARTIFACT_STORE", "local"),  # type: ignore[arg-type]
            database_url=os.environ.get("REDLINE_DATABASE_URL") or os.environ.get("DATABASE_URL"),
            expose_error_details=_parse_bool("REDLINE_SERVICE_EXPOSE_ERROR_DETAILS", expose_default),
            request_rate_limit_per_minute=_parse_nonnegative_int("REDLINE_SERVICE_RATE_LIMIT_PER_MINUTE", 120),
            max_packages=_parse_nonnegative_int("REDLINE_SERVICE_MAX_PACKAGES", 100),
            max_active_runs=_parse_nonnegative_int("REDLINE_SERVICE_MAX_ACTIVE_RUNS", 8),
            max_runs_total=_parse_nonnegative_int("REDLINE_SERVICE_MAX_RUNS_TOTAL", 500),
            run_retention_seconds=_parse_nonnegative_int("REDLINE_SERVICE_RUN_RETENTION_SECONDS", 7 * 24 * 60 * 60),
        )

    @property
    def db_path(self) -> Path:
        return self.root / "redline-service.sqlite3"

    @property
    def packages_dir(self) -> Path:
        return self.root / "packages"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _parse_nonnegative_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _parse_port(name: str, default: int) -> int:
    value = _parse_positive_int(name, default)
    if not (1 <= value <= 65535):
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def _parse_bool(name: str, default: str) -> bool:
    raw = os.environ.get(name, default).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _parse_csv(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())
