from __future__ import annotations

from dataclasses import dataclass


CURRENT_SCHEMA_VERSION = "20260624_0005_release_tier"


@dataclass(frozen=True)
class MigrationRecord:
    version: str
    name: str


SERVICE_MIGRATIONS = (
    MigrationRecord(version="20260623_0001_service_schema", name="service packages, runs, releases, and audit ledger"),
    MigrationRecord(version="20260623_0002_idempotency_keys", name="release API idempotency keys"),
    MigrationRecord(version="20260623_0003_release_jobs", name="release jobs and event ledger"),
    MigrationRecord(version="20260624_0004_approval_lifecycle", name="approval nonce, ttl, and consumption fields"),
    MigrationRecord(version="20260624_0005_release_tier", name="release tier column for L0/L1/L2 readiness"),
)


def expected_migration_versions() -> list[str]:
    return [migration.version for migration in SERVICE_MIGRATIONS]
