from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from redline.canonical import CanonicalizationError, hash_file, hash_obj, iter_canonical_files
from redline.models import PackageIdentityFile, PlaybookIdentityLock, ReasonCode

IDENTITY_LOCK_NAME = "playbook_identity.lock"
DEFAULT_ADAPTER_ID = "python_strategy_sandbox"


def identity_lock_path(package: Path) -> Path:
    return package / IDENTITY_LOCK_NAME


def build_identity_lock(package: Path, *, adapter_id: str = DEFAULT_ADAPTER_ID) -> PlaybookIdentityLock:
    locked_files = [
        PackageIdentityFile(path=rel, hash=hash_file(path))
        for rel, path in iter_canonical_files(package)
        if _is_identity_source_file(rel)
    ]
    if not locked_files:
        raise CanonicalizationError("package has no lockable playbook source files", ReasonCode.DATA_MISSING)
    identity_hash = hash_obj({"adapter_id": adapter_id, "canonical_tar_rules": "redline.v9.canonical-tree", "locked_files": locked_files})
    lock = PlaybookIdentityLock(
        adapter_id=adapter_id,
        locked_files=locked_files,
        identity_hash=identity_hash,
        lock_hash="",
    )
    return lock.model_copy(update={"lock_hash": hash_obj(lock)})


def write_identity_lock(package: Path, *, adapter_id: str = DEFAULT_ADAPTER_ID) -> PlaybookIdentityLock:
    lock = build_identity_lock(package, adapter_id=adapter_id)
    path = identity_lock_path(package)
    path.write_text(lock.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return lock


def load_identity_lock(package: Path) -> PlaybookIdentityLock:
    path = identity_lock_path(package)
    if not path.exists():
        raise CanonicalizationError("playbook identity lock is required", ReasonCode.RECEIPT_BINDING_FAILED)
    try:
        lock = PlaybookIdentityLock.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise CanonicalizationError("playbook identity lock is invalid", ReasonCode.RECEIPT_BINDING_FAILED) from exc
    expected_hash = hash_obj(lock.model_copy(update={"lock_hash": ""}))
    if lock.lock_hash != expected_hash:
        raise CanonicalizationError("playbook identity lock hash mismatch", ReasonCode.RECEIPT_BINDING_FAILED)
    _validate_locked_files(package, lock)
    return lock


def _validate_locked_files(package: Path, lock: PlaybookIdentityLock) -> None:
    root = package.resolve()
    seen: set[str] = set()
    for item in lock.locked_files:
        if item.path in seen or item.path.startswith("/") or ".." in Path(item.path).parts:
            raise CanonicalizationError("playbook identity lock contains unsafe path", ReasonCode.RECEIPT_BINDING_FAILED)
        seen.add(item.path)
        path = (root / item.path).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise CanonicalizationError("playbook identity lock path escapes package", ReasonCode.RECEIPT_BINDING_FAILED) from exc
        if not path.is_file() or path.is_symlink():
            raise CanonicalizationError("playbook identity locked file missing", ReasonCode.RECEIPT_BINDING_FAILED)
        if hash_file(path) != item.hash:
            raise CanonicalizationError("playbook identity locked file hash mismatch", ReasonCode.RECEIPT_BINDING_FAILED)
    expected_identity = hash_obj(
        {"adapter_id": lock.adapter_id, "canonical_tar_rules": lock.canonical_tar_rules, "locked_files": lock.locked_files}
    )
    if lock.identity_hash != expected_identity:
        raise CanonicalizationError("playbook identity hash mismatch", ReasonCode.RECEIPT_BINDING_FAILED)


def _is_identity_source_file(rel: str) -> bool:
    path = Path(rel)
    if rel in {"manifest.yaml", "manifest.yml", "README.md"}:
        return True
    if rel.startswith("src/"):
        return True
    return path.name == "strategy.py"
