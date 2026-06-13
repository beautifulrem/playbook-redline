from __future__ import annotations

import os
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from redline.canonical import CanonicalizationError, hash_file, hash_tree
from redline.io_safety import ensure_safe_output_dir, reject_unsafe_output_file
from redline.models import ReasonCode
from redline.service.models import ArtifactInfo, ArtifactManifest


def atomic_write_bytes(path: Path, data: bytes, *, reject_existing_hardlinks: bool = True) -> None:
    ensure_safe_output_dir(path.parent)
    reject_unsafe_output_file(path, reject_existing_hardlinks=reject_existing_hardlinks)
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as fh:
            tmp_name = fh.name
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        if tmp_name is not None:
            Path(tmp_name).unlink(missing_ok=True)
        raise


def build_artifact_manifest(run_id: str, out_dir: Path) -> ArtifactManifest:
    artifacts: list[ArtifactInfo] = []
    for artifact_id, kind, rel_path in [
        ("envelope", "decision-envelope", "envelope.json"),
        ("report", "report", "report.json"),
        ("receipt", "receipt", "receipt.json"),
        ("issuance-ledger", "ledger", "issuance-ledger.jsonl"),
        ("issuance-ledger-checkpoint", "ledger-checkpoint", "issuance-ledger.checkpoint.json"),
    ]:
        path = out_dir / rel_path
        if path.exists():
            artifacts.append(_artifact_info(run_id, artifact_id, kind, rel_path, path))
    proofs_dir = out_dir / "proofs"
    if proofs_dir.exists() and proofs_dir.is_dir() and not proofs_dir.is_symlink():
        for proof_path in sorted(proofs_dir.glob("*.json")):
            rel_path = f"proofs/{proof_path.name}"
            artifact_id = f"proofs/{proof_path.name}"
            artifacts.append(_artifact_info(run_id, artifact_id, "proof", rel_path, proof_path))
    return ArtifactManifest(run_id=run_id, artifacts=artifacts)


def resolve_artifact_path(out_dir: Path, artifact_id: str) -> Path:
    rel = Path(artifact_id)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise CanonicalizationError("artifact path is outside the run", ReasonCode.RECEIPT_BINDING_FAILED)
    root = out_dir.resolve()
    raw_path = root / rel
    try:
        st = raw_path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(artifact_id) from exc
    if stat.S_ISLNK(st.st_mode):
        raise CanonicalizationError("artifact must not be a symlink", ReasonCode.RECEIPT_BINDING_FAILED)
    if not stat.S_ISREG(st.st_mode):
        raise CanonicalizationError("artifact must be a regular file", ReasonCode.DATA_MISSING)
    if st.st_nlink > 1:
        raise CanonicalizationError("artifact must not be a hardlink alias", ReasonCode.RECEIPT_BINDING_FAILED)
    path = raw_path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise CanonicalizationError("artifact path is outside the run", ReasonCode.RECEIPT_BINDING_FAILED) from exc
    return path


def save_upload_stream(*, chunks: list[bytes], out_path: Path, max_bytes: int) -> None:
    total = sum(len(chunk) for chunk in chunks)
    if total > max_bytes:
        raise CanonicalizationError("upload exceeds max size", ReasonCode.DATA_MISSING)
    atomic_write_bytes(out_path, b"".join(chunks))


def extract_package_archive(*, archive_path: Path, out_dir: Path, max_bytes: int) -> Path:
    ensure_safe_output_dir(out_dir)
    extracted = out_dir / "source"
    ensure_safe_output_dir(extracted)
    total_bytes = 0
    try:
        with tarfile.open(archive_path, "r:*") as tar:
            for member in tar.getmembers():
                rel = _safe_tar_member_path(member)
                target = (extracted / rel).resolve()
                try:
                    target.relative_to(extracted.resolve())
                except ValueError as exc:
                    raise CanonicalizationError("archive member escapes package root", ReasonCode.RECEIPT_BINDING_FAILED) from exc
                if member.isdir():
                    ensure_safe_output_dir(target)
                    continue
                if not member.isfile():
                    raise CanonicalizationError("archive contains unsupported member type", ReasonCode.RECEIPT_BINDING_FAILED)
                total_bytes += member.size
                if total_bytes > max_bytes:
                    raise CanonicalizationError("archive exceeds max extracted size", ReasonCode.DATA_MISSING)
                source = tar.extractfile(member)
                if source is None:
                    raise CanonicalizationError("archive member is unreadable", ReasonCode.DATA_MISSING)
                atomic_write_bytes(target, source.read())
    except tarfile.TarError as exc:
        raise CanonicalizationError("archive is not a valid tar file", ReasonCode.PARSE_ERROR) from exc
    package_root = _detect_package_root(extracted)
    hash_tree(package_root)
    return package_root


def _safe_tar_member_path(member: tarfile.TarInfo) -> Path:
    raw = PurePosixPath(member.name)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise CanonicalizationError("archive contains unsafe path", ReasonCode.RECEIPT_BINDING_FAILED)
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise CanonicalizationError("archive contains link or device member", ReasonCode.RECEIPT_BINDING_FAILED)
    return Path(*raw.parts)


def _detect_package_root(extracted: Path) -> Path:
    if (extracted / "baseline").is_dir():
        return extracted
    children = [child for child in extracted.iterdir() if child.is_dir()]
    if len(children) == 1 and (children[0] / "baseline").is_dir():
        return children[0]
    return extracted


def _artifact_info(run_id: str, artifact_id: str, kind: str, rel_path: str, path: Path) -> ArtifactInfo:
    return ArtifactInfo(
        artifact_id=artifact_id,
        kind=kind,
        path=rel_path,
        sha256=hash_file(path),
        bytes=path.stat().st_size,
        download_url=f"/v1/runs/{run_id}/artifacts/{artifact_id}",
    )
