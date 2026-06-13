from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from redline.canonical import CanonicalizationError
from redline.models import ReasonCode


def ensure_safe_output_dir(path: Path) -> None:
    if path.is_symlink():
        raise CanonicalizationError(f"output directory must not be a symlink: {path}", ReasonCode.RECEIPT_BINDING_FAILED)
    if path.exists() and not path.is_dir():
        raise CanonicalizationError(f"output path must be a directory: {path}", ReasonCode.DATA_MISSING)
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CanonicalizationError(f"output directory must not be a symlink: {path}", ReasonCode.RECEIPT_BINDING_FAILED)


def reject_unsafe_output_file(path: Path, *, reject_existing_hardlinks: bool = True) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise CanonicalizationError(f"output file must not be a symlink: {path}", ReasonCode.RECEIPT_BINDING_FAILED)
    if not stat.S_ISREG(st.st_mode):
        raise CanonicalizationError(f"output path must be a regular file: {path}", ReasonCode.DATA_MISSING)
    if reject_existing_hardlinks and st.st_nlink > 1:
        raise CanonicalizationError(f"output file must not be a hardlink alias: {path}", ReasonCode.RECEIPT_BINDING_FAILED)


def atomic_write_text(path: Path, data: str, *, encoding: str = "utf-8", reject_existing_hardlinks: bool = True) -> None:
    ensure_safe_output_dir(path.parent)
    reject_unsafe_output_file(path, reject_existing_hardlinks=reject_existing_hardlinks)
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding=encoding, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as fh:
            tmp_name = fh.name
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        if tmp_name is not None:
            Path(tmp_name).unlink(missing_ok=True)
        raise


def append_text(path: Path, data: str, *, encoding: str = "utf-8", reject_existing_hardlinks: bool = True) -> None:
    ensure_safe_output_dir(path.parent)
    reject_unsafe_output_file(path, reject_existing_hardlinks=reject_existing_hardlinks)
    with path.open("a", encoding=encoding) as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
