from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from redline.models import ReasonCode

QUANT = Decimal("1e-8")


class CanonicalizationError(ValueError):
    def __init__(self, message: str, reason_code: ReasonCode = ReasonCode.NONFINITE_VALUE):
        super().__init__(message)
        self.reason_code = reason_code


def canonical_number(value: Decimal) -> str:
    try:
        dec = Decimal(value)
        if not dec.is_finite():
            raise CanonicalizationError("non-finite decimal")
        with localcontext() as ctx:
            integer_digits = max(dec.adjusted() + 1, 1)
            ctx.prec = max(28, integer_digits + abs(QUANT.as_tuple().exponent) + 4)
            quantized = dec.quantize(QUANT, rounding=ROUND_HALF_EVEN)
    except (InvalidOperation, ValueError) as exc:
        raise CanonicalizationError(f"cannot canonicalize number: {value!r}") from exc
    if quantized == 0:
        quantized = Decimal("0")
    return format(quantized, "f")


def normalize(obj: Any, *, exclude_none: bool = True) -> Any:
    if isinstance(obj, BaseModel):
        return normalize(obj.model_dump(mode="python", exclude_none=exclude_none), exclude_none=exclude_none)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Decimal):
        return canonical_number(obj)
    if isinstance(obj, float):
        raise CanonicalizationError("raw float in signed domain")
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(key): normalize(value, exclude_none=exclude_none) for key, value in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [normalize(item, exclude_none=exclude_none) for item in obj]
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    raise CanonicalizationError(f"unsupported signed-domain type: {type(obj).__name__}", ReasonCode.SCHEMA_INVALID)


def canonical_bytes(obj: Any, *, exclude_none: bool = True) -> bytes:
    normalized = normalize(obj, exclude_none=exclude_none)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any, *, exclude_none: bool = True) -> str:
    return sha256_bytes(canonical_bytes(obj, exclude_none=exclude_none))


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def hash_tree(path: Path) -> str:
    root = path.resolve()
    entries: list[dict[str, str]] = []
    for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = file_path.relative_to(root).as_posix()
        if (
            rel.startswith(".redline/")
            or rel.startswith("__pycache__/")
            or "/__pycache__/" in rel
            or rel.endswith(".pyc")
            or rel.endswith(".pyo")
        ):
            continue
        entries.append({"path": rel, "hash": hash_file(file_path)})
    return hash_obj(entries)
