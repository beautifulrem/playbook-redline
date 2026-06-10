"""Thin MCP placeholder.

P0 backend owns the verifier shape. Wiring FastMCP can wrap
`redline.verifier.verify()` without adding a second verdict implementation.
"""

from pathlib import Path

from redline.verifier import verify


def redline_check_receipt(receipt_path: str, pkg_path: str | None = None) -> dict:
    result = verify(receipt_path=Path(receipt_path), package=Path(pkg_path) if pkg_path else None)
    return result.model_dump(mode="json")

