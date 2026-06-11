"""Read-only MCP surface for Playbook Redline.

The MCP server is deliberately thin: it calls the verifier and returns the
same discriminated result shape. It never implements verdict logic locally.
"""

import json
from pathlib import Path

from redline.models import VerificationLevel
from redline.verifier import verify

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:  # pragma: no cover - exercised only in lean installs
    FastMCP = None  # type: ignore[assignment]


def redline_check_receipt(
    receipt_path: str,
    pkg_path: str | None = None,
    rerun: bool = False,
    suite_path: str | None = None,
    spec_path: str | None = None,
    report_path: str | None = None,
    ledger_path: str | None = None,
    ledger_checkpoint_path: str | None = None,
    ledger_attestation_path: str | None = None,
    trust_policy_path: str | None = None,
    baseline_receipt_path: str | None = None,
) -> dict:
    level = VerificationLevel.REPLAYED if rerun else VerificationLevel.HASH_ONLY
    if rerun:
        suite_path, spec_path = _rerun_paths_from_receipt(
            receipt_path=Path(receipt_path),
            pkg_path=Path(pkg_path) if pkg_path else None,
            suite_path=suite_path,
            spec_path=spec_path,
        )
    result = verify(
        receipt_path=Path(receipt_path),
        package=Path(pkg_path) if pkg_path else None,
        level=level,
        suite_path=Path(suite_path) if suite_path else None,
        spec_path=Path(spec_path) if spec_path else None,
        report_path=Path(report_path) if report_path else None,
        ledger_path=Path(ledger_path) if ledger_path else None,
        ledger_checkpoint_path=Path(ledger_checkpoint_path) if ledger_checkpoint_path else None,
        ledger_attestation_path=Path(ledger_attestation_path) if ledger_attestation_path else None,
        trust_policy_path=Path(trust_policy_path) if trust_policy_path else None,
        baseline_receipt_path=Path(baseline_receipt_path) if baseline_receipt_path else None,
    )
    return result.model_dump(mode="json")


def _rerun_paths_from_receipt(
    *,
    receipt_path: Path,
    pkg_path: Path | None,
    suite_path: str | None,
    spec_path: str | None,
) -> tuple[str, str]:
    if suite_path is not None and spec_path is not None:
        return suite_path, spec_path
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception:
        return suite_path or "fixtures/suites/demo_suite.json", spec_path or "fixtures/specs/redline_spec.json"
    return (
        str(_resolve_source_path(suite_path or receipt.get("suite", {}).get("source_path") or "fixtures/suites/demo_suite.json", receipt_path, pkg_path)),
        str(_resolve_source_path(spec_path or receipt.get("spec", {}).get("source_path") or "fixtures/specs/redline_spec.json", receipt_path, pkg_path)),
    )


def _resolve_source_path(value: str, receipt_path: Path, pkg_path: Path | None) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    candidates = [Path.cwd() / path, receipt_path.resolve().parent / path]
    if pkg_path is not None:
        resolved_pkg = pkg_path.resolve()
        candidates.extend(parent / path for parent in resolved_pkg.parents)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return (receipt_path.resolve().parent / path).resolve()


def build_server():
    if FastMCP is None:
        raise RuntimeError("mcp package is not installed; install project dependencies with uv sync")
    server = FastMCP("playbook-redline")

    @server.tool()
    def redline_check_receipt_tool(
        receipt_path: str,
        pkg_path: str | None = None,
        rerun: bool = False,
        suite_path: str | None = None,
        spec_path: str | None = None,
        report_path: str | None = None,
        ledger_path: str | None = None,
        ledger_checkpoint_path: str | None = None,
        ledger_attestation_path: str | None = None,
        trust_policy_path: str | None = None,
        baseline_receipt_path: str | None = None,
    ) -> dict:
        """Verify a Redline receipt without mutating package or platform state."""

        return redline_check_receipt(
            receipt_path=receipt_path,
            pkg_path=pkg_path,
            rerun=rerun,
            suite_path=suite_path,
            spec_path=spec_path,
            report_path=report_path,
            ledger_path=ledger_path,
            ledger_checkpoint_path=ledger_checkpoint_path,
            ledger_attestation_path=ledger_attestation_path,
            trust_policy_path=trust_policy_path,
            baseline_receipt_path=baseline_receipt_path,
        )

    return server


def main() -> None:
    build_server().run()
