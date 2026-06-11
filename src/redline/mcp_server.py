"""MCP surface for Playbook Redline.

The MCP server is deliberately thin: it calls the import/compiler/runner/verifier
surfaces and never implements verdict logic locally.
"""

import json
import os
from pathlib import Path

from redline.canonical import hash_obj
from redline.models import ReasonCode, Status, TrustPolicy, VerificationLevel, VerificationStatus
from redline.runner import run_redline
from redline.surfaces import compile_spec, import_package, publish_preflight
from redline.trust import verify_trust_policy
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
    return redline_verify_receipt(
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


def redline_verify_receipt(
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
    payload = result.model_dump(mode="json")
    payload["schema_version"] = "redline.mcp.check.v1"
    return payload


def redline_import_playbook(pkg_path: str) -> dict:
    try:
        result = import_package(Path(pkg_path))
    except Exception as exc:
        return _mcp_bad_input(ReasonCode.DATA_MISSING, str(exc))
    payload = result.model_dump(mode="json")
    payload["schema_version"] = "redline.mcp.import.v1"
    return payload


def redline_compile_spec(
    source_path: str,
    use_qwen: bool = False,
    qwen_model: str | None = None,
    qwen_base_url: str | None = None,
) -> dict:
    try:
        spec = compile_spec(Path(source_path), use_qwen=use_qwen, qwen_model=qwen_model, qwen_base_url=qwen_base_url)
    except Exception as exc:
        return _mcp_bad_input(ReasonCode.SCHEMA_INVALID, str(exc))
    return {
        "schema_version": "redline.mcp.compile.v1",
        "spec": spec.model_dump(mode="json"),
        "spec_hash": hash_obj(spec),
        "compiler": spec.compiler,
        "model": spec.model,
        "tool_schema_hash": spec.tool_schema_hash,
        "degraded": spec.compiler != "qwen",
        "degraded_reason": spec.degraded_reason,
    }


def redline_run_suite(
    pkg_path: str,
    baseline: str = "baseline",
    candidate: str = "candidate_good",
    suite_path: str = "fixtures/suites/demo_suite.json",
    spec_path: str = "fixtures/specs/redline_spec.json",
    baseline_receipt_path: str | None = None,
    baseline_trust_policy_path: str | None = None,
    baseline_version_id: str | None = None,
    candidate_version_id: str | None = None,
) -> dict:
    try:
        artifacts = run_redline(
            package_dir=Path(pkg_path),
            baseline=baseline,
            candidate=candidate,
            suite_path=Path(suite_path),
            spec_path=Path(spec_path),
            out_dir=None,
            baseline_receipt_path=Path(baseline_receipt_path) if baseline_receipt_path else None,
            baseline_trust_policy_path=Path(baseline_trust_policy_path) if baseline_trust_policy_path else None,
            baseline_version_id=baseline_version_id,
            candidate_version_id=candidate_version_id,
        )
    except Exception as exc:
        return _mcp_bad_input(ReasonCode.DATA_MISSING, str(exc))
    return {
        "schema_version": "redline.mcp.run.v1",
        "envelope": artifacts.envelope.model_dump(mode="json"),
        "receipt_hash": artifacts.receipt.receipt_hash if artifacts.receipt is not None else None,
        "report_hash": artifacts.report_json.get("report_hash"),
        "trace_hashes": [trace.artifact_hash for trace in artifacts.traces],
    }


def redline_export_if_clean(
    receipt_path: str,
    pkg_path: str,
    suite_path: str | None = None,
    spec_path: str | None = None,
    report_path: str | None = None,
    ledger_attestation_path: str | None = None,
    trust_policy_path: str | None = None,
    baseline_receipt_path: str | None = None,
    out_dir: str | None = None,
) -> dict:
    protected_trust_policy_path = trust_policy_path if _protected_trust_policy_matches(trust_policy_path) else None
    resolved_suite_path, resolved_spec_path = _rerun_paths_from_receipt(
        receipt_path=Path(receipt_path),
        pkg_path=Path(pkg_path),
        suite_path=suite_path,
        spec_path=spec_path,
    )
    verification = redline_verify_receipt(
        receipt_path=receipt_path,
        pkg_path=pkg_path,
        rerun=True,
        suite_path=resolved_suite_path,
        spec_path=resolved_spec_path,
        report_path=report_path,
        ledger_attestation_path=ledger_attestation_path,
        trust_policy_path=protected_trust_policy_path,
        baseline_receipt_path=baseline_receipt_path,
    )
    export_allowed = verification.get("status") == VerificationStatus.VERIFIED.value and verification.get("reason_code") == ReasonCode.PASS.value
    export_result: dict | None = None
    annotation_path: Path | None = None
    archive_path: Path | None = None
    if export_allowed:
        export_root = Path(out_dir) if out_dir is not None else Path(receipt_path).resolve().parent / "mcp-export"
        annotation_path = export_root / "redline-annotation.json"
        archive_path = export_root / "annotated-package.tar.gz"
        preflight = publish_preflight(
            receipt_path=Path(receipt_path),
            package=Path(pkg_path),
            suite_path=Path(resolved_suite_path),
            spec_path=Path(resolved_spec_path),
            out_dir=export_root,
            report_path=Path(report_path) if report_path else None,
            ledger_attestation_path=Path(ledger_attestation_path) if ledger_attestation_path else None,
            trust_policy_path=Path(protected_trust_policy_path) if protected_trust_policy_path else None,
            trust_policy_hash=os.environ.get("REDLINE_TRUST_POLICY_HASH"),
            baseline_receipt_path=Path(baseline_receipt_path) if baseline_receipt_path else None,
        )
        export_allowed = preflight.ok and preflight.reason_code == ReasonCode.PASS
        export_result = preflight.model_dump(mode="json")
    return {
        "schema_version": "redline.mcp.export_if_clean.v1",
        "export_allowed": export_allowed,
        "status": Status.PASS.value if export_allowed else Status.UNVERIFIED_NO_VERDICT.value,
        "reason_code": ReasonCode.PASS.value if export_allowed else (export_result or verification).get("reason_code", ReasonCode.UNVERIFIED_NO_VERDICT.value),
        "verification": verification,
        "export": export_result,
        "annotation_path": str(annotation_path) if export_allowed and annotation_path is not None else None,
        "annotated_package_path": str(archive_path) if export_allowed and archive_path is not None else None,
        "trust_source": "protected_env" if protected_trust_policy_path is not None else "untrusted_tool_input",
    }


def _protected_trust_policy_matches(trust_policy_path: str | None) -> bool:
    pinned_hash = os.environ.get("REDLINE_TRUST_POLICY_HASH")
    if trust_policy_path is None or pinned_hash is None:
        return False
    try:
        policy = TrustPolicy.model_validate(json.loads(Path(trust_policy_path).read_text(encoding="utf-8")))
    except Exception:
        return False
    return policy.policy_hash == pinned_hash and verify_trust_policy(policy)


def _mcp_bad_input(reason_code: ReasonCode, message: str) -> dict:
    return {
        "schema_version": "redline.mcp.error.v1",
        "status": VerificationStatus.BAD_INPUT.value,
        "reason_code": reason_code.value,
        "verification_level": VerificationLevel.HASH_ONLY.value,
        "receipt_hash": None,
        "strength_summary": message,
        "chain_status": "unchained",
        "edit_provenance_present": False,
        "proof_coverage": "incomplete",
        "missing_proof_ids": [],
    }


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

    @server.tool(name="redline_check_receipt")
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

    @server.tool(name="redline_verify_receipt")
    def redline_verify_receipt_tool(
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
        """Verify a Redline receipt and return the MCP check schema."""

        return redline_verify_receipt(
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

    @server.tool(name="redline_import_playbook")
    def redline_import_playbook_tool(pkg_path: str) -> dict:
        """Import a playbook package and return its canonical identity."""

        return redline_import_playbook(pkg_path)

    @server.tool(name="redline_compile_spec")
    def redline_compile_spec_tool(
        source_path: str,
        use_qwen: bool = False,
        qwen_model: str | None = None,
        qwen_base_url: str | None = None,
    ) -> dict:
        """Compile a JSON or text RedlineSpec without making a verdict."""

        return redline_compile_spec(source_path, use_qwen=use_qwen, qwen_model=qwen_model, qwen_base_url=qwen_base_url)

    @server.tool(name="redline_run_suite")
    def redline_run_suite_tool(
        pkg_path: str,
        baseline: str = "baseline",
        candidate: str = "candidate_good",
        suite_path: str = "fixtures/suites/demo_suite.json",
        spec_path: str = "fixtures/specs/redline_spec.json",
        baseline_receipt_path: str | None = None,
        baseline_trust_policy_path: str | None = None,
        baseline_version_id: str | None = None,
        candidate_version_id: str | None = None,
    ) -> dict:
        """Run the deterministic suite in memory and return the kernel envelope."""

        return redline_run_suite(
            pkg_path=pkg_path,
            baseline=baseline,
            candidate=candidate,
            suite_path=suite_path,
            spec_path=spec_path,
            baseline_receipt_path=baseline_receipt_path,
            baseline_trust_policy_path=baseline_trust_policy_path,
            baseline_version_id=baseline_version_id,
            candidate_version_id=candidate_version_id,
        )

    @server.tool(name="redline_export_if_clean")
    def redline_export_if_clean_tool(
        receipt_path: str,
        pkg_path: str,
        suite_path: str | None = None,
        spec_path: str | None = None,
        report_path: str | None = None,
        ledger_attestation_path: str | None = None,
        trust_policy_path: str | None = None,
        baseline_receipt_path: str | None = None,
        out_dir: str | None = None,
    ) -> dict:
        """Export an annotated package only when a receipt is replay-verified and clean."""

        return redline_export_if_clean(
            receipt_path=receipt_path,
            pkg_path=pkg_path,
            suite_path=suite_path,
            spec_path=spec_path,
            report_path=report_path,
            ledger_attestation_path=ledger_attestation_path,
            trust_policy_path=trust_policy_path,
            baseline_receipt_path=baseline_receipt_path,
            out_dir=out_dir,
        )

    return server


def main() -> None:
    build_server().run()
