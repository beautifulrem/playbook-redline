from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from redline.models import ReasonCode, Status, VerificationLevel, VerificationStatus
from redline.runner import run_redline
from redline.schemas import export_schemas as export_schema_files
from redline.sponsor.bitget import validate_sponsor_evidence_shape
from redline.verifier import verify, verify_proof

app = typer.Typer(no_args_is_help=True)
console = Console()

EXIT_BY_REASON: dict[ReasonCode, int] = {
    ReasonCode.PASS: 0,
    ReasonCode.BASELINE_GENESIS: 10,
    ReasonCode.FILE_NOT_FOUND: 2,
    ReasonCode.PARSE_ERROR: 2,
    ReasonCode.SCHEMA_INVALID: 2,
    ReasonCode.VERSION_UNSUPPORTED: 2,
    ReasonCode.NEW_BLOCK_BREACH: 3,
    ReasonCode.RECEIPT_MISMATCH: 4,
    ReasonCode.RECEIPT_BINDING_FAILED: 4,
    ReasonCode.ENGINE_IDENTITY_MISMATCH: 4,
    ReasonCode.NONFINITE_VALUE: 4,
    ReasonCode.CALIBRATION_FAILED: 5,
    ReasonCode.BASELINE_BREACHES: 5,
    ReasonCode.BASELINE_UNRUNNABLE: 5,
    ReasonCode.UNVERIFIED_NO_VERDICT: 6,
    ReasonCode.COVERAGE_INCOMPLETE: 6,
    ReasonCode.PROBE_ERROR: 6,
    ReasonCode.ENGINE_FAILURE: 6,
    ReasonCode.DATA_MISSING: 6,
    ReasonCode.BASELINE_UNCHAINED: 7,
    ReasonCode.SPONSOR_READBACK_MISMATCH: 8,
    ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED: 6,
    ReasonCode.CANDIDATE_SANDBOX_VIOLATION: 9,
    ReasonCode.VERDICT_PATH_VIOLATION: 9,
}
assert set(EXIT_BY_REASON) == set(ReasonCode)


@app.command()
def run(
    package: Path,
    baseline: str = "baseline",
    candidate: str = "candidate_bad",
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    out: Path = Path("artifacts/demo"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    artifacts = run_redline(package_dir=package, baseline=baseline, candidate=candidate, suite_path=suite, spec_path=spec, out_dir=out)
    if json_out:
        console.print_json(data=artifacts.envelope.model_dump(mode="json"))
    else:
        _print_envelope(artifacts.envelope.status.value, artifacts.envelope.reason_code.value, out)
    raise typer.Exit(EXIT_BY_REASON[artifacts.envelope.reason_code])


@app.command("make-demo")
def make_demo(
    package: Path = Path("fixtures/demo_pack"),
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    out: Path = Path("artifacts/demo"),
) -> None:
    if out.exists():
        shutil.rmtree(out)
    bad = run_redline(package_dir=package, baseline="baseline", candidate="candidate_bad", suite_path=suite, spec_path=spec, out_dir=out / "withheld")
    good = run_redline(package_dir=package, baseline="baseline", candidate="candidate_good", suite_path=suite, spec_path=spec, out_dir=out / "pass")
    table = Table("case", "status", "reason", "receipt")
    table.add_row("candidate_bad", bad.envelope.status.value, bad.envelope.reason_code.value, str((out / "withheld" / "receipt.json").resolve()))
    table.add_row("candidate_good", good.envelope.status.value, good.envelope.reason_code.value, str((out / "pass" / "receipt.json").resolve()))
    console.print(table)


@app.command()
def check(
    receipt: Path,
    package: Optional[Path] = None,
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    report: Optional[Path] = None,
    ledger: Optional[Path] = None,
    rerun: bool = False,
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    level = VerificationLevel.REPLAYED if rerun else VerificationLevel.HASH_ONLY
    result = verify(
        receipt_path=receipt,
        package=package,
        level=level,
        suite_path=suite if rerun else None,
        spec_path=spec if rerun else None,
        report_path=report,
        ledger_path=ledger,
    )
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        _print_envelope(result.status.value, result.reason_code.value, receipt)
    if result.status == VerificationStatus.VERIFIED:
        raise typer.Exit(0 if result.reason_code == ReasonCode.PASS else EXIT_BY_REASON[result.reason_code])
    raise typer.Exit(EXIT_BY_REASON[result.reason_code])


@app.command("verify-proof")
def verify_proof_cmd(
    receipt: Path,
    proof_id: str = typer.Option(..., "--proof-id"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    result = verify_proof(receipt_path=receipt, proof_id=proof_id)
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        console.print(f"{result.status}: {result.proof_id}")
    raise typer.Exit(0 if result.status == "proof_verified" else EXIT_BY_REASON[result.reason_code])


@app.command("verify-sponsor-evidence")
def verify_sponsor_evidence_cmd(
    evidence: Path,
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_sponsor_evidence_shape(evidence)
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        _print_envelope("verified" if result.ok else "rejected", (result.reason_code or ReasonCode.PASS).value, evidence)
    raise typer.Exit(0 if result.ok else EXIT_BY_REASON[result.reason_code or ReasonCode.SPONSOR_READBACK_MISMATCH])


@app.command("export-schemas")
def export_schemas(out: Path = Path("schemas")) -> None:
    export_schema_files(out)
    console.print(f"schemas written: {out}")


@app.command()
def doctor() -> None:
    console.print("redline backend doctor: ok")


def _print_envelope(status: str, reason: str, target: object) -> None:
    table = Table("field", "value")
    table.add_row("status", status)
    table.add_row("reason", reason)
    table.add_row("target", str(target))
    console.print(table)


if __name__ == "__main__":
    app()
