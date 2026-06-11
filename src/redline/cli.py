from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from redline.canonical import CanonicalizationError, hash_obj, hash_tree, sha256_bytes
from redline.models import EditProvenance, ReasonCode, Status, VerificationLevel, VerificationStatus
from redline.runner import load_spec, load_suite, resolve_package_role_dir, run_redline
from redline.receipt import IssuanceLedgerConflict
from redline.schemas import export_schemas as export_schema_files
from redline.sponsor.bitget import BitgetSponsorAdapter, SponsorState, validate_sponsor_evidence_shape, verify_sponsor_readback_evidence
from redline.surfaces import (
    capture_edit_provenance,
    compile_spec,
    execute_sponsor_readback,
    import_package,
    make_receipt_bound_package_archive,
    publish_preflight,
    render_report_html,
    verify_annotation,
)
from redline.trust import generate_trust_keypair, make_trust_policy, sign_checkpoint, verify_checkpoint_attestation
from redline.verifier import load_receipt, verify, verify_proof
from redline.models import LedgerCheckpoint, LedgerCheckpointAttestation

app = typer.Typer(no_args_is_help=True)
console = Console()
FIXTURE_TIMESTAMP = "2026-06-10T00:00:00Z"

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
    edit_provenance: Optional[Path] = typer.Option(None, "--edit-provenance"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
    baseline_trust_policy: Optional[Path] = typer.Option(None, "--baseline-trust-policy"),
    baseline_version_id: Optional[str] = typer.Option(None, "--baseline-version-id"),
    candidate_version_id: Optional[str] = typer.Option(None, "--candidate-version-id"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    provenance = _load_edit_provenance(edit_provenance) if edit_provenance is not None else None
    try:
        _validate_run_inputs(package=package, baseline=baseline, candidate=candidate, suite=suite, spec=spec)
        artifacts = run_redline(
            package_dir=package,
            baseline=baseline,
            candidate=candidate,
            suite_path=suite,
            spec_path=spec,
            out_dir=out,
            edit_provenance=provenance,
            baseline_receipt_path=baseline_receipt,
            baseline_trust_policy_path=baseline_trust_policy,
            baseline_version_id=baseline_version_id,
            candidate_version_id=candidate_version_id,
        )
    except FileNotFoundError as exc:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, f"file not found: {exc.filename or exc}", out)
    except json.JSONDecodeError:
        _exit_bad_input(ReasonCode.PARSE_ERROR, json_out, "run input JSON is invalid", out)
    except ValidationError:
        _exit_bad_input(ReasonCode.SCHEMA_INVALID, json_out, "run input failed schema validation", out)
    except ValueError as exc:
        _exit_bad_input(ReasonCode.DATA_MISSING, json_out, str(exc), out)
    except IssuanceLedgerConflict as exc:
        _exit_bad_input(ReasonCode.RECEIPT_BINDING_FAILED, json_out, str(exc), out)
    if json_out:
        console.print_json(data=artifacts.envelope.model_dump(mode="json"))
    else:
        _print_envelope(artifacts.envelope.status.value, artifacts.envelope.reason_code.value, out)
    raise typer.Exit(EXIT_BY_REASON[artifacts.envelope.reason_code])


@app.command("import")
def import_cmd(
    package: Path,
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    try:
        result = import_package(package)
    except FileNotFoundError:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, "package path not found", package)
    except NotADirectoryError:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, "package path is not a directory", package)
    except CanonicalizationError as exc:
        _exit_bad_input(exc.reason_code, json_out, str(exc), package)
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        table = Table("field", "value")
        table.add_row("path", result.path)
        table.add_row("identity_hash", result.identity_hash)
        table.add_row("files", str(len(result.files)))
        console.print(table)


@app.command("compile")
def compile_cmd(
    source: Path,
    out: Optional[Path] = typer.Option(None, "--out"),
    qwen: bool = typer.Option(False, "--qwen"),
    qwen_model: Optional[str] = typer.Option(None, "--qwen-model"),
    qwen_base_url: Optional[str] = typer.Option(None, "--qwen-base-url"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    try:
        spec = compile_spec(source, use_qwen=qwen, qwen_model=qwen_model, qwen_base_url=qwen_base_url)
    except FileNotFoundError:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, "spec source not found", source)
    except json.JSONDecodeError:
        _exit_bad_input(ReasonCode.PARSE_ERROR, json_out, "spec JSON is invalid", source)
    except OSError:
        _exit_bad_input(ReasonCode.DATA_MISSING, json_out, "spec source could not be read", source)
    except (ValidationError, ValueError):
        _exit_bad_input(ReasonCode.SCHEMA_INVALID, json_out, "spec source failed validation", source)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(spec.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if json_out or out is None:
        console.print_json(data=spec.model_dump(mode="json"))


@app.command("capture-edit")
def capture_edit_cmd(
    prompt_log: Path = typer.Option(..., "--prompt-log"),
    tool: str = typer.Option("manual", "--tool"),
    baseline: Optional[Path] = typer.Option(None, "--baseline"),
    candidate: Optional[Path] = typer.Option(None, "--candidate"),
    diff: Optional[Path] = typer.Option(None, "--diff"),
    locked_by: str = typer.Option("author", "--locked-by"),
    out: Path = typer.Option(Path("artifacts/edit-provenance.json"), "--out"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    try:
        provenance = capture_edit_provenance(
            tool=tool,
            prompt_log=prompt_log,
            baseline=baseline,
            candidate=candidate,
            diff=diff,
            locked_by=locked_by,
        )
    except FileNotFoundError as exc:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, f"file not found: {exc.filename or exc}", out)
    except NotADirectoryError as exc:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, f"path is not a directory: {exc.filename or exc}", out)
    except CanonicalizationError as exc:
        _exit_bad_input(exc.reason_code, json_out, str(exc), out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(provenance.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if json_out:
        console.print_json(data=provenance.model_dump(mode="json"))
    else:
        _print_envelope("captured", provenance.diff_hash, out)


@app.command("make-demo")
def make_demo(
    package: Path = Path("fixtures/demo_pack"),
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    out: Path = Path("artifacts/demo"),
) -> None:
    try:
        _validate_run_inputs(package=package, baseline="baseline", candidate="candidate_bad", suite=suite, spec=spec)
        _validate_run_inputs(package=package, baseline="baseline", candidate="candidate_good", suite=suite, spec=spec)
        _prepare_demo_out(out)
    except ValueError as exc:
        console.print(f"make-demo rejected: {exc}")
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING]) from exc
    except (FileNotFoundError, json.JSONDecodeError, ValidationError) as exc:
        console.print(f"make-demo rejected: {exc}")
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING]) from exc
    bad = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_bad",
        suite_path=suite,
        spec_path=spec,
        out_dir=out / "withheld",
        edit_provenance=_fixture_edit_provenance(package, "baseline", "candidate_bad"),
        ledger_written_at=FIXTURE_TIMESTAMP,
        ledger_path_label="issuance-ledger.jsonl",
    )
    _assert_demo_case(bad, expected_status=Status.WITHHELD, expected_reason=ReasonCode.NEW_BLOCK_BREACH, case="candidate_bad")
    good = run_redline(
        package_dir=package,
        baseline="baseline",
        candidate="candidate_good",
        suite_path=suite,
        spec_path=spec,
        out_dir=out / "pass",
        edit_provenance=_fixture_edit_provenance(package, "baseline", "candidate_good"),
        ledger_written_at=FIXTURE_TIMESTAMP,
        ledger_path_label="issuance-ledger.jsonl",
    )
    _assert_demo_case(good, expected_status=Status.PASS, expected_reason=ReasonCode.BASELINE_GENESIS, case="candidate_good")
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
    ledger_checkpoint: Optional[Path] = typer.Option(None, "--ledger-checkpoint"),
    ledger_attestation: Optional[Path] = typer.Option(None, "--ledger-attestation"),
    trusted_ledger_public_key: Optional[str] = typer.Option(None, "--trusted-ledger-public-key"),
    trust_policy: Optional[Path] = typer.Option(None, "--trust-policy"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
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
        ledger_checkpoint_path=ledger_checkpoint,
        ledger_attestation_path=ledger_attestation,
        trusted_ledger_public_key=trusted_ledger_public_key,
        trust_policy_path=trust_policy,
        baseline_receipt_path=baseline_receipt,
    )
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        _print_envelope(result.status.value, result.reason_code.value, receipt)
    if result.status == VerificationStatus.VERIFIED:
        raise typer.Exit(0 if result.reason_code == ReasonCode.PASS else EXIT_BY_REASON[result.reason_code])
    raise typer.Exit(EXIT_BY_REASON[result.reason_code])


@app.command()
def report(
    report_json: Path,
    out: Path = typer.Option(Path("artifacts/report.html"), "--out"),
    receipt: Optional[Path] = typer.Option(None, "--receipt"),
    package: Optional[Path] = typer.Option(None, "--package"),
    suite: Path = typer.Option(Path("fixtures/suites/demo_suite.json"), "--suite"),
    spec: Path = typer.Option(Path("fixtures/specs/redline_spec.json"), "--spec"),
    ledger_attestation: Optional[Path] = typer.Option(None, "--ledger-attestation"),
    trusted_ledger_public_key: Optional[str] = typer.Option(None, "--trusted-ledger-public-key"),
    trust_policy: Optional[Path] = typer.Option(None, "--trust-policy"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
    verified: bool = typer.Option(False, "--verified"),
) -> None:
    report_trust_policy = Path(os.environ["REDLINE_TRUST_POLICY"]) if verified and os.environ.get("REDLINE_TRUST_POLICY") else trust_policy
    report_trust_policy_hash = os.environ.get("REDLINE_TRUST_POLICY_HASH") if verified else None
    try:
        render_report_html(
            report_json,
            out,
            receipt_path=receipt,
            package=package,
            suite_path=suite if receipt is not None and package is not None else None,
            spec_path=spec if receipt is not None and package is not None else None,
            ledger_attestation_path=ledger_attestation,
            trusted_ledger_public_key=trusted_ledger_public_key,
            trust_policy_path=report_trust_policy,
            trust_policy_hash=report_trust_policy_hash,
            baseline_receipt_path=baseline_receipt,
            require_verified=verified,
        )
    except ValueError as exc:
        console.print(f"report rejected: {exc}")
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.RECEIPT_MISMATCH]) from exc
    console.print(f"report written: {out}")


@app.command()
def publish(
    package: Path,
    receipt: Path,
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    out: Path = Path("artifacts/publish-preflight"),
    execute: bool = typer.Option(False, "--execute"),
    final_publish: bool = typer.Option(False, "--final-publish"),
    yes_wrapper_only: bool = typer.Option(False, "--yes-i-understand-redline-is-wrapper-only"),
    yes_final_publish: bool = typer.Option(False, "--yes-final-publish"),
    allow_demo_baseline_genesis: bool = typer.Option(False, "--allow-demo-baseline-genesis"),
    ledger_attestation: Optional[Path] = typer.Option(None, "--ledger-attestation"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    if final_publish and not execute:
        result = {
            "schema_version": "redline.publish_preflight.v1",
            "ok": False,
            "state": "FINAL_PUBLISH_REQUIRES_EXECUTE",
            "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
        }
        _print_json_or_table(result, json_out, out)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])
    if allow_demo_baseline_genesis and (execute or final_publish):
        result = {
            "schema_version": "redline.publish_preflight.v1",
            "ok": False,
            "state": "DEMO_EXECUTE_FORBIDDEN",
            "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
        }
        _print_json_or_table(result, json_out, out)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])
    if final_publish and (not yes_final_publish or os.environ.get("REDLINE_ALLOW_FINAL_PUBLISH") != "1"):
        result = {
            "schema_version": "redline.publish_preflight.v1",
            "ok": False,
            "state": "FINAL_PUBLISH_CONFIRMATION_REQUIRED",
            "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
        }
        _print_json_or_table(result, json_out, out)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])
    if execute and not yes_wrapper_only:
        result = {
            "schema_version": "redline.publish_preflight.v1",
            "ok": False,
            "state": "EXECUTE_CONFIRMATION_REQUIRED",
            "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
        }
        _print_json_or_table(result, json_out, out)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])
    if out.exists() and not out.is_dir():
        result = {
            "schema_version": "redline.publish_preflight.v1",
            "ok": False,
            "state": "OUTPUT_PATH_INVALID",
            "reason_code": ReasonCode.DATA_MISSING.value,
        }
        _print_json_or_table(result, json_out, out)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING])
    trust_policy_path = Path(os.environ["REDLINE_TRUST_POLICY"]) if os.environ.get("REDLINE_TRUST_POLICY") else None
    trust_policy_hash = os.environ.get("REDLINE_TRUST_POLICY_HASH")
    result = publish_preflight(
        receipt_path=receipt,
        package=package,
        suite_path=suite,
        spec_path=spec,
        out_dir=out,
        ledger_attestation_path=ledger_attestation,
        trust_policy_path=trust_policy_path,
        trust_policy_hash=trust_policy_hash,
        baseline_receipt_path=baseline_receipt,
        allow_demo_baseline_genesis=allow_demo_baseline_genesis,
    )
    if execute:
        access_key = os.environ.get("REDLINE_BITGET_ACCESS_KEY") or os.environ.get("BITGET_ACCESS_KEY")
        secret_key = os.environ.get("REDLINE_BITGET_SECRET_KEY") or os.environ.get("BITGET_SECRET_KEY")
        passphrase = os.environ.get("REDLINE_BITGET_PASSPHRASE") or os.environ.get("BITGET_PASSPHRASE")
        if not result.ok:
            pass
        elif access_key is None or secret_key is None or passphrase is None:
            result = result.model_copy(update={"ok": False, "state": "BITGET_CREDENTIALS_REQUIRED", "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED})
        else:
            sponsor = execute_sponsor_readback(
                receipt_path=receipt,
                package=package,
                out_dir=out,
                access_key=access_key,
                secret_key=secret_key,
                passphrase=passphrase,
                final_publish=final_publish,
                suite_path=suite,
                spec_path=spec,
                ledger_attestation_path=ledger_attestation,
                trust_policy_path=trust_policy_path,
                baseline_receipt_path=baseline_receipt,
            )
            result = result.model_copy(
                update={
                    "ok": sponsor.ok,
                    "state": sponsor.state.value,
                    "sponsor_evidence": sponsor.evidence,
                    "reason_code": sponsor.reason_code or (ReasonCode.PASS if sponsor.ok else ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED),
                }
            )
    result_path = out / "publish-preflight.json"
    if result.state != "OUTPUT_PATH_INSIDE_PACKAGE":
        out.mkdir(parents=True, exist_ok=True)
        result_path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        _print_envelope("ready" if result.ok else "blocked", (result.reason_code or ReasonCode.PASS).value, result_path)
    raise typer.Exit(0 if result.ok else EXIT_BY_REASON[result.reason_code or ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])


@app.command("verify-annotation")
def verify_annotation_cmd(
    annotation: Path,
    receipt: Optional[Path] = typer.Option(None, "--receipt"),
    package: Optional[Path] = typer.Option(None, "--package"),
    report: Optional[Path] = typer.Option(None, "--report"),
    suite: Optional[Path] = typer.Option(None, "--suite"),
    spec: Optional[Path] = typer.Option(None, "--spec"),
    ledger_checkpoint: Optional[Path] = typer.Option(None, "--ledger-checkpoint"),
    ledger_attestation: Optional[Path] = typer.Option(None, "--ledger-attestation"),
    trust_policy: Optional[Path] = typer.Option(None, "--trust-policy"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
    allow_demo_preview: bool = typer.Option(False, "--allow-demo-preview"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    result = verify_annotation(
        annotation_path=annotation,
        receipt_path=receipt,
        package=package,
        report_path=report,
        suite_path=suite,
        spec_path=spec,
        ledger_checkpoint_path=ledger_checkpoint,
        ledger_attestation_path=ledger_attestation,
        trust_policy_path=trust_policy,
        baseline_receipt_path=baseline_receipt,
        allow_demo_preview=allow_demo_preview,
    )
    if json_out:
        console.print_json(data=result.model_dump(mode="json"))
    else:
        _print_envelope("verified" if result.ok else "rejected", (result.reason_code or ReasonCode.PASS).value, annotation)
    raise typer.Exit(0 if result.ok else EXIT_BY_REASON[result.reason_code or ReasonCode.RECEIPT_MISMATCH])


@app.command("trust-keygen")
def trust_keygen(
    out_private: Optional[Path] = typer.Option(None, "--out-private"),
    out_public: Optional[Path] = typer.Option(None, "--out-public"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    private_key, public_key = generate_trust_keypair()
    if out_private is not None:
        out_private.parent.mkdir(parents=True, exist_ok=True)
        out_private.write_text(private_key + "\n", encoding="utf-8")
    if out_public is not None:
        out_public.parent.mkdir(parents=True, exist_ok=True)
        out_public.write_text(public_key + "\n", encoding="utf-8")
    data = {"private_key": private_key if out_private is None else str(out_private), "public_key": public_key}
    if json_out:
        console.print_json(data=data)
    else:
        _print_envelope("trust_key_generated", "PASS", out_public or "stdout")


@app.command("trust-policy")
def trust_policy_cmd(
    public_key: str = typer.Option(..., "--public-key"),
    key_id: str = typer.Option(..., "--key-id"),
    issuer: str = typer.Option(..., "--issuer"),
    policy_id: str = typer.Option("redline-default", "--policy-id"),
    valid_from: Optional[str] = typer.Option(None, "--valid-from"),
    valid_until: Optional[str] = typer.Option(None, "--valid-until"),
    out: Path = typer.Option(Path("artifacts/trust-policy.json"), "--out"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    try:
        policy = make_trust_policy(
            policy_id=policy_id,
            key_id=key_id,
            public_key=public_key,
            issuer=issuer,
            valid_from=valid_from,
            valid_until=valid_until,
        )
    except ValueError:
        _exit_bad_input(ReasonCode.SCHEMA_INVALID, json_out, "invalid trust public key", out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if json_out:
        console.print_json(data=policy.model_dump(mode="json"))
    else:
        _print_envelope("trust_policy_written", policy.policy_hash, out)


@app.command("sign-ledger-checkpoint")
def sign_ledger_checkpoint_cmd(
    checkpoint: Path,
    private_key: Optional[str] = typer.Option(None, "--private-key"),
    private_key_file: Optional[Path] = typer.Option(None, "--private-key-file"),
    key_id: str = typer.Option("default", "--key-id"),
    issuer: str = typer.Option("redline-ci", "--issuer"),
    policy_id: str = typer.Option("redline-default", "--trust-policy-id"),
    audience: str = typer.Option("redline.publish", "--audience"),
    expires_at: Optional[str] = typer.Option(None, "--expires-at"),
    signer: str = typer.Option("redline-ci", "--signer"),
    out: Path = typer.Option(Path("artifacts/ledger-attestation.json"), "--out"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    key_text = private_key or os.environ.get("REDLINE_TRUST_PRIVATE_KEY")
    if key_text is None and private_key_file is not None:
        key_text = private_key_file.read_text(encoding="utf-8").strip()
    if key_text is None:
        console.print("missing signing key: pass --private-key-file or REDLINE_TRUST_PRIVATE_KEY")
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING])
    try:
        checkpoint_obj = LedgerCheckpoint.model_validate(json.loads(checkpoint.read_text(encoding="utf-8")))
        attestation = sign_checkpoint(
            checkpoint=checkpoint_obj,
            private_key_text=key_text,
            signer=signer,
            trust_policy_id=policy_id,
            key_id=key_id,
            issuer=issuer,
            audience=audience,
            expires_at=expires_at,
        )
    except FileNotFoundError:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, "checkpoint file not found", checkpoint)
    except (OSError, json.JSONDecodeError):
        _exit_bad_input(ReasonCode.PARSE_ERROR, json_out, "checkpoint JSON is invalid", checkpoint)
    except (ValidationError, ValueError):
        _exit_bad_input(ReasonCode.SCHEMA_INVALID, json_out, "checkpoint or signing key is invalid", checkpoint)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if json_out:
        console.print_json(data=attestation.model_dump(mode="json"))
    else:
        _print_envelope("attested", attestation.attestation_hash, out)


@app.command("verify-ledger-attestation")
def verify_ledger_attestation_cmd(
    attestation: Path,
    checkpoint: Path,
    trusted_public_key: Optional[str] = typer.Option(None, "--trusted-public-key"),
    trust_policy: Optional[Path] = typer.Option(None, "--trust-policy"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    try:
        checkpoint_obj = LedgerCheckpoint.model_validate(json.loads(checkpoint.read_text(encoding="utf-8")))
        attestation_obj = LedgerCheckpointAttestation.model_validate(json.loads(attestation.read_text(encoding="utf-8")))
        policy = None
        if trust_policy is not None:
            from redline.models import TrustPolicy

            policy = TrustPolicy.model_validate(json.loads(trust_policy.read_text(encoding="utf-8")))
        ok = verify_checkpoint_attestation(
            checkpoint=checkpoint_obj,
            attestation=attestation_obj,
            trusted_public_key_text=trusted_public_key,
            trust_policy=policy,
        )
    except FileNotFoundError as exc:
        _exit_bad_input(ReasonCode.FILE_NOT_FOUND, json_out, f"file not found: {exc.filename}", checkpoint)
    except (OSError, json.JSONDecodeError):
        _exit_bad_input(ReasonCode.PARSE_ERROR, json_out, "ledger attestation input is not valid JSON", attestation)
    except ValidationError:
        _exit_bad_input(ReasonCode.SCHEMA_INVALID, json_out, "ledger attestation input failed schema validation", attestation)
    except ValueError:
        ok = False
    result = {
        "schema_version": "redline.ledger_attestation_verify.v1",
        "ok": ok,
        "checkpoint_hash": checkpoint_obj.checkpoint_hash,
        "attestation_hash": attestation_obj.attestation_hash,
    }
    if json_out:
        console.print_json(data=result)
    else:
        _print_envelope("verified" if ok else "rejected", "PASS" if ok else ReasonCode.RECEIPT_MISMATCH.value, attestation)
    raise typer.Exit(0 if ok else EXIT_BY_REASON[ReasonCode.RECEIPT_MISMATCH])


@app.command("verify-proof")
def verify_proof_cmd(
    receipt: Path,
    proof_id: str = typer.Option(..., "--proof-id"),
    package: Optional[Path] = typer.Option(None, "--package"),
    suite: Path = Path("fixtures/suites/demo_suite.json"),
    spec: Path = Path("fixtures/specs/redline_spec.json"),
    baseline_receipt: Optional[Path] = typer.Option(None, "--baseline-receipt"),
    trust_policy: Optional[Path] = typer.Option(None, "--trust-policy"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    result = verify_proof(
        receipt_path=receipt,
        proof_id=proof_id,
        package=package,
        suite_path=suite if package is not None else None,
        spec_path=spec if package is not None else None,
        baseline_receipt_path=baseline_receipt,
        trust_policy_path=trust_policy,
    )
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


@app.command("verify-sponsor-run")
def verify_sponsor_run_cmd(
    evidence: Path,
    receipt: Optional[Path] = typer.Option(None, "--receipt"),
    package: Optional[Path] = typer.Option(None, "--package"),
    out_transcript: Path = typer.Option(Path("artifacts/sponsor/readback-transcript.jsonl"), "--out-transcript"),
    base_url: str = typer.Option("https://api.bitget.com", "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    shape = validate_sponsor_evidence_shape(evidence)
    if shape.reason_code in {ReasonCode.SCHEMA_INVALID, ReasonCode.SPONSOR_READBACK_MISMATCH}:
        result = {
            "ok": False,
            "state": shape.state.value,
            "evidence": shape.evidence,
            "reason_code": shape.reason_code.value,
        }
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[shape.reason_code])
    expected_package_hash: str | None = None
    expected_package_archive_hash: str | None = None
    expected_metrics_output_hash: str | None = None
    if receipt is None or package is None:
        result = {
            "ok": False,
            "state": "RECEIPT_PACKAGE_BINDING_REQUIRED",
            "evidence": {},
            "reason_code": ReasonCode.DATA_MISSING.value,
        }
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING])
    receipt_check = verify(receipt_path=receipt, level=VerificationLevel.HASH_ONLY)
    if (
        receipt_check.status in {VerificationStatus.BAD_INPUT, VerificationStatus.REJECTED}
        or receipt_check.proof_coverage != "complete"
        or receipt_check.missing_proof_ids
    ):
        result = {
            "ok": False,
            "state": SponsorState.MISMATCH.value,
            "evidence": {
                "verification_status": receipt_check.status.value,
                "proof_coverage": receipt_check.proof_coverage,
                "receipt_hash": receipt_check.receipt_hash or "",
            },
            "reason_code": receipt_check.reason_code.value,
        }
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[receipt_check.reason_code])
    try:
        receipt_obj = load_receipt(receipt)
        expected_package_hash = hash_tree(package)
    except FileNotFoundError:
        result = {"ok": False, "state": "RECEIPT_PACKAGE_BINDING_INVALID", "evidence": {}, "reason_code": ReasonCode.FILE_NOT_FOUND.value}
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.FILE_NOT_FOUND])
    except Exception:
        result = {"ok": False, "state": "RECEIPT_PACKAGE_BINDING_INVALID", "evidence": {}, "reason_code": ReasonCode.SCHEMA_INVALID.value}
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SCHEMA_INVALID])
    if expected_package_hash != receipt_obj.package.identity_hash:
        result = {
            "ok": False,
            "state": SponsorState.MISMATCH.value,
            "evidence": {"package_hash": expected_package_hash, "expected_package_hash": receipt_obj.package.identity_hash},
            "reason_code": ReasonCode.RECEIPT_BINDING_FAILED.value,
        }
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.RECEIPT_BINDING_FAILED])
    try:
        with tempfile.TemporaryDirectory(prefix="redline-sponsor-archive-") as tmp:
            archive, _annotation = make_receipt_bound_package_archive(
                receipt_path=receipt,
                package=package,
                annotation_path=Path(tmp) / "redline-annotation.json",
                out_path=Path(tmp) / "annotated-package.tar.gz",
                package_hash=expected_package_hash,
            )
            expected_package_archive_hash = sha256_bytes(archive.read_bytes())
    except FileNotFoundError:
        result = {"ok": False, "state": "RECEIPT_PACKAGE_BINDING_INVALID", "evidence": {}, "reason_code": ReasonCode.DATA_MISSING.value}
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.DATA_MISSING])
    except Exception:
        result = {"ok": False, "state": "RECEIPT_PACKAGE_BINDING_INVALID", "evidence": {}, "reason_code": ReasonCode.SCHEMA_INVALID.value}
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SCHEMA_INVALID])
    expected_metrics_output_hash = receipt_obj.result.result_hash
    access_key = os.environ.get("REDLINE_BITGET_ACCESS_KEY") or os.environ.get("BITGET_ACCESS_KEY")
    secret_key = os.environ.get("REDLINE_BITGET_SECRET_KEY") or os.environ.get("BITGET_SECRET_KEY")
    passphrase = os.environ.get("REDLINE_BITGET_PASSPHRASE") or os.environ.get("BITGET_PASSPHRASE")
    if access_key is None or secret_key is None or passphrase is None:
        result = {
            "ok": False,
            "state": SponsorState.BITGET_CREDENTIALS_REQUIRED.value,
            "evidence": {},
            "reason_code": ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED.value,
        }
        _print_json_or_table(result, json_out, evidence)
        raise typer.Exit(EXIT_BY_REASON[ReasonCode.SPONSOR_EVIDENCE_UNVERIFIED])
    adapter = BitgetSponsorAdapter(
        access_key=access_key,
        secret_key=secret_key,
        passphrase=passphrase,
        transcript_path=out_transcript,
        base_url=base_url,
    )
    result = verify_sponsor_readback_evidence(
        evidence_path=evidence,
        adapter=adapter,
        expected_package_hash=expected_package_hash,
        expected_package_archive_hash=expected_package_archive_hash,
        expected_metrics_output_hash=expected_metrics_output_hash,
    )
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


def _load_edit_provenance(path: Path) -> EditProvenance:
    return EditProvenance.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _print_json_or_table(result: dict[str, object], json_out: bool, target: object) -> None:
    if json_out:
        console.print_json(data=result)
    else:
        _print_envelope(str(result.get("state", "blocked")), str(result.get("reason_code", "")), target)


def _exit_bad_input(reason_code: ReasonCode, json_out: bool, message: str, target: object) -> None:
    result = {
        "schema_version": "redline.cli.error.v1",
        "ok": False,
        "status": VerificationStatus.BAD_INPUT.value,
        "reason_code": reason_code.value,
        "message": message,
    }
    _print_json_or_table(result, json_out, target)
    raise typer.Exit(EXIT_BY_REASON[reason_code])


def _validate_run_inputs(*, package: Path, baseline: str, candidate: str, suite: Path, spec: Path) -> None:
    if not package.exists() or not package.is_dir():
        raise ValueError(f"package not found: {package}")
    for role in [baseline, candidate]:
        resolve_package_role_dir(package, role)
    load_suite(suite)
    load_spec(spec)


def _assert_demo_case(artifacts, *, expected_status: Status, expected_reason: ReasonCode, case: str) -> None:
    if artifacts.envelope.status != expected_status or artifacts.envelope.reason_code != expected_reason or artifacts.receipt is None:
        raise typer.Exit(EXIT_BY_REASON[artifacts.envelope.reason_code])


def _fixture_edit_provenance(package: Path, baseline: str, candidate: str) -> EditProvenance:
    package = package.resolve()
    return EditProvenance(
        tool="fixture",
        prompt_digest=hash_obj({"prompt": "fixture make it more responsive"}),
        diff_hash=hash_obj(
            {
                "baseline": hash_tree(resolve_package_role_dir(package, baseline)),
                "candidate": hash_tree(resolve_package_role_dir(package, candidate)),
            }
        ),
        locked_by="author",
        captured_at=FIXTURE_TIMESTAMP,
    )


def _prepare_demo_out(out: Path) -> None:
    resolved = out.resolve()
    cwd = Path.cwd().resolve()
    artifacts_root = (cwd / "artifacts").resolve()
    temp_roots = {
        Path(tempfile.gettempdir()).resolve(),
        Path("/tmp").resolve(),
        Path("/private/tmp").resolve(),
    }
    if resolved in {cwd, artifacts_root}:
        raise ValueError("output path is too broad")
    if not (_is_relative_to(resolved, artifacts_root) or any(_is_relative_to(resolved, root) for root in temp_roots)):
        raise ValueError("output path must be under artifacts/ or the system temporary directory")
    marker = resolved / ".redline-demo-output"
    seeded_repo_demo = resolved == artifacts_root / "demo" and (resolved / "pass").is_dir() and (resolved / "withheld").is_dir()
    if resolved.exists():
        if not marker.exists() and not seeded_repo_demo:
            raise ValueError("refusing to delete a directory not created by redline make-demo")
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)
    marker.write_text("redline make-demo output\n", encoding="utf-8")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    app()
