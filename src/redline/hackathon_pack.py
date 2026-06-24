from __future__ import annotations

import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redline.attestation import RELEASE_ATTESTATION_NAME, attest_release_bundle, verify_release_attestation, write_release_attestation
from redline.canonical import CanonicalizationError, hash_file
from redline.io_safety import atomic_write_text, ensure_safe_output_dir, reject_unsafe_output_file
from redline.models import ReasonCode
from redline.service.artifacts import resolve_artifact_path
from redline.service.release import BUNDLE_NAME, MANIFEST_NAME, verify_release_evidence_bundle
from redline.service.release import resolve_release_run_dir
from redline.sponsor.bitget_execution import ExecutionBlocked, load_execution_evidence

PACK_MANIFEST_NAME = "hackathon-submit-manifest.json"
_SAFE_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def build_hackathon_submission_pack(
    *,
    bundle_path: Path | None = None,
    out_dir: Path,
    attestation_path: Path | None = None,
    manifest_path: Path | None = None,
    attester_principal: str = "hackathon-pack",
    root: Path | None = None,
) -> dict[str, Any]:
    root = root or Path.cwd()
    source_bundle_path = _resolve_bundle_path(bundle_path, root=root)
    reject_unsafe_output_file(source_bundle_path)
    source_release_dir = source_bundle_path.parent
    bundle = _load_json(source_bundle_path)
    release_id = _safe_artifact_id(_release_id(bundle, fallback=source_release_dir.name), "release id")
    raw_run_id = _execution_run_id(bundle)
    run_id = _safe_artifact_id(raw_run_id, "execution run id") if raw_run_id else ""

    source_verification = verify_release_evidence_bundle(source_bundle_path)
    if not source_verification["ok"]:
        raise CanonicalizationError("release evidence bundle is not valid", ReasonCode.RECEIPT_MISMATCH)

    source_attestation_path = attestation_path or (source_release_dir / RELEASE_ATTESTATION_NAME)
    if not source_attestation_path.exists():
        attestation = attest_release_bundle(
            bundle_path=source_bundle_path,
            attester_principal=attester_principal,
        )
        write_release_attestation(source_attestation_path, attestation)
    source_attestation_verification = verify_release_attestation(
        attestation_path=source_attestation_path,
        bundle_path=source_bundle_path,
    )
    if not source_attestation_verification["ok"]:
        raise CanonicalizationError("release attestation is not valid", ReasonCode.RECEIPT_MISMATCH)

    ensure_safe_output_dir(out_dir)
    pack_release_dir = out_dir / "service" / "releases" / release_id
    pack_service_root = out_dir / "service"
    ensure_safe_output_dir(pack_release_dir)
    _copy_text_file(source_release_dir / MANIFEST_NAME, pack_release_dir / MANIFEST_NAME)
    _copy_manifest_files(
        source_release_dir=source_release_dir,
        pack_release_dir=pack_release_dir,
        pack_service_root=pack_service_root,
    )
    _copy_text_file(source_attestation_path, pack_release_dir / RELEASE_ATTESTATION_NAME)
    _copy_showcase_orders(source_release_dir, pack_release_dir)
    _copy_session_evidence_html(source_release_dir, out_dir)
    _copy_docs(root, out_dir)

    pack_bundle_path = pack_release_dir / BUNDLE_NAME
    pack_attestation_path = pack_release_dir / RELEASE_ATTESTATION_NAME
    pack_verification = verify_release_evidence_bundle(pack_bundle_path)
    pack_attestation_verification = verify_release_attestation(
        attestation_path=pack_attestation_path,
        bundle_path=pack_bundle_path,
    )
    if not pack_verification["ok"] or not pack_attestation_verification["ok"]:
        raise CanonicalizationError("copied hackathon pack evidence does not verify", ReasonCode.RECEIPT_MISMATCH)

    orders = _collect_orders(bundle=bundle, release_dir=source_release_dir)
    verify_output = {
        "schema_version": "redline.hackathon_verify_output.v1",
        "generated_at": _utc_now(),
        "source_bundle_verification": source_verification,
        "source_attestation_verification": source_attestation_verification,
        "pack_bundle_verification": pack_verification,
        "pack_attestation_verification": pack_attestation_verification,
    }
    verify_output_path = out_dir / "verify-output.json"
    _write_json(verify_output_path, verify_output)

    showcase_index_path = out_dir / "showcase-index.json"
    _write_json(
        showcase_index_path,
        {
            "schema_version": "redline.showcase_index.v1",
            "generated_at": _utc_now(),
            "release_id": release_id,
            "orders": orders,
        },
    )

    judge_curl_path = out_dir / "judge-demo-curl.sh"
    atomic_write_text(judge_curl_path, _judge_demo_curl_script(release_id))

    manifest = {
        "schema_version": "redline.hackathon_submit_manifest.v1",
        "generated_at": _utc_now(),
        "pack_dir": str(out_dir),
        "release_id": release_id,
        "run_id": run_id,
        "source_release_bundle": str(source_bundle_path),
        "source_bundle_hash": hash_file(source_bundle_path),
        "source_attestation": str(source_attestation_path),
        "source_attestation_hash": hash_file(source_attestation_path),
        "latest_release_bundle": str(pack_bundle_path),
        "latest_bundle_hash": hash_file(pack_bundle_path),
        "latest_attestation": str(pack_attestation_path),
        "latest_attestation_hash": hash_file(pack_attestation_path),
        "latest_real_bitget_orders": orders,
        "verification_output": str(verify_output_path),
        "showcase_index": str(showcase_index_path),
        "judge_demo_curl": str(judge_curl_path),
        "openapi_schema": str(out_dir / "schemas" / "service-openapi.json"),
        "verification_commands": [
            "uv run redline doctor --json",
            "uv run python scripts/check-verdict-path-imports.py",
            "uv run --extra dev pytest -q tests/test_service_api.py -q",
            f"uv run redline verify-release-bundle {shlex.quote(str(pack_bundle_path))} --json",
            f"uv run redline verify-release-attestation {shlex.quote(str(pack_attestation_path))} --bundle {shlex.quote(str(pack_bundle_path))} --json",
        ],
    }
    pack_manifest_path = out_dir / PACK_MANIFEST_NAME
    _write_json(pack_manifest_path, manifest)
    if manifest_path is not None and manifest_path != pack_manifest_path:
        _write_json(manifest_path, manifest)

    atomic_write_text(out_dir / "README.md", _pack_readme(manifest))
    return {**manifest, "pack_manifest": str(pack_manifest_path)}


def _resolve_bundle_path(bundle_path: Path | None, *, root: Path) -> Path:
    if bundle_path is not None:
        if not bundle_path.exists():
            raise FileNotFoundError(bundle_path)
        return bundle_path
    candidates = [path for path in (root / "artifacts" / "release-demo").glob(f"**/{BUNDLE_NAME}") if path.is_file()]
    if not candidates:
        raise FileNotFoundError(root / "artifacts" / "release-demo" / f"**/{BUNDLE_NAME}")
    return max(candidates, key=lambda path: (path.stat().st_mtime, str(path)))


def _copy_manifest_files(
    *,
    source_release_dir: Path,
    pack_release_dir: Path,
    pack_service_root: Path,
) -> None:
    manifest = _load_json(source_release_dir / MANIFEST_NAME)
    files = manifest.get("files")
    if not isinstance(files, list):
        raise CanonicalizationError("release evidence manifest is invalid", ReasonCode.SCHEMA_INVALID)
    for item in files:
        if not isinstance(item, dict):
            raise CanonicalizationError("release evidence manifest entry is invalid", ReasonCode.SCHEMA_INVALID)
        rel_path = str(item.get("path") or "")
        _safe_relative_path(rel_path, "release evidence manifest path")
        if rel_path.startswith("run/"):
            parts = Path(rel_path).parts
            if len(parts) < 3:
                raise CanonicalizationError("release evidence manifest run path is invalid", ReasonCode.SCHEMA_INVALID)
            run_id = _safe_artifact_id(parts[1], "manifest run id")
            artifact_rel = Path(*parts[2:]).as_posix()
            source = resolve_artifact_path(resolve_release_run_dir(source_release_dir, run_id), artifact_rel)
            dest = _safe_child_path(pack_service_root / "runs" / run_id, artifact_rel, "pack run artifact path")
        else:
            source = _safe_child_path(source_release_dir, rel_path, "release evidence manifest path")
            dest = _safe_child_path(pack_release_dir, rel_path, "pack release artifact path")
        _copy_text_file(source, dest)


def _safe_artifact_id(value: str, label: str) -> str:
    text = str(value or "")
    if not _SAFE_ARTIFACT_ID_RE.fullmatch(text):
        raise CanonicalizationError(f"{label} is not a safe artifact id", ReasonCode.RECEIPT_BINDING_FAILED)
    return text


def _safe_relative_path(value: str, label: str) -> Path:
    rel = Path(str(value or ""))
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise CanonicalizationError(f"{label} is unsafe", ReasonCode.RECEIPT_BINDING_FAILED)
    return rel


def _safe_child_path(root: Path, rel_path: str, label: str) -> Path:
    rel = _safe_relative_path(rel_path, label)
    root_resolved = root.resolve()
    path = root_resolved.joinpath(*rel.parts)
    try:
        path.resolve(strict=False).relative_to(root_resolved)
    except ValueError as exc:
        raise CanonicalizationError(f"{label} escapes output root", ReasonCode.RECEIPT_BINDING_FAILED) from exc
    return path


def _copy_showcase_orders(source_release_dir: Path, pack_release_dir: Path) -> None:
    showcase_root = source_release_dir / "demo-showcase-orders"
    if not showcase_root.exists():
        return
    for source in sorted(showcase_root.rglob("*")):
        if not source.is_file():
            continue
        rel = source.relative_to(source_release_dir)
        _copy_text_file(source, pack_release_dir / rel)


def _copy_session_evidence_html(source_release_dir: Path, out_dir: Path) -> None:
    candidates = [
        source_release_dir / "evidence.html",
        source_release_dir.parent.parent.parent / "evidence.html",
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            _copy_text_file(candidate, out_dir / "evidence.html")
            return


def _copy_docs(root: Path, out_dir: Path) -> None:
    copies = {
        root / "HACKATHON_SUBMISSION.md": out_dir / "HACKATHON_SUBMISSION.md",
        root / "BACKEND_COMPLETENESS.md": out_dir / "BACKEND_COMPLETENESS.md",
        root / "PRODUCTION_RELEASE_BACKEND.md": out_dir / "PRODUCTION_RELEASE_BACKEND.md",
        root / "SERVICE_API.md": out_dir / "SERVICE_API.md",
        root / "README.md": out_dir / "PROJECT_README.md",
        root / "schemas" / "service-openapi.json": out_dir / "schemas" / "service-openapi.json",
    }
    for source, dest in copies.items():
        if source.exists() and source.is_file():
            _copy_text_file(source, dest)


def _collect_orders(*, bundle: dict[str, Any], release_dir: Path) -> list[dict[str, str]]:
    orders: list[dict[str, str]] = []
    execution = bundle.get("execution_evidence")
    if isinstance(execution, dict):
        orders.append(_order_summary("canonical", execution, attempt_id=""))
    showcase_root = release_dir / "demo-showcase-orders"
    if showcase_root.exists():
        for evidence_path in sorted(showcase_root.glob("*/execution-evidence.json")):
            try:
                evidence = load_execution_evidence(evidence_path).model_dump(mode="json")
            except (CanonicalizationError, ExecutionBlocked, OSError):
                continue
            orders.append(_order_summary("showcase", evidence, attempt_id=evidence_path.parent.name))
    return orders


def _order_summary(kind: str, evidence: dict[str, Any], *, attempt_id: str) -> dict[str, str]:
    return {
        "kind": kind,
        "attempt_id": attempt_id,
        "run_id": str(evidence.get("run_id") or ""),
        "bitget_order_id": str(evidence.get("bitget_order_id") or ""),
        "client_oid": str(evidence.get("client_oid") or ""),
        "receipt_hash": str(evidence.get("receipt_hash") or ""),
        "response_hash": str(evidence.get("response_hash") or ""),
        "order_mode": str(evidence.get("order_mode") or ""),
        "paptrading": str(evidence.get("paptrading") or ""),
    }


def _release_id(bundle: dict[str, Any], *, fallback: str) -> str:
    release = bundle.get("release_candidate")
    if isinstance(release, dict) and release.get("release_id"):
        return str(release["release_id"])
    return fallback


def _execution_run_id(bundle: dict[str, Any]) -> str:
    execution = bundle.get("execution_evidence")
    if isinstance(execution, dict) and execution.get("run_id"):
        return str(execution["run_id"])
    redline = bundle.get("redline")
    if isinstance(redline, dict) and redline.get("run_id"):
        return str(redline["run_id"])
    return ""


def _load_json(path: Path) -> dict[str, Any]:
    reject_unsafe_output_file(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CanonicalizationError("JSON artifact is invalid", ReasonCode.PARSE_ERROR) from exc
    if not isinstance(payload, dict):
        raise CanonicalizationError("JSON artifact must be an object", ReasonCode.SCHEMA_INVALID)
    return payload


def _copy_text_file(source: Path, dest: Path) -> None:
    reject_unsafe_output_file(source, reject_existing_hardlinks=False)
    try:
        if dest.exists() and source.resolve() == dest.resolve():
            return
    except FileNotFoundError:
        pass
    atomic_write_text(dest, source.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _judge_demo_curl_script(release_id: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail

: "${{REDLINE_SERVICE_URL:=http://127.0.0.1:8080}}"
: "${{REDLINE_SERVICE_TOKEN:?set REDLINE_SERVICE_TOKEN}}"
: "${{REDLINE_RELEASE_ID:={release_id}}}"

curl -sS \\
  -H "X-Redline-Token: $REDLINE_SERVICE_TOKEN" \\
  -H "Idempotency-Key: judge-demo-$(date +%s)" \\
  -H "Content-Type: application/json" \\
  -X POST "$REDLINE_SERVICE_URL/v1/release-candidates/$REDLINE_RELEASE_ID/jobs/showcase-order" \\
  -d '{{"side":"buy","size":"0.0001"}}'
"""


def _pack_readme(manifest: dict[str, Any]) -> str:
    bundle = manifest["latest_release_bundle"]
    attestation = manifest["latest_attestation"]
    return f"""# Playbook Redline Hackathon Submission Pack

This directory is a backend-generated, offline-verifiable submission pack.

## Key files

- `service/releases/{manifest["release_id"]}/release-evidence-bundle.json`
- `service/releases/{manifest["release_id"]}/release-attestation.json`
- `verify-output.json`
- `hackathon-submit-manifest.json`
- `showcase-index.json`
- `judge-demo-curl.sh`
- `HACKATHON_SUBMISSION.md`

## Verify

```bash
uv run redline verify-release-bundle {shlex.quote(str(bundle))} --json
uv run redline verify-release-attestation {shlex.quote(str(attestation))} --bundle {shlex.quote(str(bundle))} --json
```

## Live judge demo

Start the service with the release demo artifact root, then run:

```bash
bash judge-demo-curl.sh
```

The live action creates a backend release job; the Redline verdict path remains unchanged.
All Bitget execution evidence is demo-only and must retain `paptrading:1`.
"""
