from __future__ import annotations

from collections.abc import Mapping
import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from redline.canonical import canonical_bytes, hash_file, hash_obj
from redline.io_safety import atomic_write_text, reject_unsafe_output_file
from redline.merkle import merkle_root
from redline.models import ReleaseBundleAttestation
from redline.service.release import MANIFEST_NAME, verify_release_evidence_bundle
from redline.trust import SIGNATURE_PREFIX, _parse_private_key, _parse_public_key, _parse_signature, generate_trust_keypair, public_key_from_private


RELEASE_ATTESTATION_NAME = "release-attestation.json"


def attest_release_bundle(
    *,
    bundle_path: Path,
    private_key_text: str | None = None,
    attester_principal: str = "local:auto",
    key_id: str = "local",
    issuer: str = "redline",
    external_reference: dict[str, str] | None = None,
) -> ReleaseBundleAttestation:
    reject_unsafe_output_file(bundle_path)
    verification = verify_release_evidence_bundle(bundle_path)
    if not verification["ok"]:
        raise ValueError("release evidence bundle is not valid")
    bundle = _load_bundle(bundle_path)
    key_text = private_key_text or generate_trust_keypair()[0]
    private_key = _parse_private_key(key_text)
    public_key = public_key_from_private(key_text)
    attestation = ReleaseBundleAttestation(
        release_id=str(bundle.get("release_candidate", {}).get("release_id") or ""),
        bundle_hash=str(verification["bundle_hash"]),
        manifest_hash=hash_file(bundle_path.parent / MANIFEST_NAME),
        evidence_merkle_root=release_evidence_merkle_root(bundle),
        attestation_provider="local_signed",
        attested_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        attester_principal=attester_principal,
        key_id=key_id,
        issuer=issuer,
        public_key=public_key,
        external_reference=external_reference or {"kind": "local-signed"},
        signature="",
        attestation_hash="",
    )
    signature = private_key.sign(_attestation_payload(attestation))
    attestation = attestation.model_copy(update={"signature": SIGNATURE_PREFIX + signature.hex()})
    return attestation.model_copy(update={"attestation_hash": _attestation_hash(attestation)})


def write_release_attestation(path: Path, attestation: ReleaseBundleAttestation) -> None:
    atomic_write_text(path, attestation.model_dump_json(indent=2) + "\n")


def load_release_attestation(path: Path) -> ReleaseBundleAttestation:
    reject_unsafe_output_file(path)
    try:
        return ReleaseBundleAttestation.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("release attestation is invalid") from exc


def verify_release_attestation(*, attestation_path: Path, bundle_path: Path, trusted_public_key: str | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    expected_evidence_merkle_root: str | None = None

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    try:
        attestation = load_release_attestation(attestation_path)
        record("attestation-json", True)
        bundle_verification = verify_release_evidence_bundle(bundle_path)
        record("bundle-verification", bool(bundle_verification["ok"]), str(bundle_verification.get("bundle_hash") or ""))
        if not bundle_verification["ok"]:
            raise ValueError("release evidence bundle is not valid")
        bundle = _load_bundle(bundle_path)
        release_id = str(bundle.get("release_candidate", {}).get("release_id") or "")
        if attestation.release_id != release_id:
            raise ValueError("release id mismatch")
        record("release-id", True, release_id)
        if attestation.bundle_hash != bundle_verification["bundle_hash"] or attestation.bundle_hash != hash_file(bundle_path):
            raise ValueError("bundle hash mismatch")
        record("bundle-hash", True, attestation.bundle_hash)
        manifest_hash = hash_file(bundle_path.parent / MANIFEST_NAME)
        if attestation.manifest_hash != manifest_hash:
            raise ValueError("manifest hash mismatch")
        record("manifest-hash", True, manifest_hash)
        expected_evidence_merkle_root = release_evidence_merkle_root(bundle)
        if "evidence_merkle_root" not in attestation.model_fields_set:
            raise ValueError("evidence merkle root missing")
        if attestation.evidence_merkle_root != expected_evidence_merkle_root:
            raise ValueError("evidence merkle root mismatch")
        record("evidence-merkle-root", True, expected_evidence_merkle_root)
        if attestation.attestation_hash != _attestation_hash(attestation):
            raise ValueError("attestation hash mismatch")
        record("attestation-hash", True, attestation.attestation_hash)
        public_key = _parse_public_key(attestation.public_key)
        public_key.verify(_parse_signature(attestation.signature), _attestation_payload(attestation))
        record("signature", True, attestation.public_key)
        # Integrity-only by default (the embedded key self-signs). When a trusted key is
        # pinned, require the attestation to be signed by exactly that key — this is what
        # turns a self-consistent, self-signed forgery from `ok=true` into a failure.
        if trusted_public_key is not None:
            if attestation.public_key != trusted_public_key:
                raise ValueError("attestation public key does not match the pinned trusted key")
            record("trusted-key-pin", True, trusted_public_key)
    except (OSError, ValueError, InvalidSignature) as exc:
        record("attestation-verification", False, type(exc).__name__ if isinstance(exc, InvalidSignature) else str(exc))
    ok = all(item["ok"] for item in checks)
    payload: dict[str, Any] = {
        "schema_version": "redline.release_attestation.verify.v1",
        "ok": ok,
        "attestation_path": str(attestation_path),
        "bundle_path": str(bundle_path),
        "checks": checks,
    }
    if attestation_path.exists():
        try:
            attestation = load_release_attestation(attestation_path)
            payload["attestation_hash"] = attestation.attestation_hash
            payload["bundle_hash"] = attestation.bundle_hash
            payload["evidence_merkle_root"] = expected_evidence_merkle_root or attestation.evidence_merkle_root
            payload["provider"] = attestation.attestation_provider
            payload["external_reference"] = attestation.external_reference
        except ValueError:
            pass
    return payload


def _t(en: str, zh: str) -> str:
    """Bilingual inline text (matches render.t and the .i18n CSS toggle)."""
    return f'<span class="i18n"><span lang="en">{html.escape(en)}</span><span lang="zh">{html.escape(zh)}</span></span>'


def render_attestation_status_html(*, verification: dict[str, Any]) -> str:
    """Attestation status as a design-system section (status band + telemetry DL). No own
    <style> — it inherits the page's inlined redline.css (offline evidence page or the
    standalone attestation.html shell)."""
    ok = bool(verification.get("ok"))
    status = _t("ATTESTED", "已认证") if ok else _t("ATTESTATION INVALID", "认证无效")
    band = "rl-band--pass" if ok else ""
    rows = [
        ("bundle_hash", str(verification.get("bundle_hash") or "")),
        ("evidence_merkle_root", str(verification.get("evidence_merkle_root") or "")),
        ("attestation_hash", str(verification.get("attestation_hash") or "")),
        ("provider", str(verification.get("provider") or "")),
        ("external_reference", json.dumps(verification.get("external_reference") or {}, sort_keys=True)),
    ]
    dl = "\n".join(
        f'<dt>{html.escape(label)}</dt><dd class="rl-mono">{html.escape(value)}</dd>'
        for label, value in rows
        if value
    )
    return (
        f'<p class="rl-sec">{_t("attestation", "认证")}</p>\n'
        f'<div class="rl-band {band}"><span class="rl-band__verdict">{status}</span>'
        f'<span class="rl-band__meta">{_t("ed25519 release attestation", "ed25519 发布认证")}</span></div>\n'
        f'<div class="rl-box"><dl class="rl-dl">{dl}</dl></div>'
    )


def release_evidence_merkle_root(bundle: Mapping[str, Any]) -> str:
    return merkle_root(_release_evidence_merkle_leaves(bundle))


def _attestation_payload(attestation: ReleaseBundleAttestation) -> bytes:
    return canonical_bytes(_attestation_hash_payload(attestation, include_signature=False))


def _attestation_hash(attestation: ReleaseBundleAttestation) -> str:
    return hash_obj(_attestation_hash_payload(attestation, include_signature=True))


def _attestation_hash_payload(attestation: ReleaseBundleAttestation, *, include_signature: bool) -> dict[str, Any]:
    updates = {"attestation_hash": ""}
    if not include_signature:
        updates["signature"] = ""
    payload = attestation.model_copy(update=updates).model_dump(mode="python")
    if "evidence_merkle_root" not in attestation.model_fields_set:
        payload.pop("evidence_merkle_root", None)
    return payload


def _release_evidence_merkle_leaves(bundle: Mapping[str, Any]) -> list[str]:
    redline = _required_mapping(bundle, "redline")
    execution = _required_mapping(bundle, "execution_evidence")
    return [
        _required_string(redline, "receipt_hash", "redline receipt hash"),
        _required_string(execution, "approval_hash", "execution approval hash"),
        _required_string(execution, "artifact_hash", "execution evidence hash"),
    ]


def _required_mapping(payload: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = payload.get(field)
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} is missing from release bundle")
    return value


def _required_string(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is missing from release bundle")
    return value


def _load_bundle(bundle_path: Path) -> dict[str, Any]:
    reject_unsafe_output_file(bundle_path)
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("release evidence bundle is invalid")
    return payload
