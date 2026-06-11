from __future__ import annotations

from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from redline.canonical import canonical_bytes, hash_obj
from redline.models import LedgerCheckpoint, LedgerCheckpointAttestation, TrustKey, TrustPolicy

PRIVATE_PREFIX = "ed25519-private:"
PUBLIC_PREFIX = "ed25519-public:"
SIGNATURE_PREFIX = "ed25519-signature:"


def generate_trust_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PRIVATE_PREFIX + private_raw.hex(), PUBLIC_PREFIX + public_raw.hex()


def sign_checkpoint(
    *,
    checkpoint: LedgerCheckpoint,
    private_key_text: str,
    signer: str,
    trust_policy_id: str = "redline-default",
    key_id: str = "default",
    issuer: str | None = None,
    audience: str = "redline.publish",
    signed_at: str | None = None,
    expires_at: str | None = None,
) -> LedgerCheckpointAttestation:
    private_key = _parse_private_key(private_key_text)
    public_key_text = _public_key_text(private_key.public_key())
    attestation = LedgerCheckpointAttestation(
        checkpoint_hash=checkpoint.checkpoint_hash,
        ledger_hash=checkpoint.ledger_hash,
        ledger_tail_hash=checkpoint.ledger_tail_hash,
        ledger_entry_count=checkpoint.ledger_entry_count,
        subject_receipt_hashes=checkpoint.subject_receipt_hashes,
        trust_policy_id=trust_policy_id,
        key_id=key_id,
        issuer=issuer or signer,
        audience=audience,
        signer=signer,
        public_key=public_key_text,
        signed_at=signed_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        expires_at=expires_at,
        signature="",
        attestation_hash="",
    )
    signature = private_key.sign(_attestation_payload(attestation))
    attestation = attestation.model_copy(update={"signature": SIGNATURE_PREFIX + signature.hex()})
    return attestation.model_copy(update={"attestation_hash": hash_obj(attestation)})


def verify_checkpoint_attestation(
    *,
    checkpoint: LedgerCheckpoint,
    attestation: LedgerCheckpointAttestation,
    trusted_public_key_text: str | None = None,
    trust_policy: TrustPolicy | None = None,
    now: datetime | None = None,
) -> bool:
    trusted_key = _trusted_key(attestation=attestation, trusted_public_key_text=trusted_public_key_text, trust_policy=trust_policy, now=now)
    if trusted_key is None:
        return False
    if attestation.public_key != trusted_key.public_key:
        return False
    if attestation.attestation_hash != hash_obj(attestation.model_copy(update={"attestation_hash": ""})):
        return False
    if attestation.checkpoint_hash != checkpoint.checkpoint_hash:
        return False
    if attestation.ledger_hash != checkpoint.ledger_hash:
        return False
    if attestation.ledger_tail_hash != checkpoint.ledger_tail_hash:
        return False
    if attestation.ledger_entry_count != checkpoint.ledger_entry_count:
        return False
    if attestation.subject_receipt_hashes != checkpoint.subject_receipt_hashes:
        return False
    public_key = _parse_public_key(trusted_key.public_key)
    signature = _parse_signature(attestation.signature)
    try:
        public_key.verify(signature, _attestation_payload(attestation))
    except InvalidSignature:
        return False
    return True


def make_trust_policy(
    *,
    policy_id: str,
    key_id: str,
    public_key: str,
    issuer: str,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> TrustPolicy:
    policy = TrustPolicy(
        policy_id=policy_id,
        keys=[
            TrustKey(
                key_id=key_id,
                public_key=public_key,
                issuer=issuer,
                valid_from=valid_from,
                valid_until=valid_until,
            )
        ],
        policy_hash="",
    )
    return policy.model_copy(update={"policy_hash": hash_obj(policy)})


def verify_trust_policy(policy: TrustPolicy) -> bool:
    return policy.policy_hash == hash_obj(policy.model_copy(update={"policy_hash": ""}))


def public_key_from_private(private_key_text: str) -> str:
    return _public_key_text(_parse_private_key(private_key_text).public_key())


def _trusted_key(
    *,
    attestation: LedgerCheckpointAttestation,
    trusted_public_key_text: str | None,
    trust_policy: TrustPolicy | None,
    now: datetime | None,
) -> TrustKey | None:
    if trust_policy is None:
        if trusted_public_key_text is None:
            return None
        return TrustKey(key_id=attestation.key_id, public_key=trusted_public_key_text, issuer=attestation.issuer)
    if not verify_trust_policy(trust_policy):
        return None
    if trust_policy.policy_id != attestation.trust_policy_id or trust_policy.audience != attestation.audience:
        return None
    now = now or datetime.now(UTC)
    if attestation.expires_at is not None and _parse_time(attestation.expires_at) <= now:
        return None
    for key in trust_policy.keys:
        if key.key_id != attestation.key_id or key.issuer != attestation.issuer:
            continue
        if key.revoked:
            return None
        if key.valid_from is not None and _parse_time(key.valid_from) > now:
            return None
        if key.valid_until is not None and _parse_time(key.valid_until) <= now:
            return None
        return key
    return None


def _attestation_payload(attestation: LedgerCheckpointAttestation) -> bytes:
    return canonical_bytes(attestation.model_copy(update={"signature": "", "attestation_hash": ""}))


def _parse_private_key(text: str) -> Ed25519PrivateKey:
    raw = _parse_prefixed_hex(text.strip(), PRIVATE_PREFIX, expected_len=32)
    return Ed25519PrivateKey.from_private_bytes(raw)


def _parse_public_key(text: str) -> Ed25519PublicKey:
    raw = _parse_prefixed_hex(text.strip(), PUBLIC_PREFIX, expected_len=32)
    return Ed25519PublicKey.from_public_bytes(raw)


def _parse_signature(text: str) -> bytes:
    return _parse_prefixed_hex(text.strip(), SIGNATURE_PREFIX, expected_len=64)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_prefixed_hex(text: str, prefix: str, *, expected_len: int) -> bytes:
    if not text.startswith(prefix):
        raise ValueError(f"expected {prefix}<hex>")
    try:
        raw = bytes.fromhex(text.removeprefix(prefix))
    except ValueError as exc:
        raise ValueError(f"expected {prefix}<hex>") from exc
    if len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} bytes")
    return raw


def _public_key_text(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PUBLIC_PREFIX + raw.hex()
