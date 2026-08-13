"""Small, explicit cryptographic helpers used by identity services."""

import base64
import hashlib
import hmac
import json
import math
import os
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Ed25519PublicJWK(BaseModel):
    """The only workload-key format accepted by AgentGate."""

    model_config = ConfigDict(extra="forbid")

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str = Field(min_length=43, max_length=43)

    @field_validator("x")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        decode_base64url(value, expected_length=32, field_name="public JWK x")
        return value


def encode_base64url(value: bytes) -> str:
    """Encode bytes using unpadded URL-safe base64."""

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str, *, expected_length: int, field_name: str) -> bytes:
    """Strictly decode unpadded base64url text and enforce its binary length."""

    if "=" in value:
        raise ValueError(f"{field_name} must be unpadded base64url")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded + (b"=" * (-len(encoded) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid base64url") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"{field_name} has an invalid length")
    return decoded


def canonical_json(value: object) -> bytes:
    """Serialize normalized JSON deterministically and reject non-finite numbers."""

    _reject_non_finite(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_non_finite(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON does not permit non-finite numbers")
    if isinstance(value, dict):
        for item in value.values():
            _reject_non_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item)


def sha256_hex(value: bytes) -> str:
    """Return a lowercase SHA-256 digest without retaining the source value."""

    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: object) -> str:
    """Hash canonical JSON using the documented algorithm-labelled format."""

    return f"sha256:{sha256_hex(canonical_json(value))}"


def public_key_from_jwk(jwk: Ed25519PublicJWK) -> Ed25519PublicKey:
    """Construct an Ed25519 verifier from a validated public JWK."""

    return Ed25519PublicKey.from_public_bytes(
        decode_base64url(jwk.x, expected_length=32, field_name="public JWK x")
    )


def public_jwk_from_key(public_key: Ed25519PublicKey) -> Ed25519PublicJWK:
    """Export an Ed25519 public key in the supported JWK form."""

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Ed25519PublicJWK(kty="OKP", crv="Ed25519", x=encode_base64url(raw))


def jwk_thumbprint(jwk: Ed25519PublicJWK) -> str:
    """Calculate the RFC 7638 member-set thumbprint for an Ed25519 JWK."""

    members = {"crv": jwk.crv, "kty": jwk.kty, "x": jwk.x}
    return sha256_hex(canonical_json(members))


def secret_matches(candidate: str, expected: str) -> bool:
    """Compare secret UTF-8 values without content-dependent early return."""

    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def hash_secret_for_storage(secret: str) -> str:
    """Create a salted scrypt verifier for persisted bootstrap identity metadata."""

    salt = os.urandom(16)
    digest = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt$16384$8$1${encode_base64url(salt)}${encode_base64url(digest)}"


class EnvelopeCipher:
    """AES-256-GCM wrapper for task instructions and later request payloads."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> tuple[bytes, bytes]:
        """Encrypt bytes with a fresh 96-bit nonce and caller-defined binding data."""

        nonce = os.urandom(12)
        return self._cipher.encrypt(nonce, plaintext, associated_data), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes, *, associated_data: bytes) -> bytes:
        """Authenticate and decrypt a stored value."""

        if len(nonce) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        return self._cipher.decrypt(nonce, ciphertext, associated_data)


def json_object(value: BaseModel) -> dict[str, Any]:
    """Return a model's JSON-compatible normalized object representation."""

    return value.model_dump(mode="json")
