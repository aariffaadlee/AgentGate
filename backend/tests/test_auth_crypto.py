"""Cryptographic boundary tests."""

import math

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.auth.crypto import (
    Ed25519PublicJWK,
    EnvelopeCipher,
    canonical_json,
    canonical_sha256,
    hash_secret_for_storage,
    jwk_thumbprint,
    public_jwk_from_key,
    public_key_from_jwk,
    secret_matches,
)


def test_canonical_json_is_stable_and_rejects_non_finite_numbers() -> None:
    first = {"z": [2, 1], "a": {"value": "✓"}}
    second = {"a": {"value": "✓"}, "z": [2, 1]}

    assert canonical_json(first) == canonical_json(second)
    assert canonical_sha256(first) == canonical_sha256(second)
    assert canonical_json(first) == b'{"a":{"value":"\xe2\x9c\x93"},"z":[2,1]}'
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json({"invalid": math.inf})


def test_ed25519_jwk_round_trip_and_thumbprint_are_stable() -> None:
    private_key = Ed25519PrivateKey.generate()
    jwk = public_jwk_from_key(private_key.public_key())

    message = b"agentgate-proof"
    signature = private_key.sign(message)
    public_key_from_jwk(jwk).verify(signature, message)

    assert jwk.kty == "OKP"
    assert jwk.crv == "Ed25519"
    assert len(jwk_thumbprint(jwk)) == 64
    assert jwk_thumbprint(jwk) == jwk_thumbprint(Ed25519PublicJWK(**jwk.model_dump()))


@pytest.mark.parametrize(
    "candidate",
    [
        {"kty": "RSA", "crv": "Ed25519", "x": "A" * 43},
        {"kty": "OKP", "crv": "X25519", "x": "A" * 43},
        {"kty": "OKP", "crv": "Ed25519", "x": "short"},
        {"kty": "OKP", "crv": "Ed25519", "x": ("A" * 42) + "="},
        {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43, "d": "private"},
    ],
)
def test_public_jwk_rejects_wrong_or_private_key_material(candidate: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        Ed25519PublicJWK.model_validate(candidate)


def test_envelope_cipher_authenticates_task_binding_and_ciphertext() -> None:
    cipher = EnvelopeCipher(bytes(range(32)))
    ciphertext, nonce = cipher.encrypt(b"trusted task", associated_data=b"task:one")

    assert cipher.decrypt(ciphertext, nonce, associated_data=b"task:one") == b"trusted task"
    with pytest.raises(InvalidTag):
        cipher.decrypt(ciphertext, nonce, associated_data=b"task:two")
    with pytest.raises(InvalidTag):
        cipher.decrypt(ciphertext[:-1] + b"x", nonce, associated_data=b"task:one")


def test_bootstrap_secret_comparison_and_storage_hash_are_non_plaintext() -> None:
    secret = "correct horse battery staple with entropy"
    first = hash_secret_for_storage(secret)
    second = hash_secret_for_storage(secret)

    assert secret_matches(secret, secret) is True
    assert secret_matches(secret + "x", secret) is False
    assert first.startswith("scrypt$16384$8$1$")
    assert secret not in first
    assert first != second
