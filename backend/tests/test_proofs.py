"""Proof-of-possession validation and binding tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.auth.crypto import canonical_sha256, public_jwk_from_key
from app.auth.proofs import (
    PROOF_TYPE,
    ProofValidationError,
    RequestProofVerifier,
    create_request_proof,
    proof_jti_hash,
)
from app.config import Settings


def test_valid_issuance_and_token_bound_proofs(settings: Settings) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_jwk = public_jwk_from_key(private_key.public_key())
    agent_id = uuid4()
    body = {"task_id": str(uuid4())}
    verifier = RequestProofVerifier(settings)

    issuance = create_request_proof(
        private_key,
        agent_id=agent_id,
        method="POST",
        path=f"/agents/{agent_id}/tokens",
        body=body,
        ttl_seconds=settings.request_proof_ttl_seconds,
    )
    issuance_claims = verifier.verify(
        issuance,
        public_jwk=public_jwk,
        agent_id=agent_id,
        method="POST",
        path=f"/agents/{agent_id}/tokens",
        body=body,
        access_token=None,
    )

    protected = create_request_proof(
        private_key,
        agent_id=agent_id,
        method="GET",
        path="/tasks/example",
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token="encoded.access.token",
    )
    protected_claims = verifier.verify(
        protected,
        public_jwk=public_jwk,
        agent_id=agent_id,
        method="GET",
        path="/tasks/example",
        body={},
        access_token="encoded.access.token",
    )

    assert issuance_claims.ath is None
    assert protected_claims.ath is not None
    assert len(proof_jti_hash(protected_claims.jti)) == 64


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("method", "DELETE"),
        ("path", "/tasks/another"),
        ("body", {"changed": True}),
        ("access_token", "different.token.value"),
        ("agent_id", uuid4()),
    ],
)
def test_proof_rejects_context_substitution(
    settings: Settings,
    override: str,
    value: object,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    agent_id = uuid4()
    proof = create_request_proof(
        private_key,
        agent_id=agent_id,
        method="POST",
        path="/tool-requests",
        body={"tool": "tickets.read"},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token="encoded.access.token",
    )
    context: dict[str, object] = {
        "agent_id": agent_id,
        "method": "POST",
        "path": "/tool-requests",
        "body": {"tool": "tickets.read"},
        "access_token": "encoded.access.token",
    }
    context[override] = value

    with pytest.raises(ProofValidationError, match="PROOF_INVALID"):
        RequestProofVerifier(settings).verify(
            proof,
            public_jwk=public_jwk_from_key(private_key.public_key()),
            **context,
        )


def test_proof_rejects_wrong_key_expiry_and_downgrade(settings: Settings) -> None:
    private_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    agent_id = uuid4()
    expired = create_request_proof(
        private_key,
        agent_id=agent_id,
        method="POST",
        path="/tool-requests",
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        now=datetime.now(UTC) - timedelta(minutes=2),
    )
    issuance_with_token_binding = create_request_proof(
        private_key,
        agent_id=agent_id,
        method="POST",
        path="/tool-requests",
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token="unexpected",
    )
    verifier = RequestProofVerifier(settings)

    with pytest.raises(ProofValidationError):
        verifier.verify(
            expired,
            public_jwk=public_jwk_from_key(private_key.public_key()),
            agent_id=agent_id,
            method="POST",
            path="/tool-requests",
            body={},
            access_token=None,
        )
    with pytest.raises(ProofValidationError):
        verifier.verify(
            issuance_with_token_binding,
            public_jwk=public_jwk_from_key(other_key.public_key()),
            agent_id=agent_id,
            method="POST",
            path="/tool-requests",
            body={},
            access_token=None,
        )
    with pytest.raises(ProofValidationError):
        verifier.verify(
            issuance_with_token_binding,
            public_jwk=public_jwk_from_key(private_key.public_key()),
            agent_id=agent_id,
            method="POST",
            path="/tool-requests",
            body={},
            access_token=None,
        )


def test_proof_rejects_extra_claims_and_wrong_type(settings: Settings) -> None:
    private_key = Ed25519PrivateKey.generate()
    agent_id = uuid4()
    now = datetime.now(UTC).replace(microsecond=0)
    claims = {
        "sub": str(agent_id),
        "htm": "POST",
        "htu": "/tool-requests",
        "body_hash": canonical_sha256({}),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=30)).timestamp()),
        "jti": str(uuid4()),
        "administrator": True,
    }
    extra_claim = jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"typ": PROOF_TYPE},
    )
    claims.pop("administrator")
    wrong_type = jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"typ": "JWT"},
    )
    verifier = RequestProofVerifier(settings)
    context = {
        "public_jwk": public_jwk_from_key(private_key.public_key()),
        "agent_id": agent_id,
        "method": "POST",
        "path": "/tool-requests",
        "body": {},
        "access_token": None,
    }

    with pytest.raises(ProofValidationError):
        verifier.verify(extra_claim, **context)
    with pytest.raises(ProofValidationError):
        verifier.verify(wrong_type, **context)
