"""Short-lived, audience-separated token tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.auth.crypto import jwk_thumbprint, public_jwk_from_key
from app.auth.tokens import TokenService, TokenValidationError, token_hash, token_jti_hash
from app.config import Settings


def _identity() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, jwk_thumbprint(public_jwk_from_key(private_key.public_key()))


def test_valid_workload_token_contains_only_server_assigned_task_grants(
    settings: Settings,
) -> None:
    _, thumbprint = _identity()
    service = TokenService(settings)
    agent_id = uuid4()
    task_id = uuid4()

    issued = service.issue_workload_token(
        agent_id=agent_id,
        task_id=task_id,
        capabilities=["documents.search", "tickets.read"],
        key_thumbprint=thumbprint,
    )
    claims = service.decode_workload_token(issued.encoded)

    assert claims.sub == agent_id
    assert claims.task_id == task_id
    assert claims.capabilities == ["documents.search", "tickets.read"]
    assert claims.cnf.jkt == thumbprint
    assert claims.iss == settings.token_issuer
    assert claims.aud == settings.token_audience
    assert issued.expires_at - issued.issued_at == timedelta(
        seconds=settings.access_token_ttl_seconds
    )
    assert len(token_jti_hash(issued.jti)) == 64
    assert issued.encoded not in token_jti_hash(issued.jti)
    assert token_hash(issued.encoded).startswith("sha256:")


def test_expired_workload_token_is_rejected(settings: Settings) -> None:
    _, thumbprint = _identity()
    service = TokenService(settings)
    issued = service.issue_workload_token(
        agent_id=uuid4(),
        task_id=uuid4(),
        capabilities=["tickets.read"],
        key_thumbprint=thumbprint,
        now=datetime.now(UTC) - timedelta(seconds=settings.access_token_ttl_seconds + 30),
    )

    with pytest.raises(TokenValidationError, match="CREDENTIAL_EXPIRED"):
        service.decode_workload_token(issued.encoded)


def test_admin_and_workload_audiences_cannot_be_substituted(settings: Settings) -> None:
    _, thumbprint = _identity()
    service = TokenService(settings)
    admin = service.issue_admin_token(administrator_id=uuid4())
    workload = service.issue_workload_token(
        agent_id=uuid4(),
        task_id=uuid4(),
        capabilities=["tickets.read"],
        key_thumbprint=thumbprint,
    )

    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_workload_token(admin.encoded)
    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_admin_token(workload.encoded)


def test_wrong_issuer_and_signature_are_rejected(settings: Settings) -> None:
    _, thumbprint = _identity()
    foreign_settings = Settings(
        _env_file=None,
        database_url=settings.database_url,
        token_issuer="attacker.example",
    )
    foreign = TokenService(foreign_settings).issue_workload_token(
        agent_id=uuid4(),
        task_id=uuid4(),
        capabilities=["tickets.read"],
        key_thumbprint=thumbprint,
    )
    service = TokenService(settings)

    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_workload_token(foreign.encoded)

    parts = foreign.encoded.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_workload_token(".".join(parts))


def test_algorithm_header_and_excessive_lifetime_are_rejected(settings: Settings) -> None:
    _, thumbprint = _identity()
    service = TokenService(settings)
    issued = service.issue_workload_token(
        agent_id=uuid4(),
        task_id=uuid4(),
        capabilities=["tickets.read"],
        key_thumbprint=thumbprint,
    )
    claims = jwt.decode(issued.encoded, options={"verify_signature": False})
    claims["exp"] += 1
    private_key = Ed25519PrivateKey.from_private_bytes(settings.token_signing_key_bytes)
    overlong = jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"typ": "JWT", "kid": settings.token_signing_key_id},
    )
    wrong_type = jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"typ": "agentgate-proof+jwt", "kid": settings.token_signing_key_id},
    )

    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_workload_token(overlong)
    with pytest.raises(TokenValidationError, match="TOKEN_CONTEXT_INVALID"):
        service.decode_workload_token(wrong_type)


def test_token_issuance_requires_timezone_aware_timestamp(settings: Settings) -> None:
    _, thumbprint = _identity()
    with pytest.raises(ValueError, match="timezone-aware"):
        TokenService(settings).issue_workload_token(
            agent_id=uuid4(),
            task_id=uuid4(),
            capabilities=["tickets.read"],
            key_thumbprint=thumbprint,
            now=datetime.now(),
        )
