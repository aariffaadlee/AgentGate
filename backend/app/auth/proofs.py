"""A narrowly scoped DPoP-like Ed25519 request-proof protocol."""

import hmac
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.auth.crypto import Ed25519PublicJWK, canonical_sha256, public_key_from_jwk, sha256_hex
from app.auth.tokens import token_hash
from app.config import Settings

PROOF_TYPE = "agentgate-proof+jwt"


class ProofValidationError(Exception):
    """Internal proof failure with a stable external reason code."""


class RequestProofClaims(BaseModel):
    """Exact signed request context produced by an agent workload key."""

    model_config = ConfigDict(extra="forbid")

    sub: UUID
    htm: str = Field(pattern=r"^[A-Z]+$", min_length=3, max_length=12)
    htu: str = Field(pattern=r"^/", min_length=1, max_length=255)
    body_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ath: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    iat: int
    exp: int
    jti: UUID


class RequestProofVerifier:
    """Verify signature, freshness, endpoint, body, token binding, and proof shape."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def verify(
        self,
        proof: str,
        *,
        public_jwk: Ed25519PublicJWK,
        agent_id: UUID,
        method: str,
        path: str,
        body: object,
        access_token: str | None,
    ) -> RequestProofClaims:
        """Return validated claims or raise a non-reflective proof error."""

        try:
            header = jwt.get_unverified_header(proof)
            if header.get("alg") != "EdDSA" or header.get("typ") != PROOF_TYPE:
                raise ProofValidationError("PROOF_INVALID")
            decoded = jwt.decode(
                proof,
                public_key_from_jwk(public_jwk),
                algorithms=["EdDSA"],
                leeway=self._settings.request_proof_clock_skew_seconds,
                options={
                    "verify_aud": False,
                    "require": ["sub", "htm", "htu", "body_hash", "iat", "exp", "jti"],
                },
            )
            claims = RequestProofClaims.model_validate(decoded)
        except ProofValidationError:
            raise
        except (jwt.PyJWTError, ValidationError, ValueError) as exc:
            raise ProofValidationError("PROOF_INVALID") from exc

        expected_body_hash = canonical_sha256(body)
        if (
            claims.sub != agent_id
            or not hmac.compare_digest(claims.htm, method.upper())
            or not hmac.compare_digest(claims.htu, path)
            or not hmac.compare_digest(claims.body_hash, expected_body_hash)
            or claims.exp <= claims.iat
            or claims.exp - claims.iat > self._settings.request_proof_ttl_seconds
        ):
            raise ProofValidationError("PROOF_INVALID")

        if access_token is None:
            if claims.ath is not None:
                raise ProofValidationError("PROOF_INVALID")
        else:
            expected_token_hash = token_hash(access_token)
            if claims.ath is None or not hmac.compare_digest(claims.ath, expected_token_hash):
                raise ProofValidationError("PROOF_INVALID")
        return claims


def create_request_proof(
    private_key: Ed25519PrivateKey,
    *,
    agent_id: UUID,
    method: str,
    path: str,
    body: object,
    ttl_seconds: int,
    access_token: str | None = None,
    now: datetime | None = None,
    jti: UUID | None = None,
) -> str:
    """Client-side helper for deterministic demos and tests of the documented protocol."""

    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise ValueError("proof timestamps must be timezone-aware")
    issued_at = issued_at.astimezone(UTC).replace(microsecond=0)
    claims = RequestProofClaims(
        sub=agent_id,
        htm=method.upper(),
        htu=path,
        body_hash=canonical_sha256(body),
        ath=token_hash(access_token) if access_token is not None else None,
        iat=int(issued_at.timestamp()),
        exp=int((issued_at + timedelta(seconds=ttl_seconds)).timestamp()),
        jti=jti or uuid4(),
    )
    return jwt.encode(
        claims.model_dump(mode="json"),
        private_key,
        algorithm="EdDSA",
        headers={"typ": PROOF_TYPE},
    )


def proof_jti_hash(jti: UUID) -> str:
    """Hash a one-time proof identifier before storing its replay marker."""

    return sha256_hex(str(jti).encode("ascii"))
