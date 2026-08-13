"""Audience-separated, short-lived Ed25519 JWT issuance and validation."""

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.auth.crypto import sha256_hex
from app.config import Settings


class TokenValidationError(Exception):
    """Internal token failure carrying only a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ConfirmationClaim(BaseModel):
    """Proof-key confirmation embedded in each workload token."""

    model_config = ConfigDict(extra="forbid")

    jkt: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkloadTokenClaims(BaseModel):
    """Strict decoded workload-token contract."""

    model_config = ConfigDict(extra="forbid")

    iss: str
    aud: str
    sub: UUID
    task_id: UUID
    capabilities: list[str] = Field(min_length=1, max_length=32)
    jti: UUID
    iat: int
    nbf: int
    exp: int
    cnf: ConfirmationClaim

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("capabilities must be unique")
        if any(not value or "*" in value or len(value) > 120 for value in values):
            raise ValueError("capabilities must be exact non-wildcard names")
        return values


class AdminTokenClaims(BaseModel):
    """Strict decoded administrative token contract."""

    model_config = ConfigDict(extra="forbid")

    iss: str
    aud: str
    sub: UUID
    role: Literal["administrator"]
    jti: UUID
    iat: int
    nbf: int
    exp: int


@dataclass(frozen=True)
class IssuedToken:
    """One-time API result plus its validated metadata."""

    encoded: str
    jti: UUID
    issued_at: datetime
    not_before_at: datetime
    expires_at: datetime


class TokenService:
    """Issue and validate tokens with a fixed algorithm, issuer, and audiences."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._private_key = Ed25519PrivateKey.from_private_bytes(settings.token_signing_key_bytes)
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    def issue_workload_token(
        self,
        *,
        agent_id: UUID,
        task_id: UUID,
        capabilities: list[str],
        key_thumbprint: str,
        now: datetime | None = None,
        jti: UUID | None = None,
    ) -> IssuedToken:
        """Issue one task-bound credential whose grants came from stored task state."""

        issued_at = _utc_seconds(now)
        expires_at = issued_at + timedelta(seconds=self._settings.access_token_ttl_seconds)
        token_jti = jti or uuid4()
        claims = WorkloadTokenClaims(
            iss=self._settings.token_issuer,
            aud=self._settings.token_audience,
            sub=agent_id,
            task_id=task_id,
            capabilities=capabilities,
            jti=token_jti,
            iat=int(issued_at.timestamp()),
            nbf=int(issued_at.timestamp()),
            exp=int(expires_at.timestamp()),
            cnf=ConfirmationClaim(jkt=key_thumbprint),
        )
        encoded = self._encode(claims.model_dump(mode="json"))
        return IssuedToken(encoded, token_jti, issued_at, issued_at, expires_at)

    def issue_admin_token(
        self,
        *,
        administrator_id: UUID,
        now: datetime | None = None,
        jti: UUID | None = None,
    ) -> IssuedToken:
        """Issue an administrator-only audience token."""

        issued_at = _utc_seconds(now)
        expires_at = issued_at + timedelta(seconds=self._settings.admin_token_ttl_seconds)
        token_jti = jti or uuid4()
        claims = AdminTokenClaims(
            iss=self._settings.token_issuer,
            aud=self._settings.admin_token_audience,
            sub=administrator_id,
            role="administrator",
            jti=token_jti,
            iat=int(issued_at.timestamp()),
            nbf=int(issued_at.timestamp()),
            exp=int(expires_at.timestamp()),
        )
        encoded = self._encode(claims.model_dump(mode="json"))
        return IssuedToken(encoded, token_jti, issued_at, issued_at, expires_at)

    def decode_workload_token(self, token: str) -> WorkloadTokenClaims:
        """Verify a workload token and reject malformed or overlong claim sets."""

        payload = self._decode(token, audience=self._settings.token_audience)
        try:
            claims = WorkloadTokenClaims.model_validate(payload)
        except ValidationError as exc:
            raise TokenValidationError("TOKEN_CONTEXT_INVALID") from exc
        self._validate_lifetime(
            claims.iat,
            claims.nbf,
            claims.exp,
            self._settings.access_token_ttl_seconds,
        )
        return claims

    def decode_admin_token(self, token: str) -> AdminTokenClaims:
        """Verify an administrative token with its distinct audience and role."""

        payload = self._decode(token, audience=self._settings.admin_token_audience)
        try:
            claims = AdminTokenClaims.model_validate(payload)
        except ValidationError as exc:
            raise TokenValidationError("TOKEN_CONTEXT_INVALID") from exc
        self._validate_lifetime(
            claims.iat,
            claims.nbf,
            claims.exp,
            self._settings.admin_token_ttl_seconds,
        )
        return claims

    def _encode(self, claims: dict[str, object]) -> str:
        return jwt.encode(
            claims,
            self._private_key,
            algorithm="EdDSA",
            headers={"kid": self._settings.token_signing_key_id, "typ": "JWT"},
        )

    def _decode(self, token: str, *, audience: str) -> dict[str, object]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
                raise TokenValidationError("TOKEN_CONTEXT_INVALID")
            key_id = header.get("kid")
            if not isinstance(key_id, str) or not hmac.compare_digest(
                key_id,
                self._settings.token_signing_key_id,
            ):
                raise TokenValidationError("TOKEN_CONTEXT_INVALID")
            decoded = jwt.decode(
                token,
                self._public_key,
                algorithms=["EdDSA"],
                audience=audience,
                issuer=self._settings.token_issuer,
                leeway=self._settings.request_proof_clock_skew_seconds,
                options={
                    "require": ["iss", "aud", "sub", "jti", "iat", "nbf", "exp"],
                    "strict_aud": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("CREDENTIAL_EXPIRED") from exc
        except TokenValidationError:
            raise
        except jwt.PyJWTError as exc:
            raise TokenValidationError("TOKEN_CONTEXT_INVALID") from exc
        return {str(key): value for key, value in decoded.items()}

    @staticmethod
    def _validate_lifetime(iat: int, nbf: int, exp: int, maximum_seconds: int) -> None:
        if nbf < iat or exp <= nbf or exp - iat > maximum_seconds:
            raise TokenValidationError("TOKEN_CONTEXT_INVALID")


def _utc_seconds(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("token timestamps must be timezone-aware")
    return current.astimezone(UTC).replace(microsecond=0)


def token_hash(token: str) -> str:
    """Hash an encoded token for proof binding without persisting it."""

    return f"sha256:{sha256_hex(token.encode('ascii'))}"


def token_jti_hash(jti: UUID) -> str:
    """Hash a token identifier before database persistence."""

    return sha256_hex(str(jti).encode("ascii"))
