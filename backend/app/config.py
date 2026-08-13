"""Validated environment configuration for AgentGate."""

import base64
import hmac
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Environment(StrEnum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


DEVELOPMENT_SIGNING_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DEVELOPMENT_ENCRYPTION_KEY_B64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
DEVELOPMENT_AUDIT_KEY_B64 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
DEVELOPMENT_ADMIN_BOOTSTRAP_VALUE = "agentgate-development-bootstrap-secret-change-me"
DEFAULT_SYNTHETIC_DATA_ROOT = Path(__file__).resolve().parents[2] / "synthetic_data"
DEFAULT_AUDIT_CHECKPOINT_PATH = (
    Path(__file__).resolve().parents[2] / "audit-checkpoints" / "audit-head.json"
)


def _decode_b64url_key(value: str, *, setting_name: str) -> bytes:
    """Decode an unpadded base64url-encoded 32-byte key with strict validation."""

    if "=" in value:
        raise ValueError(f"{setting_name} must be unpadded base64url")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded + (b"=" * (-len(encoded) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{setting_name} must be unpadded base64url") from exc
    if len(decoded) != 32:
        raise ValueError(f"{setting_name} must decode to exactly 32 bytes")
    return decoded


class Settings(BaseSettings):
    """Fail-fast application settings loaded from ``AGENTGATE_*`` variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AGENTGATE_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "AgentGate API"
    environment: Environment = Environment.DEVELOPMENT
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://agentgate:agentgate-dev-only@localhost:5432/agentgate"
    )
    database_pool_size: int = Field(default=5, ge=1, le=20)
    database_max_overflow: int = Field(default=5, ge=0, le=20)
    database_pool_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    database_health_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    max_request_body_bytes: int = Field(default=262_144, ge=1_024, le=1_048_576)
    docs_enabled: bool = True
    log_level: str = "INFO"
    token_issuer: str = Field(default="agentgate.local", min_length=3, max_length=120)
    token_audience: str = Field(default="agentgate-tools", min_length=3, max_length=120)
    admin_token_audience: str = Field(default="agentgate-admin", min_length=3, max_length=120)
    token_signing_key_id: str = Field(
        default="agentgate-local-ed25519-v1",
        pattern=r"^[A-Za-z0-9._-]{3,64}$",
    )
    token_signing_key_b64: SecretStr = SecretStr(DEVELOPMENT_SIGNING_KEY_B64)
    data_encryption_key_b64: SecretStr = SecretStr(DEVELOPMENT_ENCRYPTION_KEY_B64)
    audit_hmac_key_b64: SecretStr = SecretStr(DEVELOPMENT_AUDIT_KEY_B64)
    audit_checkpoint_path: Path = DEFAULT_AUDIT_CHECKPOINT_PATH
    admin_bootstrap_username: str = Field(
        default="local-admin",
        pattern=r"^[A-Za-z0-9._-]{3,80}$",
    )
    admin_bootstrap_secret: SecretStr = SecretStr(DEVELOPMENT_ADMIN_BOOTSTRAP_VALUE)
    access_token_ttl_seconds: int = Field(default=300, ge=30, le=900)
    admin_token_ttl_seconds: int = Field(default=900, ge=60, le=3_600)
    approval_ttl_seconds: int = Field(default=180, ge=30, le=900)
    request_proof_ttl_seconds: int = Field(default=30, ge=5, le=60)
    request_proof_clock_skew_seconds: int = Field(default=5, ge=0, le=15)
    opa_url: str = "http://127.0.0.1:8181"
    opa_timeout_seconds: float = Field(default=1.0, ge=0.1, le=5.0)
    opa_max_response_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    synthetic_data_root: Path = DEFAULT_SYNTHETIC_DATA_ROOT

    @field_validator("cors_allowed_origins")
    @classmethod
    def validate_cors_origins(cls, origins: list[str]) -> list[str]:
        """Accept explicit HTTP(S) origins only; wildcard CORS is never valid."""

        if not origins:
            raise ValueError("at least one CORS origin is required")

        normalized: list[str] = []
        for origin in origins:
            if origin == "*" or "*" in origin:
                raise ValueError("wildcard CORS origins are forbidden")
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("CORS entries must be explicit HTTP(S) origins")
            normalized.append(origin.rstrip("/"))
        return list(dict.fromkeys(normalized))

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Restrict log levels to values understood by the logging subsystem."""

        normalized = value.upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("unsupported log level")
        return normalized

    @field_validator("token_signing_key_b64", "data_encryption_key_b64", "audit_hmac_key_b64")
    @classmethod
    def validate_base64_keys(cls, value: SecretStr, info: object) -> SecretStr:
        """Reject malformed Ed25519/AES key material at startup."""

        field_name = getattr(info, "field_name", "key")
        _decode_b64url_key(value.get_secret_value(), setting_name=str(field_name))
        return value

    @field_validator("admin_bootstrap_secret")
    @classmethod
    def validate_admin_secret(cls, value: SecretStr) -> SecretStr:
        """Require enough entropy-bearing space for the local bootstrap secret."""

        if len(value.get_secret_value().encode("utf-8")) < 32:
            raise ValueError("admin_bootstrap_secret must be at least 32 bytes")
        return value

    @field_validator("opa_url")
    @classmethod
    def validate_opa_url(cls, value: str) -> str:
        """Accept only a credential-free HTTP(S) service origin."""

        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("opa_url must be a credential-free HTTP(S) origin")
        return value.rstrip("/")

    @field_validator("synthetic_data_root")
    @classmethod
    def validate_synthetic_data_root(cls, value: Path) -> Path:
        """Resolve one dedicated data directory and reject a filesystem root."""

        resolved = value.resolve(strict=False)
        if resolved == Path(resolved.anchor):
            raise ValueError("synthetic_data_root must not be a filesystem root")
        return resolved

    @field_validator("audit_checkpoint_path")
    @classmethod
    def validate_audit_checkpoint_path(cls, value: Path) -> Path:
        """Require a concrete checkpoint file below a non-root directory."""

        resolved = value.resolve(strict=False)
        if resolved == Path(resolved.anchor) or not resolved.name:
            raise ValueError("audit_checkpoint_path must identify a file below a directory")
        return resolved

    @model_validator(mode="after")
    def validate_security_sensitive_settings(self) -> "Settings":
        """Reject unsafe database schemes and known development credentials."""

        raw_url = self.database_url.get_secret_value()
        try:
            parsed_url = make_url(raw_url)
        except Exception as exc:
            raise ValueError("database_url is not a valid SQLAlchemy URL") from exc

        if parsed_url.drivername != "postgresql+asyncpg":
            raise ValueError("database_url must use postgresql+asyncpg")
        if not parsed_url.host or not parsed_url.database:
            raise ValueError("database_url must include a host and database")
        if self.environment is Environment.PRODUCTION and parsed_url.password in {
            None,
            "agentgate-dev-only",
            "change-me-local-only",
        }:
            raise ValueError("production database credentials must not use development defaults")
        if self.environment is Environment.PRODUCTION and self.docs_enabled:
            raise ValueError("interactive API documentation must be disabled in production")
        if self.token_audience == self.admin_token_audience:
            raise ValueError("agent and administrator token audiences must differ")
        if hmac_compare_keys(
            self.token_signing_key_b64.get_secret_value(),
            self.data_encryption_key_b64.get_secret_value(),
        ):
            raise ValueError("token signing and data encryption keys must differ")
        encoded_keys = {
            self.token_signing_key_b64.get_secret_value(),
            self.data_encryption_key_b64.get_secret_value(),
            self.audit_hmac_key_b64.get_secret_value(),
        }
        if len(encoded_keys) != 3:
            raise ValueError("token signing, data encryption, and audit keys must differ")
        if self.environment is Environment.PRODUCTION and (
            self.token_signing_key_b64.get_secret_value() == DEVELOPMENT_SIGNING_KEY_B64
            or self.data_encryption_key_b64.get_secret_value() == DEVELOPMENT_ENCRYPTION_KEY_B64
            or self.audit_hmac_key_b64.get_secret_value() == DEVELOPMENT_AUDIT_KEY_B64
            or self.admin_bootstrap_secret.get_secret_value() == DEVELOPMENT_ADMIN_BOOTSTRAP_VALUE
        ):
            raise ValueError("production runtime secrets must not use development defaults")
        return self

    @property
    def sqlalchemy_database_url(self) -> str:
        """Return the database URL only at the database integration boundary."""

        return self.database_url.get_secret_value()

    @property
    def token_signing_key_bytes(self) -> bytes:
        """Expose decoded token key material only to the signing boundary."""

        return _decode_b64url_key(
            self.token_signing_key_b64.get_secret_value(),
            setting_name="token_signing_key_b64",
        )

    @property
    def data_encryption_key_bytes(self) -> bytes:
        """Expose decoded data key material only to the encryption boundary."""

        return _decode_b64url_key(
            self.data_encryption_key_b64.get_secret_value(),
            setting_name="data_encryption_key_b64",
        )

    @property
    def audit_hmac_key_bytes(self) -> bytes:
        """Expose decoded audit key material only to the chain boundary."""

        return _decode_b64url_key(
            self.audit_hmac_key_b64.get_secret_value(),
            setting_name="audit_hmac_key_b64",
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and cache validated process settings."""

    return Settings()


def hmac_compare_keys(first: str, second: str) -> bool:
    """Compare encoded key material without early-return content comparison."""

    return hmac.compare_digest(first.encode("ascii"), second.encode("ascii"))
