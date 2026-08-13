"""Security-sensitive settings validation tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Environment, Settings, get_settings


def test_database_url_is_redacted_from_settings_representation() -> None:
    settings = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://agentgate:do-not-print@localhost:5432/agentgate",
    )

    assert "do-not-print" not in repr(settings)
    assert "**********" in repr(settings)
    assert "do-not-print" in settings.sqlalchemy_database_url


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite+aiosqlite:///agentgate.db",
        "postgresql://agentgate:secret@localhost/agentgate",
        "not-a-url",
    ],
)
def test_non_async_postgresql_database_urls_are_rejected(database_url: str) -> None:
    with pytest.raises(ValidationError, match="database_url"):
        Settings(_env_file=None, database_url=database_url)


def test_production_rejects_development_database_password() -> None:
    with pytest.raises(ValidationError, match="development defaults"):
        Settings(_env_file=None, environment=Environment.PRODUCTION)


def test_production_requires_interactive_docs_to_be_disabled() -> None:
    with pytest.raises(ValidationError, match="documentation"):
        Settings(
            _env_file=None,
            environment=Environment.PRODUCTION,
            database_url="postgresql+asyncpg://agentgate:unique-prod-value@db/agentgate",
            docs_enabled=True,
        )


@pytest.mark.parametrize(
    "origins",
    [
        ["*"],
        ["https://*.example.test"],
        ["file:///tmp/dashboard"],
        ["https://user:password@example.test"],
        ["https://example.test/path"],
        [],
    ],
)
def test_unsafe_cors_origins_are_rejected(origins: list[str]) -> None:
    with pytest.raises(ValidationError, match="CORS"):
        Settings(_env_file=None, cors_allowed_origins=origins)


def test_cors_origins_are_normalized_and_deduplicated() -> None:
    settings = Settings(
        _env_file=None,
        cors_allowed_origins=["http://localhost:5173/", "http://localhost:5173"],
    )

    assert settings.cors_allowed_origins == ["http://localhost:5173"]


def test_invalid_log_level_and_size_limits_are_rejected() -> None:
    with pytest.raises(ValidationError, match="log level"):
        Settings(_env_file=None, log_level="VERBOSE")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, max_request_body_bytes=100)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, opa_max_response_bytes=100)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    first = get_settings()
    second = get_settings()

    assert first is second
    get_settings.cache_clear()


def test_identity_secrets_are_redacted_and_decoded_only_at_boundary() -> None:
    settings = Settings(
        _env_file=None,
        token_signing_key_b64="B" * 43,
        data_encryption_key_b64="C" * 43,
        audit_hmac_key_b64="D" * 43,
        admin_bootstrap_secret="a-unique-bootstrap-secret-with-32-bytes",
    )

    representation = repr(settings)
    assert "B" * 43 not in representation
    assert "C" * 43 not in representation
    assert "D" * 43 not in representation
    assert "a-unique-bootstrap" not in representation
    assert len(settings.token_signing_key_bytes) == 32
    assert len(settings.data_encryption_key_bytes) == 32
    assert len(settings.audit_hmac_key_bytes) == 32


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("token_signing_key_b64", "A" * 42, "exactly 32 bytes"),
        ("data_encryption_key_b64", ("A" * 42) + "=", "base64url"),
        ("audit_hmac_key_b64", "A" * 42, "exactly 32 bytes"),
        ("admin_bootstrap_secret", "too-short", "at least 32 bytes"),
        ("opa_url", "file:///tmp/opa", "opa_url"),
        ("opa_url", "http://user:secret@opa:8181", "opa_url"),
    ],
)
def test_invalid_identity_and_policy_settings_are_rejected(
    field: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None, **{field: value})


def test_agent_and_admin_audiences_must_remain_separate() -> None:
    with pytest.raises(ValidationError, match="audiences must differ"):
        Settings(
            _env_file=None,
            token_audience="same-audience",
            admin_token_audience="same-audience",
        )


def test_signing_and_encryption_keys_must_remain_separate() -> None:
    with pytest.raises(ValidationError, match="keys must differ"):
        Settings(
            _env_file=None,
            token_signing_key_b64="B" * 43,
            data_encryption_key_b64="B" * 43,
        )


def test_all_runtime_cryptographic_keys_must_be_distinct() -> None:
    with pytest.raises(ValidationError, match="audit keys must differ"):
        Settings(
            _env_file=None,
            data_encryption_key_b64="D" * 43,
            audit_hmac_key_b64="D" * 43,
        )


def test_production_rejects_development_identity_secrets() -> None:
    with pytest.raises(ValidationError, match="runtime secrets"):
        Settings(
            _env_file=None,
            environment=Environment.PRODUCTION,
            database_url="postgresql+asyncpg://agentgate:unique-prod-value@db/agentgate",
            docs_enabled=False,
        )


def test_opa_origin_is_normalized() -> None:
    settings = Settings(_env_file=None, opa_url="http://opa:8181/")

    assert settings.opa_url == "http://opa:8181"


def test_synthetic_data_root_is_resolved_and_cannot_be_a_filesystem_root(
    tmp_path: Path,
) -> None:
    settings = Settings(_env_file=None, synthetic_data_root=tmp_path / "fixtures")
    assert settings.synthetic_data_root.is_absolute()

    with pytest.raises(ValidationError, match="filesystem root"):
        Settings(_env_file=None, synthetic_data_root=Path(Path.cwd().anchor))


def test_audit_checkpoint_path_is_resolved_and_cannot_be_a_root() -> None:
    settings = Settings(
        _env_file=None,
        audit_checkpoint_path=Path("audit-checkpoints") / "head.json",
    )
    assert settings.audit_checkpoint_path.is_absolute()

    with pytest.raises(ValidationError, match="checkpoint"):
        Settings(_env_file=None, audit_checkpoint_path=Path(Path.cwd().anchor))
