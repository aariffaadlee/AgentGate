"""Recursive structured-log redaction tests."""

import json

import structlog
from pydantic import SecretStr

from app.logging import REDACTED, configure_logging, redact_value


def test_recursive_redaction_covers_keys_bearer_jwt_and_url_passwords() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.signature"
    event = {
        "authorization": "Bearer abc.def.ghi",
        "nested": {
            "refresh_token": token,
            "connection": "postgresql+asyncpg://agent:password@db/agentgate",
            "safe": "visible",
        },
        "items": [{"password": "hunter2"}],
        "wrapped": SecretStr("also-do-not-print"),
    }

    redacted = redact_value(event)

    assert redacted["authorization"] == REDACTED
    assert redacted["nested"]["refresh_token"] == REDACTED
    assert redacted["nested"]["connection"] == (
        "postgresql+asyncpg://agent:[REDACTED]@db/agentgate"
    )
    assert redacted["nested"]["safe"] == "visible"
    assert redacted["items"][0]["password"] == REDACTED
    assert redacted["wrapped"] == REDACTED


def test_structured_logger_emits_json_without_secret(capsys: object) -> None:
    configure_logging("INFO")
    structlog.get_logger("test").info(
        "security_event",
        access_token="do-not-print",
        detail="Bearer copied-token",
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    payload = json.loads(captured.out.strip().splitlines()[-1])
    assert payload["event"] == "security_event"
    assert payload["access_token"] == REDACTED
    assert payload["detail"] == f"Bearer {REDACTED}"
    assert "do-not-print" not in captured.out
    assert "copied-token" not in captured.out
