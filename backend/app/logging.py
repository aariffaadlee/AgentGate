"""Structured JSON logging with recursive secret redaction."""

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, cast

import structlog
from pydantic import SecretStr

REDACTED = "[REDACTED]"
_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "database_url",
    "password",
    "private_key",
    "secret",
    "set_cookie",
    "token",
}
_SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_URL_PASSWORD_PATTERN = re.compile(r"(://[^\s:/]+:)[^\s@/]+(@)")


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_EXACT_KEYS or normalized.endswith(_SENSITIVE_KEY_SUFFIXES)


def redact_value(value: Any) -> Any:
    """Recursively redact sensitive keys and recognizable credential strings."""

    if isinstance(value, SecretStr):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(key) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, str):
        redacted = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", value)
        redacted = _JWT_PATTERN.sub(REDACTED, redacted)
        return _URL_PASSWORD_PATTERN.sub(r"\1[REDACTED]\2", redacted)
    return value


def redact_sensitive_data(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Structlog processor that redacts the complete event dictionary."""

    return cast(MutableMapping[str, Any], redact_value(event_dict))


def configure_logging(level: str) -> None:
    """Configure standard-library and structlog output as one JSON event per line."""

    logging.basicConfig(stream=sys.stdout, level=level, format="%(message)s", force=True)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
            redact_sensitive_data,
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )
