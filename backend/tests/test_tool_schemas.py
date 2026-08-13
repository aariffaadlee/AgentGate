"""Strict Phase 3 schema and immutable-manifest security tests."""

import pytest
from pydantic import ValidationError

from app.models.enums import RiskTier
from app.tools.registry import STATIC_TOOL_REGISTRY
from app.tools.schemas import (
    DatabaseQueryArguments,
    DatabaseQueryTemplate,
    DocumentsSearchArguments,
    EmailArguments,
    FilesReadArguments,
    FilesWriteArguments,
    TicketsReadArguments,
    validate_email_address,
)


def test_static_registry_contains_only_the_seven_exact_demo_tools() -> None:
    definitions = {definition.name: definition for definition in STATIC_TOOL_REGISTRY}

    assert set(definitions) == {
        "database.query",
        "documents.search",
        "email.create_draft",
        "email.send",
        "files.read",
        "files.write",
        "tickets.read",
    }
    assert definitions["documents.search"].risk_tier is RiskTier.LOW
    assert definitions["files.read"].risk_tier is RiskTier.MEDIUM
    assert definitions["email.send"].risk_tier is RiskTier.HIGH
    assert all(item.required_capability == item.name for item in definitions.values())
    assert len(STATIC_TOOL_REGISTRY.manifest_checksum) == 64
    assert STATIC_TOOL_REGISTRY.get("shell.exec") is None


@pytest.mark.parametrize(
    ("model", "valid", "extra"),
    [
        (DocumentsSearchArguments, {"query": "vpn", "max_results": 2}, "command"),
        (TicketsReadArguments, {"ticket_id": "TICKET-001"}, "include_secret"),
        (
            EmailArguments,
            {"recipient": "student@example.test", "subject": "Lab", "body": "Ready"},
            "authorization",
        ),
        (FilesReadArguments, {"path": "welcome.txt"}, "root"),
        (
            FilesWriteArguments,
            {"path": "notes.md", "content": "safe", "overwrite": False},
            "mode",
        ),
    ],
)
def test_tool_schemas_forbid_unexpected_properties(
    model: type,
    valid: dict[str, object],
    extra: str,
) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model.model_validate({**valid, extra: "attacker-controlled"})


def test_tool_schemas_reject_coercion_and_invalid_bounds() -> None:
    with pytest.raises(ValidationError):
        DocumentsSearchArguments.model_validate({"query": "vpn", "max_results": "5"})
    with pytest.raises(ValidationError):
        TicketsReadArguments.model_validate({"ticket_id": "ticket-001"})
    with pytest.raises(ValidationError):
        EmailArguments.model_validate(
            {"recipient": "a@example.test", "subject": "x", "body": "x" * 10_001}
        )
    with pytest.raises(ValidationError):
        FilesWriteArguments.model_validate({"path": "notes.md", "content": "x", "overwrite": "yes"})


@pytest.mark.parametrize(
    "candidate",
    [
        "not-an-address",
        "Display Name <student@example.test>",
        ".leading@example.test",
        "double..dot@example.test",
        "student@localhost",
        "student@-bad.example",
        "student@example.test@example.test",
    ],
)
def test_email_validation_rejects_ambiguous_or_invalid_recipients(candidate: str) -> None:
    with pytest.raises(ValueError, match="valid ASCII email"):
        validate_email_address(candidate)


def test_email_validation_normalizes_only_the_domain() -> None:
    assert validate_email_address("Student.Tag@EXAMPLE.TEST") == "Student.Tag@example.test"


@pytest.mark.parametrize(
    "candidate",
    [
        "../outside.txt",
        "folder/../outside.txt",
        "/absolute.txt",
        "C:/Windows/win.ini",
        "\\\\server\\share\\file.txt",
        "folder\\file.txt",
        "%2e%2e/outside.txt",
        "folder//file.txt",
        "folder/./file.txt",
        "script.py",
    ],
)
def test_file_path_schema_rejects_traversal_and_ambiguous_paths(candidate: str) -> None:
    with pytest.raises(ValidationError):
        FilesReadArguments.model_validate({"path": candidate})


def test_database_query_accepts_only_exact_templates_and_parameter_names() -> None:
    parsed = DatabaseQueryArguments.model_validate(
        {"query_id": "assets.by_owner", "parameters": {"owner": "Amina Student"}}
    )
    assert parsed.query_id is DatabaseQueryTemplate.ASSETS_BY_OWNER

    with pytest.raises(ValidationError):
        DatabaseQueryArguments.model_validate(
            {"query_id": "SELECT * FROM assets", "parameters": {"owner": "any"}}
        )
    with pytest.raises(ValidationError, match="requires only"):
        DatabaseQueryArguments.model_validate(
            {"query_id": "assets.by_owner", "parameters": {"status": "active"}}
        )
    with pytest.raises(ValidationError):
        DatabaseQueryArguments.model_validate(
            {
                "query_id": "assets.by_owner",
                "parameters": {"owner": "Amina", "other": "unexpected"},
            }
        )
