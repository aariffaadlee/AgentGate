"""Strict argument, result, and synthetic-fixture schemas for every demo tool."""

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ALLOWED_FILE_EXTENSIONS = frozenset({".csv", ".json", ".md", ".txt"})
_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class StrictToolModel(BaseModel):
    """Reject coercion and unknown properties at every tool boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


def validate_email_address(value: str) -> str:
    """Validate a bounded ASCII addr-spec without accepting display-name syntax."""

    if len(value) > 254 or value.count("@") != 1 or any(ord(char) > 127 for char in value):
        raise ValueError("recipient must be one valid ASCII email address")
    local, domain = value.rsplit("@", 1)
    labels = domain.split(".")
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or _EMAIL_LOCAL.fullmatch(local) is None
        or len(labels) < 2
        or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise ValueError("recipient must be one valid ASCII email address")
    return f"{local}@{domain.lower()}"


def validate_relative_file_path(value: str) -> str:
    """Reject ambiguous, absolute, traversal, and unsupported file paths lexically."""

    if (
        not value
        or len(value) > 180
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or "%" in value
        or "\x00" in value
    ):
        raise ValueError("path must be an unambiguous relative sandbox path")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("path traversal and empty path segments are forbidden")
    path = PurePosixPath(value)
    if path.is_absolute() or path.suffix.lower() not in ALLOWED_FILE_EXTENSIONS:
        raise ValueError("path must use an allowed sandbox file extension")
    return path.as_posix()


class DocumentsSearchArguments(StrictToolModel):
    query: str = Field(min_length=1, max_length=120)
    max_results: int = Field(default=5, ge=1, le=10)


class TicketsReadArguments(StrictToolModel):
    ticket_id: str = Field(pattern=r"^TICKET-[0-9]{3}$")


class EmailArguments(StrictToolModel):
    recipient: str = Field(min_length=3, max_length=254)
    subject: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=10_000)

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        return validate_email_address(value)


class FilesReadArguments(StrictToolModel):
    path: str = Field(min_length=1, max_length=180)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_relative_file_path(value)


class FilesWriteArguments(FilesReadArguments):
    content: str = Field(max_length=16_384)
    overwrite: bool = False


class DatabaseQueryTemplate(StrEnum):
    ASSETS_BY_OWNER = "assets.by_owner"
    ASSETS_BY_STATUS = "assets.by_status"
    USERS_BY_DEPARTMENT = "users.by_department"


class DatabaseQueryArguments(StrictToolModel):
    query_id: DatabaseQueryTemplate
    parameters: dict[str, str] = Field(min_length=1, max_length=1)

    @field_validator("query_id", mode="before")
    @classmethod
    def parse_exact_query_id(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return DatabaseQueryTemplate(value)
            except ValueError:
                return value
        return value

    @model_validator(mode="after")
    def validate_template_parameters(self) -> Self:
        expected = {
            DatabaseQueryTemplate.ASSETS_BY_OWNER: "owner",
            DatabaseQueryTemplate.ASSETS_BY_STATUS: "status",
            DatabaseQueryTemplate.USERS_BY_DEPARTMENT: "department",
        }[self.query_id]
        if set(self.parameters) != {expected}:
            raise ValueError(f"{self.query_id} requires only the {expected!r} parameter")
        value = self.parameters[expected]
        if not 1 <= len(value) <= 80 or any(ord(char) < 32 for char in value):
            raise ValueError("query parameter must contain 1 to 80 printable characters")
        return self


class ProvenanceLabel(StrictToolModel):
    trust_label: Literal["trusted", "untrusted", "unknown"]
    source_type: Literal[
        "external_document",
        "support_ticket",
        "local_configuration",
        "tool_output",
    ]
    source_reference: str = Field(min_length=1, max_length=120)


class DocumentSearchHit(StrictToolModel):
    document_id: str = Field(pattern=r"^DOC-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=200)
    snippet: str = Field(max_length=600)
    provenance: ProvenanceLabel


class DocumentsSearchResult(StrictToolModel):
    matches: list[DocumentSearchHit] = Field(max_length=10)
    match_count: int = Field(ge=0, le=10)
    truncated: bool


class TicketReadResult(StrictToolModel):
    ticket_id: str = Field(pattern=r"^TICKET-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=200)
    status: Literal["open", "in_progress", "closed"]
    requester: str = Field(min_length=1, max_length=120)
    text: str = Field(max_length=12_000)
    provenance: ProvenanceLabel


class EmailActionResult(StrictToolModel):
    message_id: str = Field(pattern=r"^(draft|sent)-[0-9a-f]{32}$")
    status: Literal["draft_created", "sent"]


class FileReadResult(StrictToolModel):
    path: str = Field(min_length=1, max_length=180)
    content: str = Field(max_length=65_536)
    size_bytes: int = Field(ge=0, le=65_536)


class FileWriteResult(StrictToolModel):
    path: str = Field(min_length=1, max_length=180)
    size_bytes: int = Field(ge=0, le=16_384)
    overwritten: bool


class DatabaseRecord(StrictToolModel):
    record_id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    owner: str | None = Field(default=None, max_length=80)
    status: str | None = Field(default=None, max_length=40)
    department: str | None = Field(default=None, max_length=80)


class DatabaseQueryResult(StrictToolModel):
    query_id: DatabaseQueryTemplate
    rows: list[DatabaseRecord] = Field(max_length=20)
    row_count: int = Field(ge=0, le=20)
    truncated: bool


class DocumentFixture(StrictToolModel):
    document_id: str = Field(pattern=r"^DOC-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(max_length=20_000)


class TicketFixture(StrictToolModel):
    ticket_id: str = Field(pattern=r"^TICKET-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=200)
    status: Literal["open", "in_progress", "closed"]
    requester: str = Field(min_length=1, max_length=120)
    text: str = Field(max_length=12_000)


class SyntheticDatabaseFixture(StrictToolModel):
    assets: list[DatabaseRecord] = Field(max_length=100)
    users: list[DatabaseRecord] = Field(max_length=100)
