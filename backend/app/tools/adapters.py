"""Contained synthetic adapters; none resolves code, SQL, hosts, or paths from a model."""

import asyncio
import json
import os
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast
from uuid import uuid4

from pydantic import BaseModel, TypeAdapter, ValidationError

from app.tools.schemas import (
    DatabaseQueryArguments,
    DatabaseQueryResult,
    DatabaseQueryTemplate,
    DatabaseRecord,
    DocumentFixture,
    DocumentSearchHit,
    DocumentsSearchArguments,
    DocumentsSearchResult,
    EmailActionResult,
    EmailArguments,
    FileReadResult,
    FilesReadArguments,
    FilesWriteArguments,
    FileWriteResult,
    ProvenanceLabel,
    SyntheticDatabaseFixture,
    TicketFixture,
    TicketReadResult,
    TicketsReadArguments,
)

_FIXTURE_SIZE_LIMIT = 1_048_576
_FILE_READ_LIMIT = 65_536
_FILE_WRITE_LIMIT = 16_384
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ToolAdapterError(Exception):
    """Expected safe adapter failure represented only by a stable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolExecutionContext:
    """Trusted resources supplied by AgentGate rather than by an agent request."""

    synthetic_data_root: Path
    mailbox: "MockMailbox"

    @property
    def sandbox_root(self) -> Path:
        return self.synthetic_data_root / "sandbox"


class MockMailbox:
    """Process-local synthetic mailbox with no network or delivery integration."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._drafts: dict[str, dict[str, str]] = {}
        self._sent: dict[str, dict[str, str]] = {}

    async def create_draft(self, arguments: EmailArguments) -> EmailActionResult:
        message_id = f"draft-{uuid4().hex}"
        async with self._lock:
            self._drafts[message_id] = cast(dict[str, str], arguments.model_dump(mode="json"))
        return EmailActionResult(message_id=message_id, status="draft_created")

    async def send(self, arguments: EmailArguments) -> EmailActionResult:
        message_id = f"sent-{uuid4().hex}"
        async with self._lock:
            self._sent[message_id] = cast(dict[str, str], arguments.model_dump(mode="json"))
        return EmailActionResult(message_id=message_id, status="sent")

    @property
    def draft_count(self) -> int:
        return len(self._drafts)

    @property
    def sent_count(self) -> int:
        return len(self._sent)


def _require_model[ModelT: BaseModel](
    arguments: BaseModel,
    expected: type[ModelT],
) -> ModelT:
    if not isinstance(arguments, expected):
        raise ToolAdapterError("TOOL_ARGUMENTS_INVALID")
    return arguments


def _load_fixture[FixtureT](path: Path, adapter: TypeAdapter[FixtureT]) -> FixtureT:
    """Load one bounded, strict, repository-owned JSON fixture."""

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _FIXTURE_SIZE_LIMIT:
            raise ToolAdapterError("TOOL_DATA_INVALID")
        raw = path.read_bytes()
        return adapter.validate_python(json.loads(raw))
    except ToolAdapterError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ToolAdapterError("TOOL_DATA_INVALID") from exc


async def documents_search(
    arguments: BaseModel,
    context: ToolExecutionContext,
) -> BaseModel:
    args = _require_model(arguments, DocumentsSearchArguments)
    fixtures = await asyncio.to_thread(
        _load_fixture,
        context.synthetic_data_root / "documents.json",
        TypeAdapter(list[DocumentFixture]),
    )
    terms = tuple(term.casefold() for term in args.query.split() if term)
    matches: list[DocumentSearchHit] = []
    all_match_count = 0
    for document in fixtures:
        haystack = f"{document.title}\n{document.content}".casefold()
        if terms and all(term in haystack for term in terms):
            all_match_count += 1
            if len(matches) < args.max_results:
                snippet = " ".join(document.content.split())[:600]
                matches.append(
                    DocumentSearchHit(
                        document_id=document.document_id,
                        title=document.title,
                        snippet=snippet,
                        provenance=ProvenanceLabel(
                            trust_label="untrusted",
                            source_type="external_document",
                            source_reference=document.document_id,
                        ),
                    )
                )
    return DocumentsSearchResult(
        matches=matches,
        match_count=len(matches),
        truncated=all_match_count > len(matches),
    )


async def tickets_read(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    args = _require_model(arguments, TicketsReadArguments)
    fixtures = await asyncio.to_thread(
        _load_fixture,
        context.synthetic_data_root / "tickets.json",
        TypeAdapter(list[TicketFixture]),
    )
    ticket = next((item for item in fixtures if item.ticket_id == args.ticket_id), None)
    if ticket is None:
        raise ToolAdapterError("TOOL_RECORD_NOT_FOUND")
    return TicketReadResult(
        ticket_id=ticket.ticket_id,
        title=ticket.title,
        status=ticket.status,
        requester=ticket.requester,
        text=ticket.text,
        provenance=ProvenanceLabel(
            trust_label="untrusted",
            source_type="support_ticket",
            source_reference=ticket.ticket_id,
        ),
    )


async def email_create_draft(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    return await context.mailbox.create_draft(_require_model(arguments, EmailArguments))


async def email_send(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    """Simulate delivery; the PEP cannot reach this adapter without an allow decision."""

    return await context.mailbox.send(_require_model(arguments, EmailArguments))


def _has_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise ToolAdapterError("FILE_PATH_FORBIDDEN") from exc
    return bool(attributes & _REPARSE_POINT)


def _assert_not_link(path: Path) -> None:
    if path.is_symlink() or _has_reparse_point(path):
        raise ToolAdapterError("FILE_PATH_FORBIDDEN")


def _sandbox_target(root: Path, relative: str, *, must_exist: bool) -> Path:
    """Resolve a schema-validated path and reject links in every existing component."""

    try:
        if not root.exists() or not root.is_dir():
            raise ToolAdapterError("FILE_SANDBOX_UNAVAILABLE")
        _assert_not_link(root)
        resolved_root = root.resolve(strict=True)
        target = root.joinpath(*PurePosixPath(relative).parts)
        current = root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.exists() or current.is_symlink():
                _assert_not_link(current)
        resolved_parent = target.parent.resolve(strict=True)
        resolved_parent.relative_to(resolved_root)
        if must_exist:
            resolved_target = target.resolve(strict=True)
            resolved_target.relative_to(resolved_root)
            if not resolved_target.is_file():
                raise ToolAdapterError("FILE_NOT_FOUND")
            return resolved_target
        if target.exists():
            resolved_target = target.resolve(strict=True)
            resolved_target.relative_to(resolved_root)
        return target
    except ToolAdapterError:
        raise
    except (OSError, ValueError) as exc:
        code = "FILE_NOT_FOUND" if must_exist else "FILE_PATH_FORBIDDEN"
        raise ToolAdapterError(code) from exc


def inspect_write_target(root: Path, relative: str) -> bool:
    """Return authoritative overwrite state after containment checks."""

    target = _sandbox_target(root, relative, must_exist=False)
    if target.exists() and not target.is_file():
        raise ToolAdapterError("FILE_PATH_FORBIDDEN")
    return target.exists()


def _read_sandbox_file(root: Path, relative: str) -> FileReadResult:
    target = _sandbox_target(root, relative, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _FILE_READ_LIMIT:
                raise ToolAdapterError("FILE_TOO_LARGE")
            raw = stream.read(_FILE_READ_LIMIT + 1)
        if len(raw) > _FILE_READ_LIMIT:
            raise ToolAdapterError("FILE_TOO_LARGE")
        content = raw.decode("utf-8")
        return FileReadResult(path=relative, content=content, size_bytes=len(raw))
    except ToolAdapterError:
        raise
    except UnicodeDecodeError as exc:
        raise ToolAdapterError("FILE_ENCODING_INVALID") from exc
    except OSError as exc:
        raise ToolAdapterError("FILE_PATH_FORBIDDEN") from exc


async def files_read(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    args = _require_model(arguments, FilesReadArguments)
    return await asyncio.to_thread(_read_sandbox_file, context.sandbox_root, args.path)


def _write_sandbox_file(
    root: Path,
    relative: str,
    content: str,
    overwrite: bool,
) -> FileWriteResult:
    target = _sandbox_target(root, relative, must_exist=False)
    existed = target.exists()
    if existed and not overwrite:
        raise ToolAdapterError("FILE_EXISTS")
    raw = content.encode("utf-8")
    if len(raw) > _FILE_WRITE_LIMIT:
        raise ToolAdapterError("FILE_TOO_LARGE")

    descriptor, temporary_name = tempfile.mkstemp(prefix=".agentgate-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _assert_not_link(target.parent)
        if overwrite:
            os.replace(temporary, target)
        else:
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                raise ToolAdapterError("FILE_EXISTS") from exc
            temporary.unlink()
    except ToolAdapterError:
        raise
    except OSError as exc:
        raise ToolAdapterError("FILE_WRITE_FAILED") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
    return FileWriteResult(path=relative, size_bytes=len(raw), overwritten=existed)


async def files_write(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    args = _require_model(arguments, FilesWriteArguments)
    return await asyncio.to_thread(
        _write_sandbox_file,
        context.sandbox_root,
        args.path,
        args.content,
        args.overwrite,
    )


async def database_query(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
    args = _require_model(arguments, DatabaseQueryArguments)
    fixture = await asyncio.to_thread(
        _load_fixture,
        context.synthetic_data_root / "database.json",
        TypeAdapter(SyntheticDatabaseFixture),
    )
    if args.query_id is DatabaseQueryTemplate.ASSETS_BY_OWNER:
        source = fixture.assets
        field = "owner"
    elif args.query_id is DatabaseQueryTemplate.ASSETS_BY_STATUS:
        source = fixture.assets
        field = "status"
    else:
        source = fixture.users
        field = "department"
    expected = args.parameters[field].casefold()
    rows = [
        row
        for row in source
        if cast(str | None, getattr(row, field)) is not None
        and cast(str, getattr(row, field)).casefold() == expected
    ]
    bounded: list[DatabaseRecord] = rows[:20]
    return DatabaseQueryResult(
        query_id=args.query_id,
        rows=bounded,
        row_count=len(bounded),
        truncated=len(rows) > len(bounded),
    )
