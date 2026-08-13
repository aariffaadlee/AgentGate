"""Positive and adversarial tests for the seven contained synthetic adapters."""

import shutil
from pathlib import Path

import pytest

from app.tools.adapters import (
    MockMailbox,
    ToolAdapterError,
    ToolExecutionContext,
    database_query,
    documents_search,
    email_create_draft,
    email_send,
    files_read,
    files_write,
    tickets_read,
)
from app.tools.schemas import (
    DatabaseQueryArguments,
    DatabaseQueryResult,
    DocumentsSearchArguments,
    DocumentsSearchResult,
    EmailActionResult,
    EmailArguments,
    FileReadResult,
    FilesReadArguments,
    FilesWriteArguments,
    FileWriteResult,
    TicketReadResult,
    TicketsReadArguments,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _context(tmp_path: Path) -> ToolExecutionContext:
    for name in ("documents.json", "tickets.json", "database.json"):
        shutil.copyfile(PROJECT_ROOT / "synthetic_data" / name, tmp_path / name)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "welcome.txt").write_text("training-only", encoding="utf-8")
    return ToolExecutionContext(synthetic_data_root=tmp_path, mailbox=MockMailbox())


async def test_document_and_ticket_results_are_bounded_and_server_labelled_untrusted(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    documents = await documents_search(
        DocumentsSearchArguments(query="unsafe embedded instruction", max_results=2),
        context,
    )
    ticket = await tickets_read(TicketsReadArguments(ticket_id="TICKET-002"), context)

    assert isinstance(documents, DocumentsSearchResult)
    assert documents.match_count == 1
    assert documents.matches[0].document_id == "DOC-003"
    assert documents.matches[0].provenance.trust_label == "untrusted"
    assert isinstance(ticket, TicketReadResult)
    assert "Ignore all previous" in ticket.text
    assert ticket.provenance.source_type == "support_ticket"
    assert ticket.provenance.trust_label == "untrusted"


async def test_document_search_truncates_explicitly_and_missing_ticket_is_safe(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    result = await documents_search(
        DocumentsSearchArguments(query="synthetic", max_results=1),
        context,
    )
    assert isinstance(result, DocumentsSearchResult)
    assert result.match_count == 1
    assert result.truncated is True

    with pytest.raises(ToolAdapterError) as missing:
        await tickets_read(TicketsReadArguments(ticket_id="TICKET-999"), context)
    assert missing.value.code == "TOOL_RECORD_NOT_FOUND"


async def test_mock_email_tools_have_no_external_side_effect(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    arguments = EmailArguments(
        recipient="student@example.test",
        subject="Synthetic notification",
        body="No real email is sent.",
    )

    draft = await email_create_draft(arguments, context)
    sent = await email_send(arguments, context)

    assert isinstance(draft, EmailActionResult)
    assert isinstance(sent, EmailActionResult)
    assert draft.status == "draft_created"
    assert sent.status == "sent"
    assert context.mailbox.draft_count == 1
    assert context.mailbox.sent_count == 1


async def test_database_query_uses_exact_templates_and_treats_sql_payload_as_data(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    allowed = await database_query(
        DatabaseQueryArguments.model_validate(
            {"query_id": "assets.by_owner", "parameters": {"owner": "Daniel Trainee"}}
        ),
        context,
    )
    injected = await database_query(
        DatabaseQueryArguments.model_validate(
            {"query_id": "assets.by_owner", "parameters": {"owner": "' OR 1=1 --"}}
        ),
        context,
    )

    assert isinstance(allowed, DatabaseQueryResult)
    assert allowed.row_count == 2
    assert isinstance(injected, DatabaseQueryResult)
    assert injected.rows == []
    assert injected.row_count == 0


async def test_file_read_and_atomic_write_remain_inside_sandbox(tmp_path: Path) -> None:
    context = _context(tmp_path)
    read = await files_read(FilesReadArguments(path="welcome.txt"), context)
    write = await files_write(
        FilesWriteArguments(path="notes.md", content="phase three", overwrite=False),
        context,
    )

    assert isinstance(read, FileReadResult)
    assert read.content == "training-only"
    assert isinstance(write, FileWriteResult)
    assert write.overwritten is False
    assert (tmp_path / "sandbox" / "notes.md").read_text(encoding="utf-8") == "phase three"

    with pytest.raises(ToolAdapterError) as existing:
        await files_write(
            FilesWriteArguments(path="notes.md", content="changed", overwrite=False),
            context,
        )
    assert existing.value.code == "FILE_EXISTS"

    overwritten = await files_write(
        FilesWriteArguments(path="notes.md", content="changed", overwrite=True),
        context,
    )
    assert isinstance(overwritten, FileWriteResult)
    assert overwritten.overwritten is True


async def test_file_tools_reject_symlink_escape_binary_and_oversized_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("must-not-leak", encoding="utf-8")
    link = tmp_path / "sandbox" / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "escape.txt")

    with pytest.raises(ToolAdapterError) as escaped:
        await files_read(FilesReadArguments(path="escape.txt"), context)
    assert escaped.value.code == "FILE_PATH_FORBIDDEN"

    binary = tmp_path / "sandbox" / "binary.txt"
    binary.write_bytes(b"\xff\xfe")
    with pytest.raises(ToolAdapterError) as invalid_encoding:
        await files_read(FilesReadArguments(path="binary.txt"), context)
    assert invalid_encoding.value.code == "FILE_ENCODING_INVALID"

    with pytest.raises(ToolAdapterError) as oversized:
        await files_write(
            FilesWriteArguments(path="large.txt", content="é" * 10_000, overwrite=False),
            context,
        )
    assert oversized.value.code == "FILE_TOO_LARGE"


async def test_malformed_or_linked_fixture_fails_closed(tmp_path: Path) -> None:
    context = _context(tmp_path)
    (tmp_path / "documents.json").write_text("not-json", encoding="utf-8")

    with pytest.raises(ToolAdapterError) as invalid:
        await documents_search(DocumentsSearchArguments(query="vpn"), context)
    assert invalid.value.code == "TOOL_DATA_INVALID"
