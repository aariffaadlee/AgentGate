"""Gateway timeout, preflight, result-schema, and output-size enforcement tests."""

import asyncio
import shutil
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from app.models.enums import RiskTier
from app.tools.adapters import MockMailbox, ToolAdapterError, ToolExecutionContext
from app.tools.gateway import ToolGateway
from app.tools.registry import STATIC_TOOL_REGISTRY, ToolDefinition, ToolLimits
from app.tools.schemas import (
    DocumentsSearchArguments,
    DocumentsSearchResult,
    EmailActionResult,
    FileReadResult,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _gateway(tmp_path: Path) -> ToolGateway:
    for name in ("documents.json", "tickets.json", "database.json"):
        shutil.copyfile(PROJECT_ROOT / "synthetic_data" / name, tmp_path / name)
    (tmp_path / "sandbox").mkdir()
    return ToolGateway(ToolExecutionContext(tmp_path, MockMailbox()))


async def test_gateway_validates_and_sanitizes_registered_result(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)
    definition = STATIC_TOOL_REGISTRY.get("documents.search")
    assert definition is not None
    prepared = await gateway.prepare(definition, {"query": "VPN", "max_results": 2})

    execution = await gateway.execute(definition, prepared)

    assert execution.result["match_count"] == 1
    assert execution.summary == {
        "result_size_bytes": execution.size_bytes,
        "sanitized": True,
        "match_count": 1,
        "truncated": False,
    }
    assert "snippet" not in execution.summary


async def test_gateway_rejects_extra_fields_before_adapter_dispatch(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)
    definition = STATIC_TOOL_REGISTRY.get("documents.search")
    assert definition is not None

    with pytest.raises(ValidationError, match="extra_forbidden"):
        await gateway.prepare(definition, {"query": "vpn", "shell": "whoami"})


async def test_gateway_derives_real_overwrite_state(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)
    definition = STATIC_TOOL_REGISTRY.get("files.write")
    assert definition is not None
    target = tmp_path / "sandbox" / "existing.txt"
    target.write_text("before", encoding="utf-8")

    prepared = await gateway.prepare(
        definition,
        {"path": "existing.txt", "content": "after", "overwrite": True},
    )
    assert prepared.policy_arguments["overwrite"] is True
    assert prepared.normalized_arguments["overwrite"] is True

    new_target = await gateway.prepare(
        definition,
        {"path": "new.txt", "content": "after", "overwrite": True},
    )
    assert new_target.normalized_arguments["overwrite"] is True
    assert new_target.policy_arguments["overwrite"] is False

    with pytest.raises(ToolAdapterError) as no_overwrite:
        await gateway.prepare(
            definition,
            {"path": "existing.txt", "content": "after", "overwrite": False},
        )
    assert no_overwrite.value.code == "FILE_EXISTS"


def _definition(
    adapter,
    *,
    result_model: type[BaseModel] = DocumentsSearchResult,
    timeout: float = 0.1,
    max_response_bytes: int = 1_024,
) -> ToolDefinition:
    return ToolDefinition(
        name="test.adapter",
        risk_tier=RiskTier.LOW,
        argument_model=DocumentsSearchArguments,
        result_model=result_model,
        adapter=adapter,
        limits=ToolLimits(timeout, 1_024, max_response_bytes, 1),
    )


async def test_gateway_timeout_prevents_unbounded_adapter_execution(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)

    async def slow(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
        del arguments, context
        await asyncio.sleep(0.05)
        return DocumentsSearchResult(matches=[], match_count=0, truncated=False)

    definition = _definition(slow, timeout=0.001)
    prepared = await gateway.prepare(definition, {"query": "vpn"})
    with pytest.raises(ToolAdapterError) as timed_out:
        await gateway.execute(definition, prepared)
    assert timed_out.value.code == "TOOL_TIMEOUT"


async def test_gateway_rejects_oversized_or_wrongly_typed_adapter_results(
    tmp_path: Path,
) -> None:
    gateway = _gateway(tmp_path)

    async def large(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
        del arguments, context
        return FileReadResult(path="safe.txt", content="x" * 100, size_bytes=100)

    large_definition = _definition(large, result_model=FileReadResult, max_response_bytes=20)
    prepared = await gateway.prepare(large_definition, {"query": "vpn"})
    with pytest.raises(ToolAdapterError) as oversized:
        await gateway.execute(large_definition, prepared)
    assert oversized.value.code == "TOOL_RESULT_TOO_LARGE"

    async def wrong(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
        del arguments, context
        return EmailActionResult(message_id="draft-" + ("a" * 32), status="draft_created")

    wrong_definition = _definition(wrong)
    prepared = await gateway.prepare(wrong_definition, {"query": "vpn"})
    with pytest.raises(ToolAdapterError) as invalid:
        await gateway.execute(wrong_definition, prepared)
    assert invalid.value.code == "TOOL_RESULT_INVALID"


async def test_gateway_converts_unexpected_adapter_exception_to_stable_code(
    tmp_path: Path,
) -> None:
    gateway = _gateway(tmp_path)

    async def broken(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
        del arguments, context
        raise RuntimeError("sensitive internal detail")

    definition = _definition(broken)
    prepared = await gateway.prepare(definition, {"query": "vpn"})
    with pytest.raises(ToolAdapterError) as failed:
        await gateway.execute(definition, prepared)
    assert failed.value.code == "TOOL_EXECUTION_FAILED"
