"""Strict validation, preflight, timeout, result-model, and size enforcement."""

import asyncio
from dataclasses import dataclass
from typing import cast

import structlog
from pydantic import BaseModel, ValidationError

from app.auth.crypto import canonical_json
from app.tools.adapters import (
    ToolAdapterError,
    ToolExecutionContext,
    inspect_write_target,
)
from app.tools.registry import ToolDefinition
from app.tools.schemas import FilesWriteArguments

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PreparedArguments:
    model: BaseModel
    normalized_arguments: dict[str, object]
    policy_arguments: dict[str, object]


@dataclass(frozen=True)
class ToolExecutionResult:
    result: dict[str, object]
    summary: dict[str, object]
    size_bytes: int


class ToolGateway:
    """The only runtime component allowed to invoke a registered adapter."""

    def __init__(self, context: ToolExecutionContext) -> None:
        self._context = context

    async def prepare(
        self,
        definition: ToolDefinition,
        arguments: dict[str, object],
    ) -> PreparedArguments:
        """Strictly validate and add only server-derived policy facts."""

        model = definition.argument_model.model_validate(arguments)
        normalized_arguments = cast(dict[str, object], model.model_dump(mode="json"))
        policy_arguments = dict(normalized_arguments)
        if isinstance(model, FilesWriteArguments):
            will_overwrite = await asyncio.to_thread(
                inspect_write_target,
                self._context.sandbox_root,
                model.path,
            )
            policy_arguments["overwrite"] = will_overwrite
            if will_overwrite and not model.overwrite:
                raise ToolAdapterError("FILE_EXISTS")
        return PreparedArguments(
            model=model,
            normalized_arguments=normalized_arguments,
            policy_arguments=policy_arguments,
        )

    async def execute(
        self,
        definition: ToolDefinition,
        prepared: PreparedArguments,
    ) -> ToolExecutionResult:
        """Run one fixed adapter and accept only its declared bounded result model."""

        try:
            async with asyncio.timeout(definition.limits.timeout_seconds):
                raw_result = await definition.adapter(prepared.model, self._context)
            result_model = definition.result_model.model_validate(
                raw_result.model_dump(mode="json")
            )
            result = cast(dict[str, object], result_model.model_dump(mode="json"))
            encoded = canonical_json(result)
            if len(encoded) > definition.limits.max_response_bytes:
                raise ToolAdapterError("TOOL_RESULT_TOO_LARGE")
            return ToolExecutionResult(
                result=result,
                summary=_result_summary(definition.name, result, len(encoded)),
                size_bytes=len(encoded),
            )
        except TimeoutError as exc:
            raise ToolAdapterError("TOOL_TIMEOUT") from exc
        except ToolAdapterError:
            raise
        except (ValidationError, TypeError, ValueError) as exc:
            raise ToolAdapterError("TOOL_RESULT_INVALID") from exc
        except Exception as exc:
            await logger.aerror(
                "tool_adapter_failed",
                tool_name=definition.name,
                exception_type=type(exc).__name__,
            )
            raise ToolAdapterError("TOOL_EXECUTION_FAILED") from exc


def _result_summary(
    tool_name: str,
    result: dict[str, object],
    size_bytes: int,
) -> dict[str, object]:
    """Persist operational metadata without copying sensitive result content."""

    summary: dict[str, object] = {
        "result_size_bytes": size_bytes,
        "sanitized": True,
    }
    safe_fields = {
        "documents.search": ("match_count", "truncated"),
        "tickets.read": ("ticket_id", "status"),
        "email.create_draft": ("message_id", "status"),
        "email.send": ("message_id", "status"),
        "files.read": ("path", "size_bytes"),
        "files.write": ("path", "size_bytes", "overwritten"),
        "database.query": ("query_id", "row_count", "truncated"),
    }[tool_name]
    for field in safe_fields:
        if field in result:
            summary[field] = result[field]
    return summary
