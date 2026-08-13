"""Immutable executable registry and checksummed database-mirror manifest."""

import re
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from pydantic import BaseModel

from app.auth.crypto import canonical_json, sha256_hex
from app.models.enums import RiskTier
from app.tools import adapters
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

ToolAdapter = Callable[[BaseModel, adapters.ToolExecutionContext], Awaitable[BaseModel]]
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


@dataclass(frozen=True)
class ToolLimits:
    timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int
    rate_limit: int
    rate_window_seconds: int = 60

    def as_dict(self) -> dict[str, int | float]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "rate_limit": self.rate_limit,
            "rate_window_seconds": self.rate_window_seconds,
        }


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    risk_tier: RiskTier
    argument_model: type[BaseModel]
    result_model: type[BaseModel]
    adapter: ToolAdapter
    limits: ToolLimits
    schema_version: str = "1.0.0"
    adapter_version: str = "1.0.0"

    @property
    def required_capability(self) -> str:
        return self.name

    def manifest_entry(self) -> dict[str, object]:
        return {
            "name": self.name,
            "risk_tier": self.risk_tier.value,
            "required_capability": self.required_capability,
            "schema_version": self.schema_version,
            "adapter_version": self.adapter_version,
            "limits": self.limits.as_dict(),
            "argument_schema": self.argument_model.model_json_schema(),
            "result_schema": self.result_model.model_json_schema(),
        }


class StaticToolRegistry:
    """Exact-name lookup with no dynamic imports or caller-selected adapter references."""

    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        values = tuple(definitions)
        mapping = {definition.name: definition for definition in values}
        if len(mapping) != len(values):
            raise ValueError("tool names must be unique")
        if any(_TOOL_NAME.fullmatch(name) is None for name in mapping):
            raise ValueError("tool names must be exact capability names")
        self._definitions: Mapping[str, ToolDefinition] = MappingProxyType(mapping)
        manifest = [mapping[name].manifest_entry() for name in sorted(mapping)]
        self._manifest_checksum = sha256_hex(canonical_json(manifest))

    def get(self, name: str) -> ToolDefinition | None:
        return self._definitions.get(name)

    def __iter__(self) -> Iterator[ToolDefinition]:
        for name in sorted(self._definitions):
            yield self._definitions[name]

    def __len__(self) -> int:
        return len(self._definitions)

    @property
    def manifest_checksum(self) -> str:
        return self._manifest_checksum

    def database_constraints(self, definition: ToolDefinition) -> dict[str, object]:
        return {
            "required_capability": definition.required_capability,
            **definition.limits.as_dict(),
        }


UNKNOWN_TOOL_LIMITS = ToolLimits(
    timeout_seconds=0.1,
    max_request_bytes=4_096,
    max_response_bytes=1_024,
    rate_limit=5,
)


STATIC_TOOL_REGISTRY = StaticToolRegistry(
    [
        ToolDefinition(
            name="documents.search",
            risk_tier=RiskTier.LOW,
            argument_model=DocumentsSearchArguments,
            result_model=DocumentsSearchResult,
            adapter=adapters.documents_search,
            limits=ToolLimits(1.0, 4_096, 16_384, 30),
        ),
        ToolDefinition(
            name="tickets.read",
            risk_tier=RiskTier.LOW,
            argument_model=TicketsReadArguments,
            result_model=TicketReadResult,
            adapter=adapters.tickets_read,
            limits=ToolLimits(1.0, 1_024, 16_384, 30),
        ),
        ToolDefinition(
            name="email.create_draft",
            risk_tier=RiskTier.MEDIUM,
            argument_model=EmailArguments,
            result_model=EmailActionResult,
            adapter=adapters.email_create_draft,
            limits=ToolLimits(1.0, 16_384, 1_024, 10),
        ),
        ToolDefinition(
            name="email.send",
            risk_tier=RiskTier.HIGH,
            argument_model=EmailArguments,
            result_model=EmailActionResult,
            adapter=adapters.email_send,
            limits=ToolLimits(1.0, 16_384, 1_024, 5),
        ),
        ToolDefinition(
            name="files.read",
            risk_tier=RiskTier.MEDIUM,
            argument_model=FilesReadArguments,
            result_model=FileReadResult,
            adapter=adapters.files_read,
            limits=ToolLimits(1.0, 1_024, 70_000, 20),
        ),
        ToolDefinition(
            name="files.write",
            risk_tier=RiskTier.HIGH,
            argument_model=FilesWriteArguments,
            result_model=FileWriteResult,
            adapter=adapters.files_write,
            limits=ToolLimits(1.0, 24_576, 1_024, 5),
        ),
        ToolDefinition(
            name="database.query",
            risk_tier=RiskTier.MEDIUM,
            argument_model=DatabaseQueryArguments,
            result_model=DatabaseQueryResult,
            adapter=adapters.database_query,
            limits=ToolLimits(1.5, 4_096, 16_384, 15),
        ),
    ]
)
