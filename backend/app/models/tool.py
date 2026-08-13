"""Static tool-manifest mirror and intercepted tool request persistence."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import RiskTier, ToolRequestStatus


class ToolRegistry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Queryable mirror of the version-controlled executable tool manifest."""

    __tablename__ = "tool_registry"

    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    risk_tier: Mapped[RiskTier] = mapped_column(
        Enum(
            RiskTier,
            name="risk_tier",
            native_enum=False,
            create_constraint=True,
            length=8,
        ),
        nullable=False,
    )
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    constraints: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )


class ToolRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Every attempted tool action, including invalid and unknown tools."""

    __tablename__ = "tool_requests"
    __table_args__ = (
        CheckConstraint("request_size_bytes >= 0", name="nonnegative_request_size"),
        CheckConstraint(
            "response_size_bytes IS NULL OR response_size_bytes >= 0",
            name="nonnegative_response_size",
        ),
        CheckConstraint(
            "execution_latency_ms IS NULL OR execution_latency_ms >= 0",
            name="nonnegative_execution_latency",
        ),
        CheckConstraint(
            "(arguments_ciphertext IS NULL) = (arguments_nonce IS NULL)",
            name="arguments_encryption_pair",
        ),
    )

    correlation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    agent_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    credential_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agent_credentials.id", ondelete="RESTRICT"),
        nullable=False,
    )
    task_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tool_registry_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_registry.id", ondelete="RESTRICT"),
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    risk_tier: Mapped[RiskTier | None] = mapped_column(
        Enum(
            RiskTier,
            name="tool_request_risk_tier",
            native_enum=False,
            create_constraint=True,
            length=8,
        )
    )
    arguments_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    arguments_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    redacted_arguments: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    argument_hash: Mapped[str | None] = mapped_column(String(71))
    status: Mapped[ToolRequestStatus] = mapped_column(
        Enum(
            ToolRequestStatus,
            name="tool_request_status",
            native_enum=False,
            create_constraint=True,
            length=24,
        ),
        nullable=False,
        default=ToolRequestStatus.RECEIVED,
        index=True,
    )
    request_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    response_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    result_summary: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(80))
    execution_latency_ms: Mapped[int | None] = mapped_column(Integer)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ToolRateLimitWindow(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Atomic fixed-window counter scoped to an agent, task, and static tool."""

    __tablename__ = "tool_rate_limit_windows"
    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "task_id",
            "tool_name",
            "window_started_at",
            name="uq_tool_rate_limit_scope_window",
        ),
        CheckConstraint("request_count > 0", name="positive_request_count"),
    )

    agent_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)
