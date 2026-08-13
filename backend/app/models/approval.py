"""Exact-bound approval request and administrator action models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ApprovalActionType, ApprovalStatus


class ApprovalRequest(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One expiring authorization bound to one immutable tool request."""

    __tablename__ = "approval_requests"
    __table_args__ = (
        UniqueConstraint("tool_request_id", name="uq_approval_requests_tool_request"),
        CheckConstraint("expires_at > created_at", name="approval_expiry_after_creation"),
        CheckConstraint("row_version > 0", name="positive_approval_row_version"),
    )

    tool_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_requests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    agent_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[ApprovalStatus] = mapped_column(
        Enum(
            ApprovalStatus,
            name="approval_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        default=ApprovalStatus.PENDING,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class ApprovalAction(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only record of an administrator's approval decision."""

    __tablename__ = "approval_actions"

    approval_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("approval_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    administrator_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("administrators.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action: Mapped[ApprovalActionType] = mapped_column(
        Enum(
            ApprovalActionType,
            name="approval_action_type",
            native_enum=False,
            create_constraint=True,
            length=12,
        ),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(Text)
