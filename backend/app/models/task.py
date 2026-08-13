"""Task ownership and exact capability grants."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import TaskStatus


class Task(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Trusted task intent owned by an administrative principal."""

    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint(
            "expires_at IS NULL OR starts_at IS NULL OR expires_at > starts_at",
            name="task_expiry_after_start",
        ),
    )

    owner_admin_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("administrators.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_agent_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        index=True,
    )
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    trusted_instruction_summary: Mapped[str] = mapped_column(Text, nullable=False)
    trusted_instruction_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    instruction_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    instruction_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        Enum(
            TaskStatus,
            name="task_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        default=TaskStatus.ACTIVE,
    )
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class TaskCapability(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One exact, non-wildcard capability granted to one task."""

    __tablename__ = "task_capabilities"
    __table_args__ = (
        UniqueConstraint("task_id", "capability", name="uq_task_capabilities_task_capability"),
        CheckConstraint("position('*' in capability) = 0", name="capability_has_no_wildcard"),
    )

    task_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    capability: Mapped[str] = mapped_column(String(120), nullable=False)
