"""Tamper-evident audit event storage."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import AuditActorType


class AuditEvent(Base):
    """Ordered redacted security event with a keyed hash-chain link."""

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("sequence > 0", name="positive_audit_sequence"),
        CheckConstraint(
            "previous_hash ~ '^[0-9a-f]{64}$'",
            name="canonical_audit_previous_hash",
        ),
        CheckConstraint(
            "event_hash ~ '^[0-9a-f]{64}$'",
            name="canonical_audit_event_hash",
        ),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="audit_payload_object"),
        CheckConstraint(
            "(actor_type = 'SYSTEM' AND actor_id IS NULL) OR "
            "(actor_type <> 'SYSTEM' AND actor_id IS NOT NULL)",
            name="audit_actor_identity",
        ),
    )

    sequence: Mapped[int] = mapped_column(
        BigInteger,
        Identity(always=False),
        primary_key=True,
    )
    event_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        unique=True,
        default=uuid4,
    )
    chain_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    correlation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    actor_type: Mapped[AuditActorType] = mapped_column(
        Enum(
            AuditActorType,
            name="audit_actor_type",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
    )
    actor_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    task_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        index=True,
    )
    tool_request_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_requests.id", ondelete="RESTRICT"),
        index=True,
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
