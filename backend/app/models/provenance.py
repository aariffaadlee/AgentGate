"""Server-assigned data provenance and trust labels."""

from uuid import UUID

from sqlalchemy import CheckConstraint, Enum, ForeignKey, String, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ProvenanceSourceType, TrustLabel


class ProvenanceRecord(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A content hash, source, trust label, and optional derivation parent."""

    __tablename__ = "provenance_records"
    __table_args__ = (
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="provenance_not_self_parent"),
        CheckConstraint(
            "created_by_agent_id IS NULL OR created_by_admin_id IS NULL",
            name="provenance_single_creator",
        ),
        CheckConstraint(
            "content_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="canonical_content_hash",
        ),
    )

    task_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tool_request_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_requests.id", ondelete="RESTRICT"),
        index=True,
    )
    parent_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("provenance_records.id", ondelete="RESTRICT"),
    )
    source_type: Mapped[ProvenanceSourceType] = mapped_column(
        Enum(
            ProvenanceSourceType,
            name="provenance_source_type",
            native_enum=False,
            create_constraint=True,
            length=24,
        ),
        nullable=False,
        index=True,
    )
    trust_label: Mapped[TrustLabel] = mapped_column(
        Enum(
            TrustLabel,
            name="trust_label",
            native_enum=False,
            create_constraint=True,
            length=12,
        ),
        nullable=False,
        index=True,
    )
    source_reference: Mapped[str | None] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    created_by_agent_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
    )
    created_by_admin_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("administrators.id", ondelete="RESTRICT"),
    )
    attributes: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )


class ToolRequestInfluence(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Immutable declaration that one authoritative record influenced one request."""

    __tablename__ = "tool_request_influences"
    __table_args__ = (
        UniqueConstraint(
            "tool_request_id",
            "provenance_record_id",
            name="uq_tool_request_influences_request_record",
        ),
    )

    tool_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provenance_record_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("provenance_records.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
