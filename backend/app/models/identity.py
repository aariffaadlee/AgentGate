"""Administrator, workload identity, credential, proof, and revocation models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import AdministratorStatus, AgentStatus, CredentialStatus


class Administrator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Local administrative principal; plaintext credentials are never persisted."""

    __tablename__ = "administrators"

    username: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    credential_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[AdministratorStatus] = mapped_column(
        Enum(
            AdministratorStatus,
            name="administrator_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        default=AdministratorStatus.ACTIVE,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Agent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stable workload identity bound to one public key."""

    __tablename__ = "agents"

    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    status: Mapped[AgentStatus] = mapped_column(
        Enum(
            AgentStatus,
            name="agent_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        default=AgentStatus.ACTIVE,
    )
    public_jwk: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    key_thumbprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentCredential(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Metadata for an issued token; the encoded bearer token is never stored."""

    __tablename__ = "agent_credentials"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="expiry_after_issue"),
        CheckConstraint("not_before_at <= expires_at", name="not_before_expiry"),
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
    jti_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_thumbprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[CredentialStatus] = mapped_column(
        Enum(
            CredentialStatus,
            name="credential_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        default=CredentialStatus.ACTIVE,
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_before_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RequestProof(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One-time signed request proof identifiers used to reject replay."""

    __tablename__ = "request_proofs"

    agent_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    credential_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agent_credentials.id", ondelete="RESTRICT"),
        index=True,
    )
    proof_jti_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    proof_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class Revocation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only revocation fact for an agent and/or an issued credential."""

    __tablename__ = "revocations"
    __table_args__ = (
        CheckConstraint(
            "agent_id IS NOT NULL OR credential_id IS NOT NULL",
            name="revocation_has_target",
        ),
    )

    agent_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        index=True,
    )
    credential_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agent_credentials.id", ondelete="RESTRICT"),
        index=True,
    )
    revoked_by_admin_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("administrators.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
