"""Serialized PostgreSQL persistence for the keyed audit chain."""

import asyncio
from collections.abc import Sequence
from uuid import UUID, uuid4

from sqlalchemy import Select, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.models.audit import AuditEvent
from app.services.audit import (
    GENESIS_HASH,
    AuditEventDraft,
    AuditIntegrityError,
    CheckpointStore,
    build_audit_event,
    create_checkpoint,
    verify_audit_chain,
)

AUDIT_APPEND_LOCK_ID = 0x4147454E54474154


class SQLAlchemyAuditRepository:
    """Own a dedicated transaction for each append or read operation."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def append_batch(
        self,
        drafts: Sequence[AuditEventDraft],
        *,
        key: bytes,
        checkpoint_store: CheckpointStore,
    ) -> list[AuditEvent]:
        """Verify and extend the chain under one transaction-scoped advisory lock."""

        async with self._engine.connect() as connection:
            lock_held = False
            try:
                await connection.execute(
                    text("SELECT pg_advisory_lock(:lock_id)"),
                    {"lock_id": AUDIT_APPEND_LOCK_ID},
                )
                await connection.commit()
                lock_held = True
                async with (
                    AsyncSession(
                        bind=connection,
                        expire_on_commit=False,
                        autoflush=False,
                    ) as session,
                    session.begin(),
                ):
                    existing = await _all_events(session)
                    checkpoint = await asyncio.to_thread(checkpoint_store.read)
                    current = verify_audit_chain(existing, checkpoint, key)
                    if not current.valid:
                        raise AuditIntegrityError(
                            "audit append refused because verification returned "
                            f"{current.reason_code}"
                        )

                    chain_id = existing[0].chain_id if existing else uuid4()
                    sequence = existing[-1].sequence if existing else 0
                    previous_hash = existing[-1].event_hash if existing else GENESIS_HASH
                    appended: list[AuditEvent] = []
                    for draft in drafts:
                        sequence += 1
                        event = build_audit_event(
                            draft,
                            sequence=sequence,
                            chain_id=chain_id,
                            previous_hash=previous_hash,
                            key=key,
                        )
                        appended.append(event)
                        previous_hash = event.event_hash

                    session.add_all(appended)
                    await session.flush()

                # The database commit above happens before the atomic file replace,
                # while this connection's session-level advisory lock is still held.
                await asyncio.to_thread(
                    checkpoint_store.write,
                    create_checkpoint(appended[-1], key),
                )
                return appended
            finally:
                if lock_held:
                    await connection.execute(
                        text("SELECT pg_advisory_unlock(:lock_id)"),
                        {"lock_id": AUDIT_APPEND_LOCK_ID},
                    )
                    await connection.commit()

    async def list_events(
        self,
        *,
        after_sequence: int,
        limit: int,
        correlation_id: UUID | None,
        task_id: UUID | None,
        tool_request_id: UUID | None,
        event_type: str | None,
    ) -> Sequence[AuditEvent]:
        statement: Select[tuple[AuditEvent]] = select(AuditEvent).where(
            AuditEvent.sequence > after_sequence
        )
        if correlation_id is not None:
            statement = statement.where(AuditEvent.correlation_id == correlation_id)
        if task_id is not None:
            statement = statement.where(AuditEvent.task_id == task_id)
        if tool_request_id is not None:
            statement = statement.where(AuditEvent.tool_request_id == tool_request_id)
        if event_type is not None:
            statement = statement.where(AuditEvent.event_type == event_type)
        statement = statement.order_by(AuditEvent.sequence).limit(limit)
        async with self._session_factory() as session:
            result = await session.execute(statement)
            return result.scalars().all()

    async def list_all_events(self) -> Sequence[AuditEvent]:
        async with self._session_factory() as session:
            return await _all_events(session)


async def _all_events(session: AsyncSession) -> list[AuditEvent]:
    result = await session.execute(select(AuditEvent).order_by(AuditEvent.sequence))
    return list(result.scalars().all())
