"""Request-independent construction of the audit service."""

from typing import cast

from fastapi import Request

from app.config import Settings
from app.db.audit import SQLAlchemyAuditRepository
from app.db.session import Database
from app.services.audit import AuditService


async def get_audit_service(request: Request) -> AuditService:
    """Use a dedicated session so audit appends cannot absorb endpoint state."""

    database = cast(Database, request.app.state.database)
    settings = cast(Settings, request.app.state.settings)
    return AuditService(
        SQLAlchemyAuditRepository(database.engine),
        key=settings.audit_hmac_key_bytes,
        checkpoint_path=settings.audit_checkpoint_path,
    )
