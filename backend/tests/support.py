"""HTTPX helpers for exercising ASGI apps without deprecated test clients."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from app.api.audit_dependencies import get_audit_service
from app.services.audit import AuditEventDraft


class RecordingAuditService:
    """Minimal append sink for API tests that replace database-backed services."""

    def __init__(self) -> None:
        self.events: list[AuditEventDraft] = []

    async def append(self, *drafts: AuditEventDraft) -> list[object]:
        self.events.extend(drafts)
        return []


def install_recording_audit(application: FastAPI) -> RecordingAuditService:
    audit = RecordingAuditService()
    application.dependency_overrides[get_audit_service] = lambda: audit
    application.state.recording_audit = audit
    return audit


@asynccontextmanager
async def app_client(
    application: FastAPI,
    *,
    raise_app_exceptions: bool = False,
) -> AsyncIterator[httpx.AsyncClient]:
    """Run application lifespan and expose a local-only HTTPX ASGI client."""

    transport = httpx.ASGITransport(
        app=application,
        raise_app_exceptions=raise_app_exceptions,
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client,
    ):
        yield client
