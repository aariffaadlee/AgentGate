"""Async PostgreSQL engine and request-scoped session management."""

import asyncio
from collections.abc import AsyncIterator
from typing import cast

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings


class Database:
    """Own the async engine so application instances and tests can isolate lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._health_timeout_seconds = settings.database_health_timeout_seconds
        self.engine: AsyncEngine = create_async_engine(
            settings.sqlalchemy_database_url,
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout_seconds,
            connect_args={"timeout": settings.database_pool_timeout_seconds},
        )
        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def ping(self) -> bool:
        """Return database readiness without exposing connection error details."""

        try:
            async with asyncio.timeout(self._health_timeout_seconds):
                async with self.engine.connect() as connection:
                    await connection.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    async def dispose(self) -> None:
        """Close all pooled database connections."""

        await self.engine.dispose()


async def get_database(request: Request) -> Database:
    """Resolve the application-owned database facade."""

    return cast(Database, request.app.state.database)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield one transaction-capable session for a request."""

    database: Database = request.app.state.database
    async with database.session_factory() as session:
        yield session
