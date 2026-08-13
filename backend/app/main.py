"""FastAPI application factory for AgentGate."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.approvals import router as approvals_router
from app.api.audit import router as audit_router
from app.api.errors import install_exception_handlers
from app.api.health import router as health_router
from app.api.identity import router as identity_router
from app.api.metrics import router as metrics_router
from app.api.middleware import RequestBodyLimitMiddleware, RequestContextMiddleware
from app.api.tools import router as tools_router
from app.config import Environment, Settings, get_settings
from app.db.session import Database
from app.db.tools import verify_or_install_tool_manifest
from app.logging import configure_logging
from app.policies.client import PolicyClient
from app.tools.adapters import MockMailbox, ToolExecutionContext
from app.tools.gateway import ToolGateway
from app.tools.registry import STATIC_TOOL_REGISTRY


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build an isolated application instance with validated dependencies."""

    active_settings = settings or get_settings()
    configure_logging(active_settings.log_level)
    database = Database(active_settings)
    policy_client = PolicyClient(
        base_url=active_settings.opa_url,
        timeout_seconds=active_settings.opa_timeout_seconds,
        max_response_bytes=active_settings.opa_max_response_bytes,
    )
    tool_gateway = ToolGateway(
        ToolExecutionContext(
            synthetic_data_root=active_settings.synthetic_data_root,
            mailbox=MockMailbox(),
        )
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            if active_settings.environment is not Environment.TEST:
                await verify_or_install_tool_manifest(
                    database.session_factory,
                    STATIC_TOOL_REGISTRY,
                )
            yield
        finally:
            await policy_client.close()
            await database.dispose()

    docs_url = "/docs" if active_settings.docs_enabled else None
    redoc_url = "/redoc" if active_settings.docs_enabled else None
    openapi_url = "/openapi.json" if active_settings.docs_enabled else None
    application = FastAPI(
        title=active_settings.app_name,
        version=__version__,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    application.state.settings = active_settings
    application.state.database = database
    application.state.policy_client = policy_client
    application.state.tool_registry = STATIC_TOOL_REGISTRY
    application.state.tool_gateway = tool_gateway

    install_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(identity_router)
    application.include_router(tools_router)
    application.include_router(approvals_router)
    application.include_router(audit_router)
    application.include_router(metrics_router)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Agent-Proof", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    application.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=active_settings.max_request_body_bytes,
    )
    application.add_middleware(RequestContextMiddleware)
    return application


app = create_app()
