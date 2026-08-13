"""Stable, non-leaking API error responses."""

from enum import StrEnum

import structlog
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException

logger = structlog.get_logger(__name__)


class ErrorCode(StrEnum):
    """Stable error codes shared by middleware, authentication, and handlers."""

    INTERNAL_ERROR = "INTERNAL_ERROR"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    NOT_FOUND = "NOT_FOUND"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNAUTHORIZED = "UNAUTHORIZED"
    VALIDATION_ERROR = "VALIDATION_ERROR"


class ValidationField(BaseModel):
    """Non-reflective validation metadata safe to return to a client."""

    model_config = ConfigDict(extra="forbid")

    path: str
    error_type: str


class ErrorBody(BaseModel):
    """Inner error response object."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    request_id: str
    fields: list[ValidationField] | None = None


class ErrorEnvelope(BaseModel):
    """Consistent error envelope used by every API failure."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


class AgentGateError(Exception):
    """Expected application error with client-safe metadata."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.safe_message = message


def request_id_from(request: Request) -> str:
    """Read the middleware-generated request ID without trusting a raw header."""

    return str(getattr(request.state, "request_id", "unavailable"))


def error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    fields: list[ValidationField] | None = None,
) -> JSONResponse:
    """Build the canonical error response."""

    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=code,
            message=message,
            request_id=request_id,
            fields=fields,
        )
    )
    return JSONResponse(status_code=status_code, content=jsonable_encoder(envelope))


def _safe_http_error(status_code: int) -> tuple[str, str]:
    if status_code == status.HTTP_404_NOT_FOUND:
        return ErrorCode.NOT_FOUND, "The requested resource was not found."
    if status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
        return (
            ErrorCode.METHOD_NOT_ALLOWED,
            "The HTTP method is not allowed for this resource.",
        )
    if status_code == status.HTTP_401_UNAUTHORIZED:
        return ErrorCode.UNAUTHENTICATED, "Authentication is required."
    if status_code == status.HTTP_403_FORBIDDEN:
        return ErrorCode.UNAUTHORIZED, "The request is not authorized."
    return f"HTTP_{status_code}", "The request could not be completed."


def install_exception_handlers(app: FastAPI) -> None:
    """Install exception handlers without reflecting internal exception details."""

    @app.exception_handler(AgentGateError)
    async def handle_agentgate_error(request: Request, exc: AgentGateError) -> JSONResponse:
        return error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.safe_message,
            request_id=request_id_from(request),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        fields = [
            ValidationField(
                path=".".join(str(part) for part in error.get("loc", ())),
                error_type=str(error.get("type", "invalid")),
            )
            for error in exc.errors()
        ]
        return error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.VALIDATION_ERROR,
            message="The request did not match the required schema.",
            request_id=request_id_from(request),
            fields=fields,
        )

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code, message = _safe_http_error(exc.status_code)
        return error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            request_id=request_id_from(request),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        await logger.aerror(
            "unhandled_application_error",
            exception_type=type(exc).__name__,
            request_id=request_id_from(request),
        )
        return error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=ErrorCode.INTERNAL_ERROR,
            message="An internal error occurred.",
            request_id=request_id_from(request),
        )
