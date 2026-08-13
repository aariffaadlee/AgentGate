"""Request limits, request correlation, security headers, and access events."""

import json
from time import perf_counter
from uuid import UUID, uuid4

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from structlog.contextvars import bind_contextvars, clear_contextvars

from app.api.errors import ErrorCode

logger = structlog.get_logger(__name__)


class _AmbiguousJSON(ValueError):
    """Duplicate keys or non-finite values make canonical request binding unsafe."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _AmbiguousJSON
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> object:
    raise _AmbiguousJSON


def _request_id(scope: Scope) -> str:
    headers = Headers(scope=scope)
    candidate = headers.get("x-request-id")
    if candidate:
        try:
            return str(UUID(candidate))
        except ValueError:
            pass
    return str(uuid4())


def _security_headers(path: str) -> dict[str, str]:
    if path in {"/docs", "/redoc"} or path.startswith("/docs/"):
        content_security_policy = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    else:
        content_security_policy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return {
        "cache-control": "no-store",
        "content-security-policy": content_security_policy,
        "permissions-policy": "camera=(), geolocation=(), microphone=()",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }


class RequestContextMiddleware:
    """Create a trusted request ID and add security/access metadata."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _request_id(scope)
        scope.setdefault("state", {})["request_id"] = request_id
        clear_contextvars()
        bind_contextvars(request_id=request_id)
        started_at = perf_counter()
        status_code = 500

        async def send_with_headers(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["x-request-id"] = request_id
                for name, value in _security_headers(str(scope.get("path", ""))).items():
                    headers[name] = value
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            duration_ms = round((perf_counter() - started_at) * 1000, 3)
            await logger.ainfo(
                "http_request_completed",
                method=scope.get("method"),
                path=scope.get("path"),
                status_code=status_code,
                duration_ms=duration_ms,
            )
            clear_contextvars()


class RequestBodyLimitMiddleware:
    """Buffer at most the configured small JSON body ceiling before parsing."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _send_error(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: ErrorCode,
        message: str,
    ) -> None:
        request_id = str(scope.get("state", {}).get("request_id", "unavailable"))
        body = json.dumps(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": request_id,
                    "fields": None,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        content_lengths = [value for key, value in raw_headers if key.lower() == b"content-length"]
        if len(content_lengths) > 1:
            await self._send_error(
                scope,
                receive,
                send,
                status_code=400,
                code=ErrorCode.MALFORMED_REQUEST,
                message="The request framing is invalid.",
            )
            return
        if content_lengths:
            try:
                declared_length = int(content_lengths[0])
            except ValueError:
                declared_length = -1
            if declared_length < 0:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code=ErrorCode.MALFORMED_REQUEST,
                    message="The request framing is invalid.",
                )
                return
            if declared_length > self.max_body_bytes:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=413,
                    code=ErrorCode.REQUEST_TOO_LARGE,
                    message="The request body exceeds the configured limit.",
                )
                return

        headers = Headers(scope=scope)
        content_encoding = headers.get("content-encoding", "identity").lower()
        if content_encoding not in {"", "identity"}:
            await self._send_error(
                scope,
                receive,
                send,
                status_code=415,
                code=ErrorCode.MALFORMED_REQUEST,
                message="Encoded request bodies are not supported.",
            )
            return

        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > self.max_body_bytes:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=413,
                    code=ErrorCode.REQUEST_TOO_LARGE,
                    message="The request body exceeds the configured limit.",
                )
                return
            if not message.get("more_body", False):
                break

        complete_body = b"".join(chunks)
        scope.setdefault("state", {})["request_body_size_bytes"] = len(complete_body)
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if complete_body and (content_type == "application/json" or content_type.endswith("+json")):
            try:
                json.loads(
                    complete_body,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_non_finite_constant,
                )
            except _AmbiguousJSON:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code=ErrorCode.MALFORMED_REQUEST,
                    message="JSON property names must be unique and values must be finite.",
                )
                return
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": complete_body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)
