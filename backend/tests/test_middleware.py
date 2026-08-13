"""Request framing, size, CORS, and method-handling tests."""

import httpx


async def test_declared_oversized_body_is_rejected_before_routing(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/health/live",
        content=b"x" * 1_025,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_encoded_request_body_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/health/live",
        content=b"not-really-gzip",
        headers={"Content-Encoding": "gzip"},
    )

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "MALFORMED_REQUEST"


async def test_disallowed_method_uses_safe_error_response(client: httpx.AsyncClient) -> None:
    response = await client.post("/health/live", content=b"")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert response.json()["error"]["message"] == (
        "The HTTP method is not allowed for this resource."
    )


async def test_allowed_local_cors_preflight(client: httpx.AsyncClient) -> None:
    response = await client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


async def test_unlisted_cors_origin_receives_no_allow_origin(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/health/live",
        headers={"Origin": "https://attacker.example"},
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
