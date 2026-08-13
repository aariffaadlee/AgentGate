"""Application factory behavior tests."""

from app.config import Environment, Settings
from app.main import create_app
from tests.support import app_client


async def test_api_documentation_can_be_disabled() -> None:
    settings = Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_url="postgresql+asyncpg://agentgate:test-only@localhost/agentgate_test",
        docs_enabled=False,
    )
    app = create_app(settings)

    async with app_client(app) as client:
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/redoc")).status_code == 404
        assert (await client.get("/openapi.json")).status_code == 404


async def test_api_documentation_csp_is_restricted_when_enabled() -> None:
    settings = Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_url="postgresql+asyncpg://agentgate:test-only@localhost/agentgate_test",
        docs_enabled=True,
    )
    app = create_app(settings)

    async with app_client(app) as client:
        response = await client.get("/docs")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in csp
    assert "frame-ancestors 'none'" in csp
