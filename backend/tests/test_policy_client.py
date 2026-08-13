"""OPA client contract and fail-closed behavior tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest

from app.models.enums import AgentStatus, PolicyOutcome, RiskTier, TrustLabel
from app.policies.client import (
    OPA_DECISION_PATH,
    AuthorizationInput,
    PolicyAgent,
    PolicyApproval,
    PolicyClient,
    PolicyLimits,
    PolicyProvenance,
    PolicyRequest,
    PolicyTask,
    PolicyToken,
    PolicyTool,
)


def policy_input() -> AuthorizationInput:
    now = datetime.now(UTC)
    task_id = uuid4()
    return AuthorizationInput(
        agent=PolicyAgent(id=uuid4(), status=AgentStatus.ACTIVE),
        task=PolicyTask(id=task_id, owner_id=uuid4()),
        token=PolicyToken(
            issuer="agentgate.local",
            audience="agentgate-tools",
            expected_issuer="agentgate.local",
            expected_audience="agentgate-tools",
            expires_at=now + timedelta(minutes=5),
            task_id=task_id,
            capabilities=["tickets.read"],
            revoked=False,
            proof_valid=True,
        ),
        tool=PolicyTool(name="tickets.read", known=True, risk=RiskTier.LOW),
        request=PolicyRequest(
            arguments_valid=True,
            arguments={},
            argument_hash="sha256:" + ("a" * 64),
            body_size_bytes=2,
        ),
        provenance=PolicyProvenance(
            labels=[TrustLabel.TRUSTED],
            source_types=["user_instruction"],
            untrusted_influence=False,
            trusted_intent_present=True,
            context_valid=True,
        ),
        approval=PolicyApproval(
            status="none",
            argument_hash=None,
            expires_at=None,
            consumed=False,
        ),
        limits=PolicyLimits(
            rate_exceeded=False,
            request_size_exceeded=False,
            expected_response_size_exceeded=False,
        ),
        now=now,
    )


async def test_policy_client_accepts_strict_named_decision() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == OPA_DECISION_PATH
        assert b'"input"' in request.content
        return httpx.Response(
            200,
            json={
                "decision_id": "opa-decision-1",
                "result": {
                    "decision": "allow",
                    "reason_codes": ["LOW_RISK_CAPABILITY_ALLOWED"],
                    "policy_version": "1.0.0",
                    "opa_decision_id": None,
                },
            },
        )

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.test",
    )
    client = PolicyClient(base_url="http://ignored.test", timeout_seconds=1, client=http_client)

    result = await client.evaluate(policy_input())

    assert result.decision is PolicyOutcome.ALLOW
    assert result.reason_codes == ["LOW_RISK_CAPABILITY_ALLOWED"]
    assert result.opa_decision_id == "opa-decision-1"
    await http_client.aclose()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"result": None},
        {
            "result": {
                "decision": "allow",
                "reason_codes": ["CAPABILITY_MISSING"],
                "policy_version": "1.0.0",
            }
        },
        {
            "result": {
                "decision": "permit",
                "reason_codes": ["LOW_RISK_CAPABILITY_ALLOWED"],
                "policy_version": "1.0.0",
            }
        },
        {
            "result": {
                "decision": "deny",
                "reason_codes": [],
                "policy_version": "1.0.0",
            }
        },
        {
            "result": {
                "decision": "deny",
                "reason_codes": ["DEFAULT_DENY"],
                "policy_version": "1.0.0",
            },
            "unexpected": "field",
        },
    ],
)
async def test_policy_client_denies_malformed_or_undefined_results(
    payload: dict[str, object],
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.test",
    )
    client = PolicyClient(base_url="http://ignored.test", timeout_seconds=1, client=http_client)

    result = await client.evaluate(policy_input())

    assert result.decision is PolicyOutcome.DENY
    assert result.reason_codes == ["POLICY_ENGINE_ERROR"]
    assert result.policy_version == "unavailable"
    await http_client.aclose()


async def test_policy_client_denies_transport_and_http_failures() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == OPA_DECISION_PATH:
            raise httpx.ConnectError("opa unavailable", request=request)
        return httpx.Response(503)

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.test",
    )
    client = PolicyClient(base_url="http://ignored.test", timeout_seconds=1, client=http_client)

    result = await client.evaluate(policy_input())

    assert result.reason_codes == ["POLICY_ENGINE_ERROR"]
    assert await client.is_ready() is False
    await http_client.aclose()


async def test_policy_client_denies_oversized_response() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + (b"x" * 2_000) + b"}")

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.test",
    )
    client = PolicyClient(
        base_url="http://ignored.test",
        timeout_seconds=1,
        max_response_bytes=1_024,
        client=http_client,
    )

    result = await client.evaluate(policy_input())

    assert result.reason_codes == ["POLICY_ENGINE_ERROR"]
    await http_client.aclose()


async def test_policy_readiness_accepts_only_success_status() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/health"
        assert "plugins" in request.url.query.decode()
        return httpx.Response(200, json={})

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.test",
    )
    client = PolicyClient(base_url="http://ignored.test", timeout_seconds=1, client=http_client)

    assert await client.is_ready() is True
    await client.close()
    assert not http_client.is_closed
    await http_client.aclose()
