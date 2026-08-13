"""Optional real-OPA integration test used by Compose and local policy gates."""

import os

import pytest

from app.models.enums import PolicyOutcome
from app.policies.client import PolicyClient
from tests.test_policy_client import policy_input


async def test_live_opa_returns_validated_allow_decision() -> None:
    opa_url = os.getenv("AGENTGATE_TEST_OPA_URL")
    if not opa_url:
        pytest.skip("AGENTGATE_TEST_OPA_URL is not configured")
    client = PolicyClient(base_url=opa_url, timeout_seconds=2)
    try:
        assert await client.is_ready() is True
        decision = await client.evaluate(policy_input())
    finally:
        await client.close()

    assert decision.decision is PolicyOutcome.ALLOW
    assert decision.reason_codes == ["LOW_RISK_CAPABILITY_ALLOWED"]
    assert decision.policy_version == "1.0.0"
