"""Contract tests for the proof-bound portfolio demonstration client."""

import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from demo_agent import DemoClientError, run_demo  # noqa: E402

AGENT_ID = "10000000-0000-4000-8000-000000000001"
TASK_ID = "20000000-0000-4000-8000-000000000002"
INTENT_ID = "30000000-0000-4000-8000-000000000003"
ALLOWED_ID = "40000000-0000-4000-8000-000000000004"
DENIED_ID = "50000000-0000-4000-8000-000000000005"
PENDING_ID = "60000000-0000-4000-8000-000000000006"
APPROVAL_ID = "70000000-0000-4000-8000-000000000007"
ARGUMENT_HASH = f"sha256:{'a' * 64}"


@pytest.mark.asyncio
async def test_demo_uses_public_key_proofs_and_returns_only_sanitized_evidence() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body: dict[str, Any] = json.loads(request.content) if request.content else {}
        route = (request.method, request.url.path)
        if route == ("POST", "/admin/session"):
            return httpx.Response(200, json={"access_token": "admin-token-value"})
        if route == ("POST", "/agents"):
            assert set(body) == {"name", "public_jwk"}
            assert body["public_jwk"]["kty"] == "OKP"
            return httpx.Response(201, json={"id": AGENT_ID})
        if route == ("POST", "/tasks"):
            return httpx.Response(
                201,
                json={"id": TASK_ID, "trusted_intent_provenance_id": INTENT_ID},
            )
        if route == ("POST", f"/agents/{AGENT_ID}/tokens"):
            return httpx.Response(201, json={"access_token": "workload-token-value"})
        if route == ("POST", "/tool-requests"):
            tool_name = body["tool_name"]
            if tool_name == "documents.search":
                return httpx.Response(
                    201,
                    json={"id": ALLOWED_ID, "decision": "allow"},
                )
            if tool_name == "shell.exec":
                return httpx.Response(
                    403,
                    json={
                        "id": DENIED_ID,
                        "decision": "deny",
                        "reason_codes": [
                            "ARGUMENTS_INVALID",
                            "CAPABILITY_MISSING",
                            "UNKNOWN_TOOL",
                        ],
                    },
                )
            assert tool_name == "email.send"
            return httpx.Response(
                202,
                json={"id": PENDING_ID, "approval_id": APPROVAL_ID},
            )
        if route == ("GET", "/approvals"):
            return httpx.Response(
                200,
                json=[{"id": APPROVAL_ID, "argument_hash": ARGUMENT_HASH}],
            )
        if route == ("POST", f"/approvals/{APPROVAL_ID}/approve"):
            assert body["argument_hash"] == ARGUMENT_HASH
            return httpx.Response(200, json={"status": "consumed"})
        if route == ("POST", "/audit/verify"):
            return httpx.Response(
                200,
                json={"valid": True, "reason_code": "CHAIN_VALID"},
            )
        raise AssertionError(f"unexpected route: {route}")

    bootstrap_secret = "bootstrap-secret-that-is-never-returned"
    summary = await run_demo(
        api_base="http://127.0.0.1:8000",
        bootstrap_secret=bootstrap_secret,
        transport=httpx.MockTransport(handler),
    )

    assert summary.allowed_decision == "allow"
    assert summary.denied_reason_codes == (
        "ARGUMENTS_INVALID",
        "CAPABILITY_MISSING",
        "UNKNOWN_TOOL",
    )
    assert summary.approval_status == "consumed"
    assert summary.audit_valid is True
    serialized = json.dumps(summary.as_dict(), sort_keys=True)
    assert bootstrap_secret not in serialized
    assert "admin-token-value" not in serialized
    assert "workload-token-value" not in serialized
    assert "Synthetic demo only" not in serialized

    agent_request = next(request for request in requests if request.url.path == "/agents")
    assert "private" not in agent_request.content.decode("utf-8").lower()
    proof_requests = [request for request in requests if "x-agent-proof" in request.headers]
    assert len(proof_requests) == 4
    assert len({request.headers["x-agent-proof"] for request in proof_requests}) == 4
    workload_requests = [request for request in requests if request.url.path == "/tool-requests"]
    assert all(
        request.headers["authorization"] == "Bearer workload-token-value"
        for request in workload_requests
    )
    admin_paths = {"/agents", "/tasks", "/approvals", f"/approvals/{APPROVAL_ID}/approve"}
    assert all(
        request.headers["authorization"] == "Bearer admin-token-value"
        for request in requests
        if request.url.path in admin_paths
    )


@pytest.mark.asyncio
async def test_demo_rejects_non_loopback_api_before_network_access() -> None:
    with pytest.raises(DemoClientError, match="DEMO_CONFIGURATION_INVALID"):
        await run_demo(
            api_base="https://agentgate.example.com",
            bootstrap_secret="x" * 32,
        )
