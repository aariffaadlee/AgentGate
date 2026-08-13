"""A safe, proof-bound client that demonstrates AgentGate's complete control loop."""

import ipaddress
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.auth.crypto import public_jwk_from_key
from app.auth.proofs import create_request_proof

_PROOF_TTL_SECONDS = 30


class DemoClientError(RuntimeError):
    """A content-free demo failure safe to show in a terminal."""


@dataclass(frozen=True)
class DemoSummary:
    """Sanitized evidence from one complete demonstration run."""

    agent_id: str
    task_id: str
    allowed_request_id: str
    allowed_decision: str
    denied_request_id: str
    denied_reason_codes: tuple[str, ...]
    approval_id: str
    approval_status: str
    audit_valid: bool
    audit_reason_code: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable, credential-free view."""

        return asdict(self)


async def run_demo(
    *,
    api_base: str,
    bootstrap_secret: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DemoSummary:
    """Run allow, deny, approval, execution, and audit-verification scenarios."""

    if len(bootstrap_secret) < 32:
        raise DemoClientError("DEMO_CONFIGURATION_INVALID")
    origin = _loopback_origin(api_base)
    private_key = Ed25519PrivateKey.generate()

    async with httpx.AsyncClient(
        base_url=origin,
        transport=transport,
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
    ) as client:
        session = _object(
            await _request(
                client,
                "POST",
                "/admin/session",
                expected={200},
                body={"bootstrap_secret": bootstrap_secret},
            )
        )
        admin_token = _text(session, "access_token")

        agent = _object(
            await _request(
                client,
                "POST",
                "/agents",
                expected={201},
                token=admin_token,
                body={
                    "name": f"Portfolio Demo {uuid4().hex[:8]}",
                    "public_jwk": public_jwk_from_key(private_key.public_key()).model_dump(
                        mode="json"
                    ),
                },
            )
        )
        agent_id = _uuid(agent, "id")

        task = _object(
            await _request(
                client,
                "POST",
                "/tasks",
                expected={201},
                token=admin_token,
                body={
                    "assigned_agent_id": str(agent_id),
                    "title": "Demonstrate AgentGate security decisions",
                    "trusted_instruction_summary": (
                        "Search synthetic documents and send one synthetic demonstration email."
                    ),
                    "trusted_instruction": (
                        "Use only synthetic fixtures. Search for the VPN policy, then send the "
                        "demonstration result to security@example.test."
                    ),
                    "capabilities": ["documents.search", "email.send"],
                },
            )
        )
        task_id = _uuid(task, "id")
        trusted_intent_id = _uuid(task, "trusted_intent_provenance_id")

        token_body: dict[str, object] = {"task_id": str(task_id)}
        token_path = f"/agents/{agent_id}/tokens"
        token_response = _object(
            await _request(
                client,
                "POST",
                token_path,
                expected={201},
                proof=_proof(
                    private_key,
                    agent_id=agent_id,
                    path=token_path,
                    body=token_body,
                ),
                body=token_body,
            )
        )
        workload_token = _text(token_response, "access_token")

        allowed = _object(
            await _workload_request(
                client,
                private_key=private_key,
                agent_id=agent_id,
                access_token=workload_token,
                expected={201},
                body={
                    "task_id": str(task_id),
                    "tool_name": "documents.search",
                    "arguments": {"query": "VPN policy", "max_results": 2},
                    "influence_ids": [str(trusted_intent_id)],
                },
            )
        )

        denied = _object(
            await _workload_request(
                client,
                private_key=private_key,
                agent_id=agent_id,
                access_token=workload_token,
                expected={403},
                body={
                    "task_id": str(task_id),
                    "tool_name": "shell.exec",
                    "arguments": {},
                    "influence_ids": [str(trusted_intent_id)],
                },
            )
        )

        pending = _object(
            await _workload_request(
                client,
                private_key=private_key,
                agent_id=agent_id,
                access_token=workload_token,
                expected={202},
                body={
                    "task_id": str(task_id),
                    "tool_name": "email.send",
                    "arguments": {
                        "recipient": "security@example.test",
                        "subject": "Synthetic AgentGate demonstration",
                        "body": "Synthetic demo only: the VPN policy search completed.",
                    },
                    "influence_ids": [str(trusted_intent_id)],
                },
            )
        )
        approval_id = _uuid(pending, "approval_id")

        approvals = _list(
            await _request(
                client,
                "GET",
                "/approvals",
                expected={200},
                token=admin_token,
            )
        )
        approval = _find_by_id(approvals, approval_id)
        approved = _object(
            await _request(
                client,
                "POST",
                f"/approvals/{approval_id}/approve",
                expected={200},
                token=admin_token,
                body={
                    "argument_hash": _text(approval, "argument_hash"),
                    "reason": "Approved for the synthetic portfolio demonstration.",
                },
            )
        )
        audit = _object(
            await _request(
                client,
                "POST",
                "/audit/verify",
                expected={200},
                token=admin_token,
            )
        )

    return DemoSummary(
        agent_id=str(agent_id),
        task_id=str(task_id),
        allowed_request_id=str(_uuid(allowed, "id")),
        allowed_decision=_text(allowed, "decision"),
        denied_request_id=str(_uuid(denied, "id")),
        denied_reason_codes=_text_tuple(denied, "reason_codes"),
        approval_id=str(approval_id),
        approval_status=_text(approved, "status"),
        audit_valid=_boolean(audit, "valid"),
        audit_reason_code=_text(audit, "reason_code"),
    )


async def _workload_request(
    client: httpx.AsyncClient,
    *,
    private_key: Ed25519PrivateKey,
    agent_id: UUID,
    access_token: str,
    expected: set[int],
    body: dict[str, object],
) -> object:
    path = "/tool-requests"
    return await _request(
        client,
        "POST",
        path,
        expected=expected,
        token=access_token,
        proof=_proof(
            private_key,
            agent_id=agent_id,
            path=path,
            body=body,
            access_token=access_token,
        ),
        body=body,
    )


def _proof(
    private_key: Ed25519PrivateKey,
    *,
    agent_id: UUID,
    path: str,
    body: object,
    access_token: str | None = None,
) -> str:
    return create_request_proof(
        private_key,
        agent_id=agent_id,
        method="POST",
        path=path,
        body=body,
        ttl_seconds=_PROOF_TTL_SECONDS,
        access_token=access_token,
    )


async def _request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    expected: set[int],
    token: str | None = None,
    proof: str | None = None,
    body: dict[str, object] | None = None,
) -> object:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if proof is not None:
        headers["X-Agent-Proof"] = proof
    try:
        response = await client.request(method, path, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise DemoClientError("DEMO_API_UNAVAILABLE") from exc
    if response.status_code not in expected:
        raise DemoClientError(f"DEMO_API_UNEXPECTED_STATUS_{response.status_code}")
    if response.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    try:
        return response.json()
    except ValueError as exc:
        raise DemoClientError("DEMO_API_INVALID_RESPONSE") from exc


def _loopback_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise DemoClientError("DEMO_CONFIGURATION_INVALID") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise DemoClientError("DEMO_CONFIGURATION_INVALID")
    hostname = parsed.hostname.lower()
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname == "localhost"
    if not is_loopback:
        raise DemoClientError("DEMO_CONFIGURATION_INVALID")
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    return value


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    return value


def _text(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    return item


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    try:
        return UUID(_text(value, key))
    except ValueError as exc:
        raise DemoClientError("DEMO_API_INVALID_RESPONSE") from exc


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    return item


def _text_tuple(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    item = value.get(key)
    if not isinstance(item, list) or not all(isinstance(entry, str) for entry in item):
        raise DemoClientError("DEMO_API_INVALID_RESPONSE")
    return tuple(item)


def _find_by_id(values: list[object], expected_id: UUID) -> dict[str, Any]:
    for value in values:
        item = _object(value)
        if item.get("id") == str(expected_id):
            return item
    raise DemoClientError("DEMO_APPROVAL_NOT_FOUND")
