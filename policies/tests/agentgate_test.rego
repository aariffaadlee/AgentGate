package agentgate.authorization_test

import rego.v1
import data.agentgate.authorization.decision

base_input := {
    "agent": {
        "id": "11111111-1111-4111-8111-111111111111",
        "status": "active",
    },
    "task": {
        "id": "22222222-2222-4222-8222-222222222222",
        "owner_id": "33333333-3333-4333-8333-333333333333",
    },
    "token": {
        "issuer": "agentgate.local",
        "audience": "agentgate-tools",
        "expected_issuer": "agentgate.local",
        "expected_audience": "agentgate-tools",
        "expires_at": "2026-08-11T10:05:00Z",
        "task_id": "22222222-2222-4222-8222-222222222222",
        "capabilities": ["tickets.read"],
        "revoked": false,
        "proof_valid": true,
    },
    "tool": {"name": "tickets.read", "known": true, "risk": "low"},
    "request": {
        "arguments_valid": true,
        "arguments": {},
        "argument_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "body_size_bytes": 10,
    },
    "provenance": {
        "labels": ["trusted"],
        "source_types": ["user_instruction"],
        "untrusted_influence": false,
        "trusted_intent_present": true,
        "context_valid": true,
    },
    "approval": {
        "status": "none",
        "argument_hash": null,
        "expires_at": null,
        "consumed": false,
    },
    "limits": {
        "rate_exceeded": false,
        "request_size_exceeded": false,
        "expected_response_size_exceeded": false,
    },
    "now": "2026-08-11T10:00:00Z",
}

merge_section(section, changes) := object.union(
    base_input,
    {section: object.union(base_input[section], changes)},
)

has_reason(result, reason) if {
    reason in result.reason_codes
}

test_default_deny_for_incomplete_input if {
    result := decision with input as {}
    result == {
        "decision": "deny",
        "reason_codes": ["DEFAULT_DENY"],
        "policy_version": "1.0.0",
    }
}

test_allow_explicit_low_risk_capability if {
    result := decision with input as base_input
    result.decision == "allow"
    result.reason_codes == ["LOW_RISK_CAPABILITY_ALLOWED"]
}

test_deny_inactive_agent if {
    candidate := merge_section("agent", {"status": "revoked"})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "AGENT_INACTIVE")
}

test_deny_wrong_issuer if {
    candidate := merge_section("token", {"issuer": "attacker.example"})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "TOKEN_CONTEXT_INVALID")
}

test_deny_expired_credential if {
    candidate := merge_section("token", {"expires_at": "2026-08-11T09:59:59Z"})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "CREDENTIAL_EXPIRED")
}

test_deny_revoked_credential if {
    candidate := merge_section("token", {"revoked": true})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "CREDENTIAL_REVOKED")
}

test_deny_invalid_proof if {
    candidate := merge_section("token", {"proof_valid": false})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "PROOF_INVALID")
}

test_deny_cross_task_credential if {
    candidate := merge_section(
        "token",
        {"task_id": "99999999-9999-4999-8999-999999999999"},
    )
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "CROSS_TASK_CREDENTIAL")
}

test_deny_missing_capability if {
    candidate := merge_section("token", {"capabilities": []})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "CAPABILITY_MISSING")
}

test_deny_unknown_tool if {
    candidate := merge_section("tool", {"known": false})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "UNKNOWN_TOOL")
}

test_deny_invalid_arguments if {
    candidate := merge_section("request", {"arguments_valid": false})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "ARGUMENTS_INVALID")
}

test_deny_untrusted_only_sensitive_intent if {
    high_tool := {"name": "email.send", "known": true, "risk": "high"}
    high_token := object.union(base_input.token, {"capabilities": ["email.send"]})
    untrusted := object.union(
        base_input.provenance,
        {"untrusted_influence": true, "trusted_intent_present": false},
    )
    candidate := object.union_n([
        base_input,
        {"tool": high_tool},
        {"token": high_token},
        {"provenance": untrusted},
    ])
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "UNTRUSTED_ONLY_SENSITIVE_INTENT")
}

test_deny_invalid_provenance_context if {
    candidate := merge_section("provenance", {"context_valid": false})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "PROVENANCE_INVALID")
}

test_deny_unknown_only_sensitive_intent if {
    candidate := object.union_n([
        base_input,
        {"tool": {"name": "email.send", "known": true, "risk": "high"}},
        {"token": object.union(base_input.token, {"capabilities": ["email.send"]})},
        {"provenance": {
            "labels": ["unknown"],
            "source_types": ["tool_output"],
            "untrusted_influence": false,
            "trusted_intent_present": false,
            "context_valid": true,
        }},
    ])
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "UNKNOWN_PROVENANCE_SENSITIVE_INTENT")
}

test_require_approval_for_high_risk_tool if {
    high_tool := {"name": "email.send", "known": true, "risk": "high"}
    high_token := object.union(base_input.token, {"capabilities": ["email.send"]})
    candidate := object.union_n([base_input, {"tool": high_tool}, {"token": high_token}])
    result := decision with input as candidate
    result.decision == "require_approval"
    result.reason_codes == ["HIGH_RISK_APPROVAL_REQUIRED"]
}

test_require_approval_for_file_overwrite if {
    tool := {"name": "files.write", "known": true, "risk": "medium"}
    token := object.union(base_input.token, {"capabilities": ["files.write"]})
    request := object.union(base_input.request, {"arguments": {"overwrite": true}})
    candidate := object.union_n([
        base_input,
        {"tool": tool},
        {"token": token},
        {"request": request},
    ])
    result := decision with input as candidate
    result.decision == "require_approval"
    result.reason_codes == ["FILE_OVERWRITE_APPROVAL_REQUIRED"]
}

approved_input(approval_changes) := object.union_n([
    base_input,
    {"tool": {"name": "email.send", "known": true, "risk": "high"}},
    {"token": object.union(base_input.token, {"capabilities": ["email.send"]})},
    {"approval": object.union({
        "status": "approved",
        "argument_hash": base_input.request.argument_hash,
        "expires_at": "2026-08-11T10:02:00Z",
        "consumed": false,
    }, approval_changes)},
])

test_allow_exact_valid_approval if {
    result := decision with input as approved_input({})
    result.decision == "allow"
    result.reason_codes == ["APPROVAL_VALID"]
}

test_deny_modified_arguments_after_approval if {
    candidate := object.union(approved_input({}), {
        "request": object.union(base_input.request, {
            # Simulate a one-character argument change after the exact hash was approved.
            "argument_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        }),
    })
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "APPROVAL_ARGUMENT_MISMATCH")
}

test_deny_expired_approval if {
    result := decision with input as approved_input({"expires_at": "2026-08-11T09:59:59Z"})
    result.decision == "deny"
    has_reason(result, "APPROVAL_EXPIRED")
}

test_deny_replayed_approval if {
    result := decision with input as approved_input({"consumed": true})
    result.decision == "deny"
    has_reason(result, "APPROVAL_REPLAYED")
}

test_deny_rate_limit if {
    candidate := merge_section("limits", {"rate_exceeded": true})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "RATE_LIMIT_EXCEEDED")
}

test_deny_request_resource_limit if {
    candidate := merge_section("limits", {"request_size_exceeded": true})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "RESOURCE_LIMIT_EXCEEDED")
}

test_deny_response_resource_limit if {
    candidate := merge_section("limits", {"expected_response_size_exceeded": true})
    result := decision with input as candidate
    result.decision == "deny"
    has_reason(result, "RESOURCE_LIMIT_EXCEEDED")
}

test_allow_explicit_medium_risk_capability if {
    tool := {"name": "email.create_draft", "known": true, "risk": "medium"}
    token := object.union(base_input.token, {"capabilities": ["email.create_draft"]})
    candidate := object.union_n([base_input, {"tool": tool}, {"token": token}])
    result := decision with input as candidate
    result.decision == "allow"
    result.reason_codes == ["MEDIUM_RISK_CAPABILITY_ALLOWED"]
}

test_novel_risk_remains_default_deny if {
    candidate := merge_section("tool", {"risk": "critical"})
    result := decision with input as candidate
    result.decision == "deny"
    result.reason_codes == ["DEFAULT_DENY"]
}
