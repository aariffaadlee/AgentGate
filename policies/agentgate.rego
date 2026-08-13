package agentgate.authorization

import rego.v1

policy_version := "1.0.0"

default decision := {
    "decision": "deny",
    "reason_codes": ["DEFAULT_DENY"],
    "policy_version": "1.0.0",
}

valid_timestamp(value) if {
    time.parse_rfc3339_ns(value)
}

token_context_valid if {
    input.token.issuer == input.token.expected_issuer
    input.token.audience == input.token.expected_audience
    valid_timestamp(input.token.expires_at)
    valid_timestamp(input.now)
}

base_authorized if {
    input.agent.status == "active"
    token_context_valid
    time.parse_rfc3339_ns(input.token.expires_at) > time.parse_rfc3339_ns(input.now)
    input.token.revoked == false
    input.token.proof_valid == true
    input.token.task_id == input.task.id
    input.tool.known == true
    input.request.arguments_valid == true
    input.provenance.context_valid == true
    input.tool.name in input.token.capabilities
    input.limits.rate_exceeded == false
    input.limits.request_size_exceeded == false
    input.limits.expected_response_size_exceeded == false
    not untrusted_only_sensitive
}

untrusted_only_sensitive if {
    input.tool.risk == "high"
    input.provenance.untrusted_influence == true
    input.provenance.trusted_intent_present == false
}

unknown_only_sensitive if {
    input.tool.risk == "high"
    "unknown" in input.provenance.labels
    input.provenance.trusted_intent_present == false
}

approval_valid if {
    input.approval.status == "approved"
    input.approval.consumed == false
    input.approval.argument_hash == input.request.argument_hash
    valid_timestamp(input.approval.expires_at)
    time.parse_rfc3339_ns(input.approval.expires_at) > time.parse_rfc3339_ns(input.now)
}

file_overwrite if {
    input.tool.name == "files.write"
    input.request.arguments.overwrite == true
}

deny_reasons contains "AGENT_INACTIVE" if {
    input.agent.status != "active"
}

deny_reasons contains "TOKEN_CONTEXT_INVALID" if {
    input.token
    not token_context_valid
}

deny_reasons contains "CREDENTIAL_EXPIRED" if {
    valid_timestamp(input.token.expires_at)
    valid_timestamp(input.now)
    time.parse_rfc3339_ns(input.token.expires_at) <= time.parse_rfc3339_ns(input.now)
}

deny_reasons contains "CREDENTIAL_REVOKED" if {
    input.token.revoked == true
}

deny_reasons contains "PROOF_INVALID" if {
    input.token.proof_valid != true
}

deny_reasons contains "CROSS_TASK_CREDENTIAL" if {
    input.token.task_id != input.task.id
}

deny_reasons contains "CAPABILITY_MISSING" if {
    not input.tool.name in input.token.capabilities
}

deny_reasons contains "UNKNOWN_TOOL" if {
    input.tool.known != true
}

deny_reasons contains "ARGUMENTS_INVALID" if {
    input.request.arguments_valid != true
}

deny_reasons contains "PROVENANCE_INVALID" if {
    input.provenance.context_valid != true
}

deny_reasons contains "UNTRUSTED_ONLY_SENSITIVE_INTENT" if {
    untrusted_only_sensitive
}

deny_reasons contains "UNKNOWN_PROVENANCE_SENSITIVE_INTENT" if {
    unknown_only_sensitive
}

deny_reasons contains "APPROVAL_ARGUMENT_MISMATCH" if {
    input.approval.status == "approved"
    input.approval.argument_hash != input.request.argument_hash
}

deny_reasons contains "APPROVAL_EXPIRED" if {
    input.approval.status == "approved"
    valid_timestamp(input.approval.expires_at)
    valid_timestamp(input.now)
    time.parse_rfc3339_ns(input.approval.expires_at) <= time.parse_rfc3339_ns(input.now)
}

deny_reasons contains "APPROVAL_REPLAYED" if {
    input.approval.consumed == true
}

deny_reasons contains "RATE_LIMIT_EXCEEDED" if {
    input.limits.rate_exceeded == true
}

deny_reasons contains "RESOURCE_LIMIT_EXCEEDED" if {
    input.limits.request_size_exceeded == true
}

deny_reasons contains "RESOURCE_LIMIT_EXCEEDED" if {
    input.limits.expected_response_size_exceeded == true
}

approval_reasons contains "HIGH_RISK_APPROVAL_REQUIRED" if {
    base_authorized
    input.tool.risk == "high"
    not approval_valid
}

approval_reasons contains "FILE_OVERWRITE_APPROVAL_REQUIRED" if {
    base_authorized
    file_overwrite
    not approval_valid
}

allow_reasons contains "LOW_RISK_CAPABILITY_ALLOWED" if {
    base_authorized
    input.tool.risk == "low"
}

allow_reasons contains "MEDIUM_RISK_CAPABILITY_ALLOWED" if {
    base_authorized
    input.tool.risk == "medium"
    not file_overwrite
}

allow_reasons contains "APPROVAL_VALID" if {
    base_authorized
    input.tool.risk == "high"
    approval_valid
}

decision := {
    "decision": "deny",
    "reason_codes": sort([reason | some reason in deny_reasons]),
    "policy_version": policy_version,
} if {
    count(deny_reasons) > 0
}

decision := {
    "decision": "require_approval",
    "reason_codes": sort([reason | some reason in approval_reasons]),
    "policy_version": policy_version,
} if {
    count(deny_reasons) == 0
    count(approval_reasons) > 0
}

decision := {
    "decision": "allow",
    "reason_codes": sort([reason | some reason in allow_reasons]),
    "policy_version": policy_version,
} if {
    count(deny_reasons) == 0
    count(approval_reasons) == 0
    count(allow_reasons) > 0
}
