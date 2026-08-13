import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "../src/App";

const approvalHash = `sha256:${"b".repeat(64)}`;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("security console", () => {
  it("authenticates in memory, renders authoritative data, and approves the exact hash", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = requestUrl(input);
      if (url.endsWith("/admin/session")) {
        return Promise.resolve(jsonResponse({
          access_token: "secret-admin-token",
          token_type: "Bearer",
          expires_in: 900,
          expires_at: "2099-01-01T00:15:00Z",
        }));
      }
      if (url.includes("/approvals/") && url.endsWith("/approve")) {
        return Promise.resolve(jsonResponse({ ...approval(), status: "consumed", consumed_at: "2099-01-01T00:01:00Z" }));
      }
      if (url.endsWith("/agents")) return Promise.resolve(jsonResponse([agent()]));
      if (url.endsWith("/tasks")) return Promise.resolve(jsonResponse([task()]));
      if (url.includes("/tool-requests?")) return Promise.resolve(jsonResponse([toolRequest()]));
      if (url.endsWith("/approvals")) return Promise.resolve(jsonResponse([approval()]));
      if (url.includes("/audit/events")) return Promise.resolve(jsonResponse([auditEvent()]));
      if (url.endsWith("/audit/verify")) return Promise.resolve(jsonResponse(auditVerification()));
      if (url.endsWith("/metrics/security")) return Promise.resolve(jsonResponse(securityMetrics()));
      return Promise.resolve(jsonResponse({ error: { code: "NOT_FOUND", message: "Not found." } }, 404));
    });

    render(<App />);
    const input = screen.getByLabelText("Bootstrap secret");
    await user.type(input, "x".repeat(32));
    await user.click(screen.getByRole("button", { name: "Authenticate" }));

    expect(await screen.findByText("Controls nominal")).toBeInTheDocument();
    expect(screen.getByText("50/50")).toBeInTheDocument();
    expect(screen.getAllByText("HIGH_RISK_APPROVAL_REQUIRED").length).toBeGreaterThan(0);
    expect(screen.getByText("Hash chain verified")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("secret-admin-token");
    expect(document.body).not.toHaveTextContent("full secret instruction");

    await user.click(screen.getByRole("button", { name: "Review & approve" }));
    const dialog = screen.getByRole("dialog", { name: "Approve sensitive action" });
    expect(within(dialog).getByText(approvalHash)).toBeInTheDocument();
    const approveButton = within(dialog).getByRole("button", { name: "Approve exact action" });
    expect(approveButton).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(approveButton);

    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([url, request]) =>
          requestUrl(url).endsWith("/approve") && bodyText(request?.body).includes(approvalHash),
        ),
      ).toBe(true);
    });
    const approvalCall = fetchMock.mock.calls.find(([url]) => requestUrl(url).endsWith("/approve"));
    expect(JSON.parse(bodyText(approvalCall?.[1]?.body))).toEqual({
      argument_hash: approvalHash,
      reason: null,
    });
    expect(bodyText(approvalCall?.[1]?.body)).not.toContain("recipient");
    expect(
      fetchMock.mock.calls
        .map(([, init]) => new Headers(init?.headers).get("Authorization"))
        .filter((value): value is string => value !== null),
    ).toContain("Bearer secret-admin-token");
  });
});

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function bodyText(body: BodyInit | null | undefined): string {
  if (typeof body !== "string") {
    throw new Error("Expected a JSON string request body.");
  }
  return body;
}

function agent() {
  return {
    id: "30000000-0000-4000-8000-000000000003",
    name: "Portfolio Agent",
    status: "active",
    key_thumbprint: `sha256:${"1".repeat(64)}`,
    created_at: "2099-01-01T00:00:00Z",
    revoked_at: null,
  };
}

function task() {
  return {
    id: "40000000-0000-4000-8000-000000000004",
    owner_admin_id: "50000000-0000-4000-8000-000000000005",
    assigned_agent_id: agent().id,
    title: "Send approved notification",
    trusted_instruction_summary: "Prepare and send a synthetic notification.",
    trusted_instruction_hash: `sha256:${"2".repeat(64)}`,
    status: "active",
    capabilities: ["email.send"],
    starts_at: null,
    expires_at: null,
    created_at: "2099-01-01T00:00:00Z",
    trusted_intent_provenance_id: "60000000-0000-4000-8000-000000000006",
  };
}

function toolRequest() {
  return {
    id: toolRequestId(),
    correlation_id: "70000000-0000-4000-8000-000000000007",
    agent_id: agent().id,
    task_id: task().id,
    tool_name: "email.send",
    risk_tier: "high",
    status: "pending_approval",
    decision: "require_approval",
    policy_version: "agentgate-v1",
    reason_codes: ["HIGH_RISK_APPROVAL_REQUIRED"],
    error_code: null,
    result: null,
    result_summary: null,
    request_size_bytes: 128,
    response_size_bytes: null,
    execution_latency_ms: null,
    created_at: "2099-01-01T00:00:00Z",
    completed_at: null,
    approval_id: approval().id,
    influences: [],
    produced_provenance: [],
  };
}

function approval() {
  return {
    id: "10000000-0000-4000-8000-000000000001",
    tool_request_id: toolRequestId(),
    agent_id: agent().id,
    task_id: task().id,
    tool_name: "email.send",
    argument_hash: approvalHash,
    redacted_arguments: { fields: ["body", "recipient", "subject"], encrypted_size_bytes: 180 },
    status: "pending",
    expires_at: "2099-01-01T00:10:00Z",
    consumed_at: null,
    row_version: 1,
    tool_request_status: "pending_approval",
    decision: "require_approval",
    reason_codes: ["HIGH_RISK_APPROVAL_REQUIRED"],
    error_code: null,
    result_summary: null,
    created_at: "2099-01-01T00:00:00Z",
  };
}

function toolRequestId(): string {
  return "20000000-0000-4000-8000-000000000002";
}

function auditEvent() {
  return {
    sequence: 12,
    event_id: "80000000-0000-4000-8000-000000000008",
    chain_id: "90000000-0000-4000-8000-000000000009",
    event_type: "policy.decided",
    occurred_at: "2099-01-01T00:00:00Z",
    correlation_id: "70000000-0000-4000-8000-000000000007",
    actor_type: "agent",
    actor_id: agent().id,
    task_id: task().id,
    tool_request_id: toolRequestId(),
    payload: { decision: "require_approval" },
    previous_hash: "3".repeat(64),
    event_hash: "4".repeat(64),
  };
}

function auditVerification() {
  return {
    valid: true,
    reason_code: "AUDIT_CHAIN_VALID",
    event_count: 12,
    verified_sequence: 12,
    chain_id: "90000000-0000-4000-8000-000000000009",
    head_hash: "4".repeat(64),
    failure_sequence: null,
  };
}

function securityMetrics() {
  return {
    evaluation_run_id: "a0000000-0000-4000-8000-00000000000a",
    scenario_set_hash: `sha256:${"5".repeat(64)}`,
    configuration_hash: `sha256:${"6".repeat(64)}`,
    started_at: "2099-01-01T00:00:00Z",
    completed_at: "2099-01-01T00:00:01Z",
    metrics: {
      total_scenarios: 50,
      legitimate_scenarios: 20,
      adversarial_scenarios: 30,
      passed_scenarios: 50,
      attack_success_rate: 0,
      unauthorized_action_block_rate: 1,
      legitimate_task_completion_rate: 1,
      false_positive_rate: 0,
      false_negative_rate: 0,
      approval_enforcement_accuracy: 1,
      mean_policy_latency_ms: 0.03,
      p95_policy_latency_ms: 0.05,
      mean_enforcement_latency_ms: 12.9,
      audit_record_completeness: 1,
      audit_chain_verification_rate: 1,
    },
  };
}
