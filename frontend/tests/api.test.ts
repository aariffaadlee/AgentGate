import { AgentGateClient, normalizeApiBase } from "../src/api";
import type { Approval } from "../src/types";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("AgentGateClient", () => {
  it("allows same-origin or loopback API targets and rejects credential exfiltration targets", () => {
    expect(normalizeApiBase("/api/")).toBe("/api");
    expect(normalizeApiBase("http://127.0.0.1:8000/")).toBe("http://127.0.0.1:8000");
    expect(() => normalizeApiBase("https://attacker.example/api")).toThrow(/loopback/);
    expect(() => normalizeApiBase("//attacker.example/api")).toThrow();
    expect(() => normalizeApiBase("http://user:secret@localhost:8000")).toThrow();
  });

  it("exchanges the bootstrap secret without adding an authorization header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        access_token: "admin-token-not-rendered",
        token_type: "Bearer",
        expires_in: 900,
        expires_at: "2099-01-01T00:00:00Z",
      }),
    );

    const session = await new AgentGateClient().createSession("x".repeat(32));

    expect(session.access_token).toBe("admin-token-not-rendered");
    const request = fetchMock.mock.calls[0];
    expect(request?.[0]).toBe("/api/admin/session");
    const headers = new Headers(request?.[1]?.headers);
    expect(headers.has("Authorization")).toBe(false);
    expect(request?.[1]?.credentials).toBe("omit");
  });

  it("binds approval to the exact server-provided hash and never sends full arguments", async () => {
    const approval = approvalFixture();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ ...approval, status: "consumed" }),
    );

    await new AgentGateClient("memory-only-token").approve(approval, "Reviewed locally");

    const request = fetchMock.mock.calls[0];
    const headers = new Headers(request?.[1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer memory-only-token");
    expect(JSON.parse(bodyText(request?.[1]?.body))).toEqual({
      argument_hash: approval.argument_hash,
      reason: "Reviewed locally",
    });
    expect(bodyText(request?.[1]?.body)).not.toContain("recipient");
  });

  it("maps safe API errors without reflecting an arbitrary response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } }, 401),
    );

    await expect(new AgentGateClient().createSession("x".repeat(32))).rejects.toEqual(
      expect.objectContaining({
        status: 401,
        code: "UNAUTHENTICATED",
        message: "Authentication is required.",
      }),
    );
  });

  it("fails closed when a successful response violates its runtime contract", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        access_token: "admin-token-not-rendered",
        token_type: "bearer",
        expires_in: "900",
        expires_at: "not-a-timestamp",
        unexpected: true,
      }),
    );

    await expect(new AgentGateClient().createSession("x".repeat(32))).rejects.toEqual(
      expect.objectContaining({
        status: 200,
        code: "INVALID_RESPONSE",
        message: "AgentGate returned an invalid response.",
      }),
    );
  });
});

function approvalFixture(): Approval {
  return {
    id: "10000000-0000-4000-8000-000000000001",
    tool_request_id: "20000000-0000-4000-8000-000000000002",
    agent_id: "30000000-0000-4000-8000-000000000003",
    task_id: "40000000-0000-4000-8000-000000000004",
    tool_name: "email.send",
    argument_hash: `sha256:${"a".repeat(64)}`,
    redacted_arguments: { fields: ["recipient", "subject", "body"], encrypted_size_bytes: 180 },
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

function bodyText(body: BodyInit | null | undefined): string {
  if (typeof body !== "string") {
    throw new Error("Expected a JSON string request body.");
  }
  return body;
}
