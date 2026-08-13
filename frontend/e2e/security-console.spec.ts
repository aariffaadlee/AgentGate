import { expect, test, type Route } from "@playwright/test";
import { readFile } from "node:fs/promises";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const approvalHash = `sha256:${"b".repeat(64)}`;
const agentId = "30000000-0000-4000-8000-000000000003";
const taskId = "40000000-0000-4000-8000-000000000004";
const requestId = "20000000-0000-4000-8000-000000000002";
const approvalId = "10000000-0000-4000-8000-000000000001";
const distRoot = fileURLToPath(new URL("../dist/", import.meta.url));
let staticServer: Server | undefined;

test.beforeAll(async () => {
  staticServer = createServer((request, response) => {
    void serveStatic(request, response);
  });
  await new Promise<void>((resolvePromise, rejectPromise) => {
    staticServer?.once("error", rejectPromise);
    staticServer?.listen(4173, "127.0.0.1", resolvePromise);
  });
});

async function serveStatic(request: IncomingMessage, response: ServerResponse): Promise<void> {
  try {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const relativePath = pathname === "/" ? "index.html" : `.${decodeURIComponent(pathname)}`;
    const filePath = resolve(distRoot, relativePath);
    if (!filePath.startsWith(`${resolve(distRoot)}${sep}`)) {
      response.writeHead(403).end();
      return;
    }
    const content = await readFile(filePath);
    const contentTypes: Record<string, string> = {
      ".css": "text/css; charset=utf-8",
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
    };
    response.writeHead(200, {
      "Content-Type": contentTypes[extname(filePath)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
    });
    response.end(content);
  } catch {
    response.writeHead(404).end();
  }
}

test.afterAll(async () => {
  if (staticServer === undefined) return;
  staticServer.closeAllConnections();
  await new Promise<void>((resolvePromise, rejectPromise) => {
    staticServer?.close((error) => (error === undefined ? resolvePromise() : rejectPromise(error)));
  });
});

test("administrator authenticates and submits only the exact approval binding", async ({ page }) => {
  let submittedApproval: unknown = null;

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/admin/session") {
      expect(request.headers().authorization).toBeUndefined();
      await json(route, session());
      return;
    }
    expect(request.headers().authorization).toBe("Bearer browser-memory-only-token");
    if (path === `/api/approvals/${approvalId}/approve`) {
      submittedApproval = request.postDataJSON();
      await json(route, { ...approval(), status: "consumed", consumed_at: "2099-01-01T00:01:00Z" });
      return;
    }
    const responses: Record<string, unknown> = {
      "/api/agents": [agent()],
      "/api/tasks": [taskFixture()],
      "/api/tool-requests": [toolRequest()],
      "/api/approvals": [approval()],
      "/api/audit/events": [],
      "/api/audit/verify": auditVerification(),
      "/api/metrics/security": securityMetrics(),
    };
    const response = responses[path];
    if (response === undefined) {
      await json(route, { error: { code: "NOT_FOUND", message: "Not found." } }, 404);
      return;
    }
    await json(route, response);
  });

  await page.goto("/");
  await page.getByLabel("Bootstrap secret").fill("x".repeat(32));
  await page.getByRole("button", { name: "Authenticate" }).click();

  await expect(page.getByText("Controls nominal")).toBeVisible();
  await expect(page.getByText("50/50")).toBeVisible();
  await expect(page.getByText("Hash chain verified")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("browser-memory-only-token");

  await page.getByRole("button", { name: "Review & approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve sensitive action" });
  await expect(dialog.getByText(approvalHash)).toBeVisible();
  const approveButton = dialog.getByRole("button", { name: "Approve exact action" });
  await expect(approveButton).toBeDisabled();
  await dialog.getByRole("checkbox").check();
  await approveButton.click();

  await expect(dialog).toBeHidden();
  expect(submittedApproval).toEqual({ argument_hash: approvalHash, reason: null });
  expect(JSON.stringify(submittedApproval)).not.toContain("recipient");
});

async function json(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

function session() {
  return {
    access_token: "browser-memory-only-token",
    token_type: "Bearer",
    expires_in: 900,
    expires_at: "2099-01-01T00:15:00Z",
  };
}

function agent() {
  return {
    id: agentId,
    name: "Portfolio Agent",
    status: "active",
    key_thumbprint: "portfolio-thumbprint",
    created_at: "2099-01-01T00:00:00Z",
    revoked_at: null,
  };
}

function taskFixture() {
  return {
    id: taskId,
    owner_admin_id: "50000000-0000-4000-8000-000000000005",
    assigned_agent_id: agentId,
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
    id: requestId,
    correlation_id: "70000000-0000-4000-8000-000000000007",
    agent_id: agentId,
    task_id: taskId,
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
    approval_id: approvalId,
    influences: [],
    produced_provenance: [],
  };
}

function approval() {
  return {
    id: approvalId,
    tool_request_id: requestId,
    agent_id: agentId,
    task_id: taskId,
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

function auditVerification() {
  return {
    valid: true,
    reason_code: "AUDIT_CHAIN_VALID",
    event_count: 0,
    verified_sequence: 0,
    chain_id: null,
    head_hash: "0".repeat(64),
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
