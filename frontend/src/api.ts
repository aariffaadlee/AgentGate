import type {
  AdminSession,
  Approval,
  DashboardData,
  SecurityMetrics,
} from "./types";
import {
  parseAdminSession,
  parseAgents,
  parseApprovalResponse,
  parseApprovals,
  parseAuditEvents,
  parseAuditVerification,
  parseSecurityMetrics,
  parseTasks,
  parseToolRequests,
} from "./validation";

interface ErrorEnvelope {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export function normalizeApiBase(candidate: string): string {
  const value = candidate.trim().replace(/\/$/, "");
  if (value.startsWith("/") && !value.startsWith("//")) {
    return value;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("VITE_API_BASE_URL must be a relative path or loopback HTTP URL.");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
    url.username !== "" ||
    url.password !== ""
  ) {
    throw new Error("VITE_API_BASE_URL may target only this origin or a loopback host.");
  }
  return url.toString().replace(/\/$/, "");
}

const configuredApiBase: unknown = (
  import.meta as ImportMeta & { readonly env: { readonly VITE_API_BASE_URL?: unknown } }
).env.VITE_API_BASE_URL;
const apiBase = normalizeApiBase(
  typeof configuredApiBase === "string" ? configuredApiBase : "/api",
);

function errorDetails(status: number, body: unknown): ApiError {
  const envelope = isRecord(body) ? (body as ErrorEnvelope) : {};
  const error = isRecord(envelope.error) ? envelope.error : {};
  const code = typeof error.code === "string" ? error.code : "REQUEST_FAILED";
  const message =
    typeof error.message === "string" ? error.message : "AgentGate rejected the request.";
  return new ApiError(status, code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "AgentGate returned an invalid response.");
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError(response.status, "INVALID_RESPONSE", "AgentGate returned malformed JSON.");
  }
}

export class AgentGateClient {
  readonly #token: string | null;

  constructor(token: string | null = null) {
    this.#token = token;
  }

  async createSession(bootstrapSecret: string): Promise<AdminSession> {
    return this.#request("/admin/session", parseAdminSession, {
      method: "POST",
      body: JSON.stringify({ bootstrap_secret: bootstrapSecret }),
    });
  }

  async loadDashboard(signal?: AbortSignal): Promise<DashboardData> {
    const options = signal === undefined ? {} : { signal };
    const [agents, tasks, toolRequests, approvals, auditEvents, auditVerification, metrics] =
      await Promise.all([
        this.#request("/agents", parseAgents, options),
        this.#request("/tasks", parseTasks, options),
        this.#request("/tool-requests?limit=100", parseToolRequests, options),
        this.#request("/approvals", parseApprovals, options),
        this.#request("/audit/events?limit=100", parseAuditEvents, options),
        this.#request("/audit/verify", parseAuditVerification, { method: "POST", ...options }),
        this.#loadMetrics(options),
      ]);
    return {
      agents,
      tasks,
      toolRequests,
      approvals,
      auditEvents,
      auditVerification,
      securityMetrics: metrics,
      loadedAt: new Date(),
    };
  }

  async approve(approval: Approval, reason: string | null): Promise<Approval> {
    return this.#request(`/approvals/${approval.id}/approve`, parseApprovalResponse, {
      method: "POST",
      body: JSON.stringify({ argument_hash: approval.argument_hash, reason }),
    });
  }

  async reject(approval: Approval, reason: string | null): Promise<Approval> {
    return this.#request(`/approvals/${approval.id}/reject`, parseApprovalResponse, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async #loadMetrics(options: RequestInit): Promise<SecurityMetrics | null> {
    try {
      return await this.#request("/metrics/security", parseSecurityMetrics, options);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404 && error.code === "NO_EVALUATION_DATA") {
        return null;
      }
      throw error;
    }
  }

  async #request<T>(
    path: string,
    parser: (value: unknown) => T,
    init: RequestInit = {},
  ): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    if (this.#token !== null) {
      headers.set("Authorization", `Bearer ${this.#token}`);
    }
    let response: Response;
    try {
      response = await fetch(`${apiBase}${path}`, {
        ...init,
        headers,
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw error;
      }
      throw new ApiError(0, "NETWORK_ERROR", "The local AgentGate API is unavailable.");
    }
    const body = await readJson(response);
    if (!response.ok) {
      throw errorDetails(response.status, body);
    }
    try {
      return parser(body);
    } catch {
      throw new ApiError(
        response.status,
        "INVALID_RESPONSE",
        "AgentGate returned an invalid response.",
      );
    }
  }
}
