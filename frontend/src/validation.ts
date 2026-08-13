import type {
  AdminSession,
  Agent,
  Approval,
  AuditEvent,
  AuditVerification,
  SecurityMetrics,
  SecurityMetricValues,
  Task,
  ToolRequest,
  ProvenanceReference,
} from "./types";

type JsonObject = Record<string, unknown>;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const HEX_HASH_PATTERN = /^[0-9a-f]{64}$/;

const agentStatuses = ["active", "suspended", "revoked"] as const;
const taskStatuses = ["active", "completed", "cancelled", "expired"] as const;
const requestStatuses = [
  "received",
  "denied",
  "pending_approval",
  "running",
  "succeeded",
  "failed",
] as const;
const policyOutcomes = ["allow", "deny", "require_approval"] as const;
const approvalStatuses = ["pending", "approved", "rejected", "expired", "consumed"] as const;
const riskTiers = ["low", "medium", "high"] as const;
const trustLabels = ["trusted", "untrusted", "unknown"] as const;
const actorTypes = ["administrator", "agent", "system"] as const;

export class ResponseValidationError extends Error {
  constructor(path: string, expectation: string) {
    super(`${path} must be ${expectation}`);
    this.name = "ResponseValidationError";
  }
}

export function parseAdminSession(value: unknown): AdminSession {
  const item = objectAt(value, "response");
  exactKeys(item, "response", ["access_token", "token_type", "expires_in", "expires_at"]);
  const tokenType = stringAt(item.token_type, "response.token_type");
  if (tokenType !== "Bearer") invalid("response.token_type", 'the literal "Bearer"');
  const expiresIn = nonnegativeIntegerAt(item.expires_in, "response.expires_in");
  if (expiresIn === 0) invalid("response.expires_in", "a positive integer");
  return {
    access_token: nonemptyStringAt(item.access_token, "response.access_token"),
    token_type: "Bearer",
    expires_in: expiresIn,
    expires_at: timestampAt(item.expires_at, "response.expires_at"),
  };
}

export function parseAgents(value: unknown): Agent[] {
  return arrayAt(value, "response").map((item, index) => parseAgent(item, `response[${index}]`));
}

export function parseTasks(value: unknown): Task[] {
  return arrayAt(value, "response").map((item, index) => parseTask(item, `response[${index}]`));
}

export function parseToolRequests(value: unknown): ToolRequest[] {
  return arrayAt(value, "response").map((item, index) =>
    parseToolRequest(item, `response[${index}]`),
  );
}

export function parseApprovals(value: unknown): Approval[] {
  return arrayAt(value, "response").map((item, index) =>
    parseApproval(item, `response[${index}]`),
  );
}

export function parseApprovalResponse(value: unknown): Approval {
  return parseApproval(value, "response");
}

export function parseAuditEvents(value: unknown): AuditEvent[] {
  return arrayAt(value, "response").map((item, index) =>
    parseAuditEvent(item, `response[${index}]`),
  );
}

export function parseAuditVerification(value: unknown): AuditVerification {
  const item = objectAt(value, "response");
  exactKeys(item, "response", [
    "valid",
    "reason_code",
    "event_count",
    "verified_sequence",
    "chain_id",
    "head_hash",
    "failure_sequence",
  ]);
  return {
    valid: booleanAt(item.valid, "response.valid"),
    reason_code: nonemptyStringAt(item.reason_code, "response.reason_code"),
    event_count: nonnegativeIntegerAt(item.event_count, "response.event_count"),
    verified_sequence: nonnegativeIntegerAt(item.verified_sequence, "response.verified_sequence"),
    chain_id: nullable(item.chain_id, (entry) => uuidAt(entry, "response.chain_id")),
    head_hash: patternStringAt(item.head_hash, "response.head_hash", HEX_HASH_PATTERN, "a hash"),
    failure_sequence: nullable(item.failure_sequence, (entry) =>
      nonnegativeIntegerAt(entry, "response.failure_sequence"),
    ),
  };
}

export function parseSecurityMetrics(value: unknown): SecurityMetrics {
  const item = objectAt(value, "response");
  exactKeys(item, "response", [
    "evaluation_run_id",
    "scenario_set_hash",
    "configuration_hash",
    "started_at",
    "completed_at",
    "metrics",
  ]);
  return {
    evaluation_run_id: uuidAt(item.evaluation_run_id, "response.evaluation_run_id"),
    scenario_set_hash: sha256At(item.scenario_set_hash, "response.scenario_set_hash"),
    configuration_hash: sha256At(item.configuration_hash, "response.configuration_hash"),
    started_at: timestampAt(item.started_at, "response.started_at"),
    completed_at: timestampAt(item.completed_at, "response.completed_at"),
    metrics: parseMetricValues(item.metrics, "response.metrics"),
  };
}

function parseAgent(value: unknown, path: string): Agent {
  const item = objectAt(value, path);
  exactKeys(item, path, ["id", "name", "status", "key_thumbprint", "created_at", "revoked_at"]);
  return {
    id: uuidAt(item.id, `${path}.id`),
    name: nonemptyStringAt(item.name, `${path}.name`),
    status: enumAt(item.status, `${path}.status`, agentStatuses),
    key_thumbprint: nonemptyStringAt(item.key_thumbprint, `${path}.key_thumbprint`),
    created_at: timestampAt(item.created_at, `${path}.created_at`),
    revoked_at: nullable(item.revoked_at, (entry) => timestampAt(entry, `${path}.revoked_at`)),
  };
}

function parseTask(value: unknown, path: string): Task {
  const item = objectAt(value, path);
  exactKeys(item, path, [
    "id",
    "owner_admin_id",
    "assigned_agent_id",
    "title",
    "trusted_instruction_summary",
    "trusted_instruction_hash",
    "status",
    "capabilities",
    "starts_at",
    "expires_at",
    "created_at",
    "trusted_intent_provenance_id",
  ]);
  return {
    id: uuidAt(item.id, `${path}.id`),
    owner_admin_id: uuidAt(item.owner_admin_id, `${path}.owner_admin_id`),
    assigned_agent_id: uuidAt(item.assigned_agent_id, `${path}.assigned_agent_id`),
    title: nonemptyStringAt(item.title, `${path}.title`),
    trusted_instruction_summary: nonemptyStringAt(
      item.trusted_instruction_summary,
      `${path}.trusted_instruction_summary`,
    ),
    trusted_instruction_hash: sha256At(item.trusted_instruction_hash, `${path}.trusted_instruction_hash`),
    status: enumAt(item.status, `${path}.status`, taskStatuses),
    capabilities: stringArrayAt(item.capabilities, `${path}.capabilities`),
    starts_at: nullable(item.starts_at, (entry) => timestampAt(entry, `${path}.starts_at`)),
    expires_at: nullable(item.expires_at, (entry) => timestampAt(entry, `${path}.expires_at`)),
    created_at: timestampAt(item.created_at, `${path}.created_at`),
    trusted_intent_provenance_id: uuidAt(
      item.trusted_intent_provenance_id,
      `${path}.trusted_intent_provenance_id`,
    ),
  };
}

function parseToolRequest(value: unknown, path: string): ToolRequest {
  const item = objectAt(value, path);
  exactKeys(item, path, [
    "id",
    "correlation_id",
    "agent_id",
    "task_id",
    "tool_name",
    "risk_tier",
    "status",
    "decision",
    "policy_version",
    "reason_codes",
    "error_code",
    "result",
    "result_summary",
    "request_size_bytes",
    "response_size_bytes",
    "execution_latency_ms",
    "created_at",
    "completed_at",
    "approval_id",
    "influences",
    "produced_provenance",
  ]);
  if (item.result !== null) invalid(`${path}.result`, "null");
  return {
    id: uuidAt(item.id, `${path}.id`),
    correlation_id: uuidAt(item.correlation_id, `${path}.correlation_id`),
    agent_id: uuidAt(item.agent_id, `${path}.agent_id`),
    task_id: uuidAt(item.task_id, `${path}.task_id`),
    tool_name: nonemptyStringAt(item.tool_name, `${path}.tool_name`),
    risk_tier: nullable(item.risk_tier, (entry) => enumAt(entry, `${path}.risk_tier`, riskTiers)),
    status: enumAt(item.status, `${path}.status`, requestStatuses),
    decision: nullable(item.decision, (entry) => enumAt(entry, `${path}.decision`, policyOutcomes)),
    policy_version: nullable(item.policy_version, (entry) => stringAt(entry, `${path}.policy_version`)),
    reason_codes: stringArrayAt(item.reason_codes, `${path}.reason_codes`),
    error_code: nullable(item.error_code, (entry) => stringAt(entry, `${path}.error_code`)),
    result: null,
    result_summary: nullable(item.result_summary, (entry) => objectAt(entry, `${path}.result_summary`)),
    request_size_bytes: nonnegativeIntegerAt(item.request_size_bytes, `${path}.request_size_bytes`),
    response_size_bytes: nullable(item.response_size_bytes, (entry) =>
      nonnegativeIntegerAt(entry, `${path}.response_size_bytes`),
    ),
    execution_latency_ms: nullable(item.execution_latency_ms, (entry) =>
      nonnegativeNumberAt(entry, `${path}.execution_latency_ms`),
    ),
    created_at: timestampAt(item.created_at, `${path}.created_at`),
    completed_at: nullable(item.completed_at, (entry) => timestampAt(entry, `${path}.completed_at`)),
    approval_id: nullable(item.approval_id, (entry) => uuidAt(entry, `${path}.approval_id`)),
    influences: provenanceArrayAt(item.influences, `${path}.influences`),
    produced_provenance: provenanceArrayAt(item.produced_provenance, `${path}.produced_provenance`),
  };
}

function parseApproval(value: unknown, path: string): Approval {
  const item = objectAt(value, path);
  exactKeys(item, path, [
    "id",
    "tool_request_id",
    "agent_id",
    "task_id",
    "tool_name",
    "argument_hash",
    "redacted_arguments",
    "status",
    "expires_at",
    "consumed_at",
    "row_version",
    "tool_request_status",
    "decision",
    "reason_codes",
    "error_code",
    "result_summary",
    "created_at",
  ]);
  return {
    id: uuidAt(item.id, `${path}.id`),
    tool_request_id: uuidAt(item.tool_request_id, `${path}.tool_request_id`),
    agent_id: uuidAt(item.agent_id, `${path}.agent_id`),
    task_id: uuidAt(item.task_id, `${path}.task_id`),
    tool_name: nonemptyStringAt(item.tool_name, `${path}.tool_name`),
    argument_hash: sha256At(item.argument_hash, `${path}.argument_hash`),
    redacted_arguments: objectAt(item.redacted_arguments, `${path}.redacted_arguments`),
    status: enumAt(item.status, `${path}.status`, approvalStatuses),
    expires_at: timestampAt(item.expires_at, `${path}.expires_at`),
    consumed_at: nullable(item.consumed_at, (entry) => timestampAt(entry, `${path}.consumed_at`)),
    row_version: nonnegativeIntegerAt(item.row_version, `${path}.row_version`),
    tool_request_status: enumAt(item.tool_request_status, `${path}.tool_request_status`, requestStatuses),
    decision: nullable(item.decision, (entry) => enumAt(entry, `${path}.decision`, policyOutcomes)),
    reason_codes: stringArrayAt(item.reason_codes, `${path}.reason_codes`),
    error_code: nullable(item.error_code, (entry) => stringAt(entry, `${path}.error_code`)),
    result_summary: nullable(item.result_summary, (entry) => objectAt(entry, `${path}.result_summary`)),
    created_at: timestampAt(item.created_at, `${path}.created_at`),
  };
}

function parseAuditEvent(value: unknown, path: string): AuditEvent {
  const item = objectAt(value, path);
  exactKeys(item, path, [
    "sequence",
    "event_id",
    "chain_id",
    "event_type",
    "occurred_at",
    "correlation_id",
    "actor_type",
    "actor_id",
    "task_id",
    "tool_request_id",
    "payload",
    "previous_hash",
    "event_hash",
  ]);
  return {
    sequence: positiveIntegerAt(item.sequence, `${path}.sequence`),
    event_id: uuidAt(item.event_id, `${path}.event_id`),
    chain_id: uuidAt(item.chain_id, `${path}.chain_id`),
    event_type: nonemptyStringAt(item.event_type, `${path}.event_type`),
    occurred_at: timestampAt(item.occurred_at, `${path}.occurred_at`),
    correlation_id: uuidAt(item.correlation_id, `${path}.correlation_id`),
    actor_type: enumAt(item.actor_type, `${path}.actor_type`, actorTypes),
    actor_id: nullable(item.actor_id, (entry) => uuidAt(entry, `${path}.actor_id`)),
    task_id: nullable(item.task_id, (entry) => uuidAt(entry, `${path}.task_id`)),
    tool_request_id: nullable(item.tool_request_id, (entry) => uuidAt(entry, `${path}.tool_request_id`)),
    payload: objectAt(item.payload, `${path}.payload`),
    previous_hash: patternStringAt(item.previous_hash, `${path}.previous_hash`, HEX_HASH_PATTERN, "a hash"),
    event_hash: patternStringAt(item.event_hash, `${path}.event_hash`, HEX_HASH_PATTERN, "a hash"),
  };
}

function parseMetricValues(value: unknown, path: string): SecurityMetricValues {
  const item = objectAt(value, path);
  const countKeys = [
    "total_scenarios",
    "legitimate_scenarios",
    "adversarial_scenarios",
    "passed_scenarios",
  ] as const;
  const rateKeys = [
    "attack_success_rate",
    "unauthorized_action_block_rate",
    "legitimate_task_completion_rate",
    "false_positive_rate",
    "false_negative_rate",
    "approval_enforcement_accuracy",
    "audit_record_completeness",
    "audit_chain_verification_rate",
  ] as const;
  const latencyKeys = [
    "mean_policy_latency_ms",
    "p95_policy_latency_ms",
    "mean_enforcement_latency_ms",
  ] as const;
  exactKeys(item, path, [...countKeys, ...rateKeys, ...latencyKeys]);
  const result = {} as SecurityMetricValues;
  for (const key of countKeys) result[key] = nonnegativeIntegerAt(item[key], `${path}.${key}`);
  for (const key of rateKeys) result[key] = rateAt(item[key], `${path}.${key}`);
  for (const key of latencyKeys) result[key] = nonnegativeNumberAt(item[key], `${path}.${key}`);
  return result;
}

function provenanceArrayAt(value: unknown, path: string): ProvenanceReference[] {
  return arrayAt(value, path).map((entry, index) => {
    const itemPath = `${path}[${index}]`;
    const item = objectAt(entry, itemPath);
    exactKeys(item, itemPath, ["id", "source_type", "trust_label", "source_reference", "content_hash"]);
    return {
      id: uuidAt(item.id, `${itemPath}.id`),
      source_type: nonemptyStringAt(item.source_type, `${itemPath}.source_type`),
      trust_label: enumAt(item.trust_label, `${itemPath}.trust_label`, trustLabels),
      source_reference: nullable(item.source_reference, (source) =>
        stringAt(source, `${itemPath}.source_reference`),
      ),
      content_hash: sha256At(item.content_hash, `${itemPath}.content_hash`),
    };
  });
}

function objectAt(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(path, "an object");
  return value as JsonObject;
}

function arrayAt(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) invalid(path, "an array");
  return value;
}

function stringAt(value: unknown, path: string): string {
  if (typeof value !== "string") invalid(path, "a string");
  return value;
}

function nonemptyStringAt(value: unknown, path: string): string {
  const result = stringAt(value, path);
  if (result.length === 0) invalid(path, "a non-empty string");
  return result;
}

function booleanAt(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") invalid(path, "a boolean");
  return value;
}

function nonnegativeNumberAt(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    invalid(path, "a finite non-negative number");
  }
  return value;
}

function nonnegativeIntegerAt(value: unknown, path: string): number {
  const result = nonnegativeNumberAt(value, path);
  if (!Number.isInteger(result)) invalid(path, "a non-negative integer");
  return result;
}

function positiveIntegerAt(value: unknown, path: string): number {
  const result = nonnegativeIntegerAt(value, path);
  if (result === 0) invalid(path, "a positive integer");
  return result;
}

function rateAt(value: unknown, path: string): number {
  const result = nonnegativeNumberAt(value, path);
  if (result > 1) invalid(path, "a number from 0 through 1");
  return result;
}

function timestampAt(value: unknown, path: string): string {
  const result = stringAt(value, path);
  if (!result.includes("T") || Number.isNaN(Date.parse(result))) invalid(path, "an ISO timestamp");
  return result;
}

function uuidAt(value: unknown, path: string): string {
  return patternStringAt(value, path, UUID_PATTERN, "a UUID");
}

function sha256At(value: unknown, path: string): string {
  return patternStringAt(value, path, SHA256_PATTERN, "a sha256 digest");
}

function patternStringAt(value: unknown, path: string, pattern: RegExp, expectation: string): string {
  const result = stringAt(value, path);
  if (!pattern.test(result)) invalid(path, expectation);
  return result;
}

function stringArrayAt(value: unknown, path: string): string[] {
  return arrayAt(value, path).map((entry, index) => stringAt(entry, `${path}[${index}]`));
}

function enumAt<const T extends readonly string[]>(value: unknown, path: string, values: T): T[number] {
  const result = stringAt(value, path);
  if (!values.includes(result)) invalid(path, `one of ${values.join(", ")}`);
  return result;
}

function nullable<T>(value: unknown, parser: (entry: unknown) => T): T | null {
  return value === null ? null : parser(value);
}

function exactKeys(value: JsonObject, path: string, keys: readonly string[]): void {
  const expected = new Set(keys);
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) invalid(`${path}.${key}`, "present");
  }
  for (const key of Object.keys(value)) {
    if (!expected.has(key)) invalid(`${path}.${key}`, "absent");
  }
}

function invalid(path: string, expectation: string): never {
  throw new ResponseValidationError(path, expectation);
}
