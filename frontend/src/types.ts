export type AgentStatus = "active" | "suspended" | "revoked";
export type TaskStatus = "active" | "completed" | "cancelled" | "expired";
export type ToolRequestStatus =
  | "received"
  | "denied"
  | "pending_approval"
  | "running"
  | "succeeded"
  | "failed";
export type PolicyOutcome = "allow" | "deny" | "require_approval";
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "consumed";

export interface AdminSession {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  expires_at: string;
}

export interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  key_thumbprint: string;
  created_at: string;
  revoked_at: string | null;
}

export interface Task {
  id: string;
  owner_admin_id: string;
  assigned_agent_id: string;
  title: string;
  trusted_instruction_summary: string;
  trusted_instruction_hash: string;
  status: TaskStatus;
  capabilities: string[];
  starts_at: string | null;
  expires_at: string | null;
  created_at: string;
  trusted_intent_provenance_id: string;
}

export interface ProvenanceReference {
  id: string;
  source_type: string;
  trust_label: "trusted" | "untrusted" | "unknown";
  source_reference: string | null;
  content_hash: string;
}

export interface ToolRequest {
  id: string;
  correlation_id: string;
  agent_id: string;
  task_id: string;
  tool_name: string;
  risk_tier: "low" | "medium" | "high" | null;
  status: ToolRequestStatus;
  decision: PolicyOutcome | null;
  policy_version: string | null;
  reason_codes: string[];
  error_code: string | null;
  result: null;
  result_summary: Record<string, unknown> | null;
  request_size_bytes: number;
  response_size_bytes: number | null;
  execution_latency_ms: number | null;
  created_at: string;
  completed_at: string | null;
  approval_id: string | null;
  influences: ProvenanceReference[];
  produced_provenance: ProvenanceReference[];
}

export interface Approval {
  id: string;
  tool_request_id: string;
  agent_id: string;
  task_id: string;
  tool_name: string;
  argument_hash: string;
  redacted_arguments: Record<string, unknown>;
  status: ApprovalStatus;
  expires_at: string;
  consumed_at: string | null;
  row_version: number;
  tool_request_status: ToolRequestStatus;
  decision: PolicyOutcome | null;
  reason_codes: string[];
  error_code: string | null;
  result_summary: Record<string, unknown> | null;
  created_at: string;
}

export interface AuditEvent {
  sequence: number;
  event_id: string;
  chain_id: string;
  event_type: string;
  occurred_at: string;
  correlation_id: string;
  actor_type: "administrator" | "agent" | "system";
  actor_id: string | null;
  task_id: string | null;
  tool_request_id: string | null;
  payload: Record<string, unknown>;
  previous_hash: string;
  event_hash: string;
}

export interface AuditVerification {
  valid: boolean;
  reason_code: string;
  event_count: number;
  verified_sequence: number;
  chain_id: string | null;
  head_hash: string;
  failure_sequence: number | null;
}

export interface SecurityMetricValues {
  total_scenarios: number;
  legitimate_scenarios: number;
  adversarial_scenarios: number;
  passed_scenarios: number;
  attack_success_rate: number;
  unauthorized_action_block_rate: number;
  legitimate_task_completion_rate: number;
  false_positive_rate: number;
  false_negative_rate: number;
  approval_enforcement_accuracy: number;
  mean_policy_latency_ms: number;
  p95_policy_latency_ms: number;
  mean_enforcement_latency_ms: number;
  audit_record_completeness: number;
  audit_chain_verification_rate: number;
}

export interface SecurityMetrics {
  evaluation_run_id: string;
  scenario_set_hash: string;
  configuration_hash: string;
  started_at: string;
  completed_at: string;
  metrics: SecurityMetricValues;
}

export interface DashboardData {
  agents: Agent[];
  tasks: Task[];
  toolRequests: ToolRequest[];
  approvals: Approval[];
  auditEvents: AuditEvent[];
  auditVerification: AuditVerification;
  securityMetrics: SecurityMetrics | null;
  loadedAt: Date;
}
