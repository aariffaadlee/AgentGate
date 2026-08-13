import { useCallback, useEffect, useMemo, useState } from "react";

import { AgentGateClient, ApiError } from "./api";
import type {
  AdminSession,
  Approval,
  DashboardData,
  SecurityMetricValues,
  ToolRequest,
} from "./types";

type ActivityFilter = "all" | "allow" | "deny" | "pending";
type ApprovalAction = "approve" | "reject";

interface ApprovalSelection {
  approval: Approval;
  action: ApprovalAction;
}

function App() {
  const [session, setSession] = useState<AdminSession | null>(null);

  if (session === null) {
    return <SignIn onSession={setSession} />;
  }
  return <Dashboard session={session} onSignOut={() => setSession(null)} />;
}

function SignIn({ onSession }: { onSession: (session: AdminSession) => void }) {
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const session = await new AgentGateClient().createSession(secret);
      setSecret("");
      onSession(session);
    } catch (caught) {
      setSecret("");
      setError(messageFor(caught));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="sign-in-shell">
      <section className="sign-in-context" aria-labelledby="welcome-title">
        <Brand />
        <div className="eyebrow">Zero trust enforcement plane</div>
        <h1 id="welcome-title">Every agent action needs a reason.</h1>
        <p>
          Inspect identities, capability grants, policy outcomes, approvals, and the
          tamper-evident audit chain from one local security console.
        </p>
        <div className="boundary-list" aria-label="Security boundaries">
          <Boundary number="01" label="Authenticate workload identity" />
          <Boundary number="02" label="Evaluate deterministic policy" />
          <Boundary number="03" label="Enforce, record, and verify" />
        </div>
      </section>

      <section className="sign-in-panel" aria-labelledby="sign-in-title">
        <div className="panel-kicker">
          <span className="live-dot" aria-hidden="true" /> Local administration
        </div>
        <h2 id="sign-in-title">Open security console</h2>
        <p className="muted">Use the local bootstrap secret configured for this environment.</p>
        <form onSubmit={(event) => void submit(event)}>
          <label htmlFor="bootstrap-secret">Bootstrap secret</label>
          <input
            id="bootstrap-secret"
            name="bootstrap-secret"
            type="password"
            autoComplete="current-password"
            minLength={32}
            maxLength={512}
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            required
            autoFocus
          />
          {error === null ? null : (
            <div className="alert alert-error" role="alert">
              {error}
            </div>
          )}
          <button className="button button-primary button-wide" type="submit" disabled={submitting}>
            {submitting ? "Authenticating…" : "Authenticate"}
          </button>
        </form>
        <div className="session-note">
          <LockIcon />
          <span>The short-lived admin token stays only in memory and is never displayed.</span>
        </div>
      </section>
    </main>
  );
}

function Dashboard({ session, onSignOut }: { session: AdminSession; onSignOut: () => void }) {
  const client = useMemo(() => new AgentGateClient(session.access_token), [session.access_token]);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ActivityFilter>("all");
  const [selection, setSelection] = useState<ApprovalSelection | null>(null);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      setError(null);
      try {
        setData(await client.loadDashboard(signal));
      } catch (caught) {
        if (caught instanceof DOMException && caught.name === "AbortError") {
          return;
        }
        if (caught instanceof ApiError && caught.status === 401) {
          onSignOut();
          return;
        }
        setError(messageFor(caught));
      } finally {
        setLoading(false);
      }
    },
    [client, onSignOut],
  );

  useEffect(() => {
    const controller = new AbortController();
    const initialLoad = window.setTimeout(() => void refresh(controller.signal), 0);
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      controller.abort();
      window.clearTimeout(initialLoad);
      window.clearInterval(timer);
    };
  }, [refresh]);

  const pendingApprovals = data?.approvals.filter((approval) => approval.status === "pending") ?? [];
  const activity = filterActivity(data?.toolRequests ?? [], filter);
  const posture = getPosture(data);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="Dashboard sections">
          <a className="nav-link nav-link-active" href="#overview">
            <span className="nav-marker" /> Overview
          </a>
          <a className="nav-link" href="#approvals">Approvals</a>
          <a className="nav-link" href="#activity">Tool activity</a>
          <a className="nav-link" href="#identities">Identities</a>
          <a className="nav-link" href="#audit">Audit integrity</a>
        </nav>
        <div className="sidebar-foot">
          <span className="environment-pill">LOCAL MVP</span>
          <p>Deterministic controls outside the model.</p>
        </div>
      </aside>

      <main className="dashboard">
        <header className="topbar">
          <div>
            <div className="eyebrow">Security operations</div>
            <h1>Control plane overview</h1>
          </div>
          <div className="topbar-actions">
            <div className="session-expiry">
              Session expires
              <strong>{formatClock(session.expires_at)}</strong>
            </div>
            <button className="button button-secondary" type="button" onClick={() => void refresh()}>
              Refresh
            </button>
            <button className="button button-quiet" type="button" onClick={onSignOut}>
              Sign out
            </button>
          </div>
        </header>

        {error === null ? null : (
          <div className="alert alert-error dashboard-alert" role="alert">
            <span>{error}</span>
            <button type="button" onClick={() => void refresh()}>Try again</button>
          </div>
        )}

        {data === null && loading ? (
          <LoadingState />
        ) : data === null ? (
          <EmptyState title="Dashboard unavailable" detail="The local API did not return dashboard data." />
        ) : (
          <>
            <section id="overview" className="overview-grid" aria-label="Security overview">
              <article className={`posture-card posture-${posture.tone}`}>
                <div className="posture-icon" aria-hidden="true"><ShieldIcon /></div>
                <div>
                  <div className="card-label">Current posture</div>
                  <h2>{posture.title}</h2>
                  <p>{posture.detail}</p>
                </div>
                <div className="posture-status"><span /> {posture.label}</div>
              </article>
              <Kpi label="Registered agents" value={String(data.agents.length)} detail={`${countActive(data.agents)} active`} />
              <Kpi label="Active tasks" value={String(data.tasks.filter((task) => task.status === "active").length)} detail={`${capabilityCount(data)} exact grants`} />
              <Kpi label="Tool decisions" value={String(data.toolRequests.length)} detail="Newest 100 retained in view" />
              <Kpi label="Pending approvals" value={String(pendingApprovals.length)} detail={pendingApprovals.length === 0 ? "Queue clear" : "Human decision required"} urgent={pendingApprovals.length > 0} />
            </section>

            <EvaluationPanel metrics={data.securityMetrics} />

            <section id="approvals" className="section-block">
              <SectionHeading eyebrow="Human authorization" title="Pending approvals" meta={`${pendingApprovals.length} awaiting review`} />
              {pendingApprovals.length === 0 ? (
                <EmptyState title="Approval queue clear" detail="No sensitive action is waiting for an administrator." compact />
              ) : (
                <div className="approval-grid">
                  {pendingApprovals.map((approval) => (
                    <ApprovalCard key={approval.id} approval={approval} onSelect={setSelection} />
                  ))}
                </div>
              )}
            </section>

            <section id="activity" className="section-block">
              <SectionHeading eyebrow="Policy enforcement" title="Tool-request timeline" meta={`${data.toolRequests.length} recent actions`} />
              <ActivityFilters selected={filter} requests={data.toolRequests} onChange={setFilter} />
              <ToolActivityTable requests={activity} />
            </section>

            <section id="identities" className="two-column-section">
              <div className="section-block inset-section">
                <SectionHeading eyebrow="Workload identity" title="Agents" meta={`${data.agents.length} registered`} />
                <div className="stack-list">
                  {data.agents.map((agent) => (
                    <article className="identity-row" key={agent.id}>
                      <div className="identity-avatar">{initials(agent.name)}</div>
                      <div className="identity-main">
                        <strong>{agent.name}</strong>
                        <span>{shortId(agent.id)} · key {shortHash(agent.key_thumbprint)}</span>
                      </div>
                      <StatusBadge value={agent.status} />
                    </article>
                  ))}
                  {data.agents.length === 0 ? <EmptyState title="No agents" detail="No workload identities are registered." compact /> : null}
                </div>
              </div>

              <div className="section-block inset-section">
                <SectionHeading eyebrow="Least privilege" title="Active tasks" meta={`${data.tasks.length} total`} />
                <div className="stack-list task-list">
                  {data.tasks.map((task) => (
                    <article className="task-row" key={task.id}>
                      <div className="task-row-top">
                        <strong>{task.title}</strong>
                        <StatusBadge value={task.status} />
                      </div>
                      <p>{task.trusted_instruction_summary}</p>
                      <div className="capability-list">
                        {task.capabilities.map((capability) => <code key={capability}>{capability}</code>)}
                      </div>
                      <span className="row-meta">Agent {shortId(task.assigned_agent_id)} · Created {formatDate(task.created_at)}</span>
                    </article>
                  ))}
                  {data.tasks.length === 0 ? <EmptyState title="No tasks" detail="No capability-scoped work is active." compact /> : null}
                </div>
              </div>
            </section>

            <AuditPanel data={data} />

            <footer className="dashboard-footer">
              <span>Loaded {formatDateTime(data.loadedAt.toISOString())}</span>
              <span>Full credentials, trusted instructions, arguments, and sensitive results are excluded.</span>
            </footer>
          </>
        )}
      </main>

      {selection === null ? null : (
        <ApprovalReview
          client={client}
          selection={selection}
          onClose={() => setSelection(null)}
          onComplete={async () => {
            setSelection(null);
            await refresh();
          }}
        />
      )}
    </div>
  );
}

function EvaluationPanel({ metrics }: { metrics: DashboardData["securityMetrics"] }) {
  return (
    <section className="section-block evaluation-section" aria-labelledby="evaluation-title">
      <SectionHeading
        eyebrow="Measured regression evidence"
        title="Security evaluation"
        meta={metrics === null ? "No completed persisted run" : `Run ${shortId(metrics.evaluation_run_id)}`}
        titleId="evaluation-title"
      />
      {metrics === null ? (
        <EmptyState title="Evaluation not measured" detail="Persist a completed evaluation run before interpreting security rates." compact />
      ) : (
        <>
          <div className="metric-grid">
            <MetricCard label="Scenarios passed" value={`${numberMetric(metrics.metrics, "passed_scenarios")}/${numberMetric(metrics.metrics, "total_scenarios")}`} detail={`${numberMetric(metrics.metrics, "legitimate_scenarios")} legitimate · ${numberMetric(metrics.metrics, "adversarial_scenarios")} adversarial`} />
            <MetricCard label="Unauthorized block" value={formatPercent(numberMetric(metrics.metrics, "unauthorized_action_block_rate"))} detail="Adversarial actions blocked" />
            <MetricCard label="Legitimate completion" value={formatPercent(numberMetric(metrics.metrics, "legitimate_task_completion_rate"))} detail="Expected legitimate outcomes" />
            <MetricCard label="Attack success" value={formatPercent(numberMetric(metrics.metrics, "attack_success_rate"))} detail="Lower is better" />
            <MetricCard label="Approval accuracy" value={formatPercent(numberMetric(metrics.metrics, "approval_enforcement_accuracy"))} detail="Approval-relevant cases" />
            <MetricCard label="Policy p95" value={`${numberMetric(metrics.metrics, "p95_policy_latency_ms").toFixed(3)} ms`} detail={`Mean ${numberMetric(metrics.metrics, "mean_policy_latency_ms").toFixed(3)} ms`} />
          </div>
          <div className="evidence-strip">
            <span>Completed {formatDateTime(metrics.completed_at)}</span>
            <span>Scenario set {shortHash(metrics.scenario_set_hash)}</span>
            <span>Offline deterministic policy-contract executor</span>
          </div>
        </>
      )}
    </section>
  );
}

function ApprovalCard({ approval, onSelect }: { approval: Approval; onSelect: (selection: ApprovalSelection) => void }) {
  return (
    <article className="approval-card">
      <div className="approval-card-top">
        <RiskBadge value="high" />
        <span className="expiry">Expires {formatDateTime(approval.expires_at)}</span>
      </div>
      <h3>{approval.tool_name}</h3>
      <p>Agent {shortId(approval.agent_id)} requests a sensitive action for task {shortId(approval.task_id)}.</p>
      <div className="hash-block">
        <span>Exact argument hash</span>
        <code>{approval.argument_hash}</code>
      </div>
      <ReasonCodes values={approval.reason_codes} />
      <div className="approval-actions">
        <button className="button button-danger" type="button" onClick={() => onSelect({ approval, action: "reject" })}>Reject</button>
        <button className="button button-primary" type="button" onClick={() => onSelect({ approval, action: "approve" })}>Review & approve</button>
      </div>
    </article>
  );
}

function ApprovalReview({ client, selection, onClose, onComplete }: { client: AgentGateClient; selection: ApprovalSelection; onClose: () => void; onComplete: () => Promise<void> }) {
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const approving = selection.action === "approve";

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const rationale = reason.trim() === "" ? null : reason.trim();
      if (approving) {
        await client.approve(selection.approval, rationale);
      } else {
        await client.reject(selection.approval, rationale);
      }
      await onComplete();
    } catch (caught) {
      setError(messageFor(caught));
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="review-title">
        <div className="modal-header">
          <div>
            <div className="eyebrow">Exact action binding</div>
            <h2 id="review-title">{approving ? "Approve sensitive action" : "Reject sensitive action"}</h2>
          </div>
          <button className="icon-button" type="button" aria-label="Close review" onClick={onClose}>×</button>
        </div>
        <form onSubmit={(event) => void submit(event)}>
          <dl className="review-grid">
            <div><dt>Tool</dt><dd>{selection.approval.tool_name}</dd></div>
            <div><dt>Agent</dt><dd>{shortId(selection.approval.agent_id)}</dd></div>
            <div><dt>Task</dt><dd>{shortId(selection.approval.task_id)}</dd></div>
            <div><dt>Expires</dt><dd>{formatDateTime(selection.approval.expires_at)}</dd></div>
          </dl>
          <div className="hash-block hash-block-large">
            <span>Canonical SHA-256 binding</span>
            <code>{selection.approval.argument_hash}</code>
          </div>
          <div className="redacted-fields">
            <span>Server-redacted argument metadata</span>
            <pre>{safeJson(selection.approval.redacted_arguments)}</pre>
          </div>
          <label htmlFor="decision-reason">Decision note <span>(optional)</span></label>
          <textarea id="decision-reason" maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} />
          {approving ? (
            <label className="confirm-row">
              <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
              <span>I reviewed the exact hash and understand approval is single-use.</span>
            </label>
          ) : null}
          {error === null ? null : <div className="alert alert-error" role="alert">{error}</div>}
          <div className="modal-actions">
            <button className="button button-secondary" type="button" onClick={onClose}>Cancel</button>
            <button className={approving ? "button button-primary" : "button button-danger"} type="submit" disabled={submitting || (approving && !confirmed)}>
              {submitting ? "Applying decision…" : approving ? "Approve exact action" : "Reject action"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function ActivityFilters({ selected, requests, onChange }: { selected: ActivityFilter; requests: ToolRequest[]; onChange: (filter: ActivityFilter) => void }) {
  const options: Array<{ id: ActivityFilter; label: string; count: number }> = [
    { id: "all", label: "All", count: requests.length },
    { id: "allow", label: "Allowed", count: requests.filter((request) => request.decision === "allow").length },
    { id: "deny", label: "Denied", count: requests.filter((request) => request.decision === "deny").length },
    { id: "pending", label: "Pending", count: requests.filter((request) => request.status === "pending_approval").length },
  ];
  return (
    <div className="filter-row" role="group" aria-label="Filter tool requests">
      {options.map((option) => (
        <button className={selected === option.id ? "filter-button filter-button-active" : "filter-button"} type="button" key={option.id} onClick={() => onChange(option.id)}>
          {option.label} <span>{option.count}</span>
        </button>
      ))}
    </div>
  );
}

function ToolActivityTable({ requests }: { requests: ToolRequest[] }) {
  if (requests.length === 0) {
    return <EmptyState title="No matching actions" detail="No tool request matches this filter." compact />;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Tool</th><th>Risk</th><th>Decision</th><th>Policy reason</th><th>Latency</th><th>Request</th></tr></thead>
        <tbody>
          {requests.map((request) => (
            <tr key={request.id}>
              <td className="nowrap">{formatDateTime(request.created_at)}</td>
              <td><strong>{request.tool_name}</strong><span className="cell-sub">Task {shortId(request.task_id)}</span></td>
              <td>{request.risk_tier === null ? <span className="muted">Unknown</span> : <RiskBadge value={request.risk_tier} />}</td>
              <td><DecisionBadge request={request} /></td>
              <td><ReasonCodes values={request.reason_codes} compact />{request.policy_version === null ? null : <span className="cell-sub">Policy {request.policy_version}</span>}</td>
              <td className="nowrap">{request.execution_latency_ms === null ? "—" : `${request.execution_latency_ms} ms`}</td>
              <td><code>{shortId(request.id)}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditPanel({ data }: { data: DashboardData }) {
  const verification = data.auditVerification;
  return (
    <section id="audit" className="section-block audit-section">
      <SectionHeading eyebrow="Tamper evidence" title="Audit integrity" meta={`${verification.event_count} events verified`} />
      <div className={verification.valid ? "integrity-banner integrity-valid" : "integrity-banner integrity-invalid"}>
        <div className="integrity-icon"><ShieldIcon /></div>
        <div><strong>{verification.valid ? "Hash chain verified" : "Integrity verification failed"}</strong><span>{verification.reason_code} · sequence {verification.verified_sequence}</span></div>
        <code>{shortHash(verification.head_hash)}</code>
      </div>
      <div className="audit-timeline">
        {data.auditEvents.slice().reverse().slice(0, 12).map((event) => (
          <article className="audit-event" key={event.event_id}>
            <div className="timeline-node" />
            <div className="audit-sequence">#{event.sequence}</div>
            <div className="audit-body"><strong>{event.event_type}</strong><span>{event.actor_type} · {formatDateTime(event.occurred_at)}</span></div>
            <div className="audit-links">{event.tool_request_id === null ? "" : `Request ${shortId(event.tool_request_id)}`}</div>
          </article>
        ))}
        {data.auditEvents.length === 0 ? <EmptyState title="No audit events" detail="The append-only timeline is empty." compact /> : null}
      </div>
    </section>
  );
}

function Brand() {
  return <div className="brand"><div className="brand-mark"><ShieldIcon /></div><div><strong>AgentGate</strong><span>Security console</span></div></div>;
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 20 5v6c0 5.1-3.4 9.1-8 11-4.6-1.9-8-5.9-8-11V5l8-3Z" /><path d="m8.8 12 2 2 4.5-5" /></svg>;
}

function LockIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>;
}

function Boundary({ number, label }: { number: string; label: string }) {
  return <div><span>{number}</span><strong>{label}</strong></div>;
}

function Kpi({ label, value, detail, urgent = false }: { label: string; value: string; detail: string; urgent?: boolean }) {
  return <article className={urgent ? "kpi-card kpi-urgent" : "kpi-card"}><div className="card-label">{label}</div><strong>{value}</strong><span>{detail}</span></article>;
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric-card"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function SectionHeading({ eyebrow, title, meta, titleId }: { eyebrow: string; title: string; meta: string; titleId?: string }) {
  return <div className="section-heading"><div><div className="eyebrow">{eyebrow}</div><h2 id={titleId}>{title}</h2></div><span>{meta}</span></div>;
}

function EmptyState({ title, detail, compact = false }: { title: string; detail: string; compact?: boolean }) {
  return <div className={compact ? "empty-state empty-state-compact" : "empty-state"}><div className="empty-icon">◇</div><strong>{title}</strong><span>{detail}</span></div>;
}

function LoadingState() {
  return <div className="loading-state" role="status"><span className="spinner" /><strong>Loading authoritative state</strong><small>Querying AgentGate’s administrative plane…</small></div>;
}

function StatusBadge({ value }: { value: string }) {
  return <span className={`status-badge status-${statusTone(value)}`}><span />{humanize(value)}</span>;
}

function RiskBadge({ value }: { value: "low" | "medium" | "high" }) {
  return <span className={`risk-badge risk-${value}`}>{value} risk</span>;
}

function DecisionBadge({ request }: { request: ToolRequest }) {
  const value = request.status === "pending_approval" ? "pending" : (request.decision ?? request.status);
  return <StatusBadge value={value} />;
}

function ReasonCodes({ values, compact = false }: { values: string[]; compact?: boolean }) {
  if (values.length === 0) return <span className="muted">—</span>;
  return <div className={compact ? "reason-list reason-list-compact" : "reason-list"}>{values.map((value) => <code key={value}>{value}</code>)}</div>;
}

function filterActivity(requests: ToolRequest[], filter: ActivityFilter): ToolRequest[] {
  if (filter === "all") return requests;
  if (filter === "pending") return requests.filter((request) => request.status === "pending_approval");
  return requests.filter((request) => request.decision === filter);
}

function getPosture(data: DashboardData | null): { title: string; detail: string; label: string; tone: "good" | "warn" | "bad" } {
  if (data === null) return { title: "Loading state", detail: "Awaiting authoritative controls.", label: "Checking", tone: "warn" };
  if (!data.auditVerification.valid) return { title: "Integrity alert", detail: `Audit verification failed at sequence ${String(data.auditVerification.failure_sequence ?? "unknown")}.`, label: "Investigate", tone: "bad" };
  if (data.securityMetrics === null) return { title: "Controls online", detail: "The audit chain verifies, but no persisted evaluation measurement is available.", label: "Evaluation missing", tone: "warn" };
  const metrics = data.securityMetrics.metrics;
  const passed = numberMetric(metrics, "passed_scenarios");
  const total = numberMetric(metrics, "total_scenarios");
  if (passed !== total) return { title: "Regression detected", detail: `${passed} of ${total} evaluation scenarios passed.`, label: "Review evidence", tone: "bad" };
  return { title: "Controls nominal", detail: `${passed} of ${total} measured scenarios passed and the audit chain verifies.`, label: "Verified", tone: "good" };
}

function numberMetric(metrics: SecurityMetricValues, key: keyof SecurityMetricValues): number {
  const value = metrics[key];
  return Number.isFinite(value) ? value : 0;
}

function countActive(agents: DashboardData["agents"]): number {
  return agents.filter((agent) => agent.status === "active").length;
}

function capabilityCount(data: DashboardData): number {
  return data.tasks.reduce((count, task) => count + task.capabilities.length, 0);
}

function statusTone(value: string): "good" | "warn" | "bad" | "neutral" {
  if (["active", "allow", "allowed", "succeeded", "consumed", "verified"].includes(value)) return "good";
  if (["pending", "pending_approval", "require_approval", "received", "running"].includes(value)) return "warn";
  if (["deny", "denied", "failed", "rejected", "revoked", "expired", "cancelled"].includes(value)) return "bad";
  return "neutral";
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

function shortHash(value: string): string {
  const hash = value.startsWith("sha256:") ? value.slice(7) : value;
  return hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-6)}` : hash;
}

function initials(value: string): string {
  return value.split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase() ?? "").join("");
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(value === 0 || value === 1 ? 0 : 1)}%`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(new Date(value));
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function formatClock(value: string): string {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function safeJson(value: Record<string, unknown>): string {
  return JSON.stringify(value, null, 2);
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) return `${error.code}: ${error.message}`;
  return "The security console could not complete the request.";
}

export default App;
